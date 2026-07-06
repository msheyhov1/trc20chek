"""Telegram-бот: /start + любой текст → проверка адреса."""
from __future__ import annotations

import asyncio
import logging
import os

from aiogram import BaseMiddleware, Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import Message, TelegramObject

from core import check_address
from core.models import AddressVerdict, EntityType, RiskLevel, is_valid_trc20_address

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "")


def _parse_ids(raw: str) -> set[int]:
    """Разбор списка TG-ID из env: '123, 456 789' → {123,456,789}."""
    out: set[int] = set()
    for chunk in raw.replace(",", " ").split():
        try:
            out.add(int(chunk))
        except ValueError:
            log.warning("ALLOWED_TG_IDS: пропускаю невалидный id %r", chunk)
    return out


# Белый список Telegram user_id. Пусто → доступ открыт (чтобы не залочиться
# до настройки env); задан → бот отвечает только этим пользователям.
ALLOWED_TG_IDS = _parse_ids(os.getenv("ALLOWED_TG_IDS", ""))


def _is_allowed(user_id: int | None) -> bool:
    if not ALLOWED_TG_IDS:
        return True
    return user_id in ALLOWED_TG_IDS


class AccessMiddleware(BaseMiddleware):
    """Гейт доступа по Telegram user_id. Незнакомцам — отказ, дальше не пускаем."""

    async def __call__(self, handler, event: TelegramObject, data: dict):
        user = data.get("event_from_user")
        if not _is_allowed(user.id if user else None):
            uid = user.id if user else "?"
            log.warning("Доступ запрещён: user_id=%s", uid)
            if isinstance(event, Message):
                await event.answer(
                    "⛔ Доступ к боту ограничен.\n"
                    f"Ваш Telegram ID: <code>{uid}</code> — передайте его администратору "
                    "для добавления в белый список.",
                    parse_mode=ParseMode.HTML,
                )
            return  # обработчик не вызываем
        return await handler(event, data)

RISK_EMOJI = {
    RiskLevel.SAFE: "🟢",
    RiskLevel.CAUTION: "🟡",
    RiskLevel.DANGEROUS: "🔴",
    RiskLevel.UNKNOWN: "⚪",
}

TYPE_RU = {
    EntityType.EXCHANGE: "Биржа",
    EntityType.CONTRACT: "Смарт-контракт",
    EntityType.PROJECT: "Проект",
    EntityType.SCAM: "СКАМ",
    EntityType.SANCTIONED: "САНКЦИОННЫЙ (OFAC)",
    EntityType.LABELED: "Маркированный",
    EntityType.WALLET: "Кошелёк",
    EntityType.UNKNOWN: "Неизвестно",
}


def _score_bar(score: int) -> str:
    """Визуальная шкала риск-скора 0-100."""
    filled = round(score / 10)
    return "█" * filled + "░" * (10 - filled)

RISK_RU = {
    RiskLevel.SAFE: "безопасно",
    RiskLevel.CAUTION: "осторожно",
    RiskLevel.DANGEROUS: "ОПАСНО",
    RiskLevel.UNKNOWN: "нет данных",
}


_AML_LEVEL_EMOJI = {"LOW_RISK": "✅", "MEDIUM_RISK": "⚠️", "HIGH_RISK": "⛔️"}


def _fmt_amount(x: float) -> str:
    """Компактно: 1 234.56 (без лишних нулей для целых)."""
    try:
        x = float(x)
    except (TypeError, ValueError):
        return "0"
    s = f"{x:,.2f}".replace(",", " ")
    return s[:-3] if s.endswith(".00") else s


def format_verdict(v: AddressVerdict) -> str:
    emoji = RISK_EMOJI[v.risk_level]
    lines = [
        f"{emoji} <b>{v.entity or '—'}</b>",
        f"<i>Тип:</i> {TYPE_RU[v.entity_type]}",
        "",
        f"<code>{v.address}</code>",
        f"<i>Баланс:</i> {_fmt_amount(v.balance_usdt)} USDT · {_fmt_amount(v.balance_trx)} TRX",
    ]

    # Связи с биржами (оставляем)
    if v.exchange_links:
        lines.append("")
        lines.append("<b>Связи с биржами:</b>")
        for e in v.exchange_links[:5]:
            parts = []
            if e.get("deposits"):
                parts.append(f"депозиты ×{e['deposits']}")
            if e.get("withdrawals"):
                parts.append(f"выводы ×{e['withdrawals']}")
            mark = " 🚫<b>САНКЦ.</b>" if e.get("sanctioned") else ""
            lines.append(f"  • {e['name']}{mark}: {', '.join(parts)}")

    # Туннель: AML показываем только для НЕ-биржевых кошельков
    ext = v.external_aml or {}
    if ext.get("skipped"):
        pass  # биржа/сервис — AML не нужен
    elif ext.get("available"):
        lines.append("")
        prov = ext.get("provider", "AML")
        if ext.get("pending"):
            lines.append(f"<b>AML ({prov}):</b> ⏳ результат готовится, повторите через минуту")
        else:
            rl, rs = ext.get("risk_level"), ext.get("risk_score")
            try:
                rl_ru = RISK_RU.get(RiskLevel(rl)) if rl else None
            except ValueError:
                rl_ru = str(rl)
            tail = " · ".join(p for p in [rl_ru, f"{rs}%" if rs is not None else None] if p)
            lines.append(f"<b>AML ({prov}):</b> {tail}".rstrip() or f"<b>AML ({prov})</b>")
            for e in ext.get("entities", [])[:6]:
                mark = _AML_LEVEL_EMOJI.get(e.get("level"), "•")
                es = e.get("risk_score")
                lines.append(f"  {mark} {e.get('entity', '—')}" + (f" — {es}%" if es is not None else ""))
    elif ext:
        lines.append("")
        lines.append(f"<i>AML:</i> {ext.get('reason', 'внешний API не настроен')}")

    if v.cached:
        lines.append("")
        lines.append("<i>(из кеша)</i>")
    return "\n".join(lines)


dp = Dispatcher()
dp.message.middleware(AccessMiddleware())


@dp.message(CommandStart())
async def cmd_start(message: Message):
    await message.answer(
        "👋 Пришлите TRC20-адрес (начинается с <code>T</code>, длина 34 символа).\n\n"
        "Я определю, кому он принадлежит: биржа, смарт-контракт, скам или неизвестный.",
        parse_mode=ParseMode.HTML,
    )


@dp.message(F.text)
async def on_text(message: Message):
    text = (message.text or "").strip()
    # Поддержка нескольких адресов через пробел/перенос
    candidates = [c for c in text.split() if c.startswith("T") and len(c) == 34]
    if not candidates:
        await message.answer(
            "Не похоже на TRC20-адрес. Пришлите строку из 34 символов, начинающуюся с <code>T</code>.",
            parse_mode=ParseMode.HTML,
        )
        return

    for addr in candidates[:5]:  # лимит на одно сообщение
        if not is_valid_trc20_address(addr):
            await message.answer(
                f"❌ <code>{addr}</code> — невалидный TRC20-адрес (checksum failed).",
                parse_mode=ParseMode.HTML,
            )
            continue
        try:
            # Бот всегда проверяет заново (use_cache=False): для AML важна
            # свежесть — у адреса могли появиться новые «грязные» транзакции.
            v = await check_address(addr, use_cache=False)
            await message.answer(format_verdict(v), parse_mode=ParseMode.HTML)
        except Exception as e:
            log.exception("check failed")
            await message.answer(f"⚠️ Ошибка при проверке: {e}")


async def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN env var is required")
    from core.cache import init_db
    from core.cluster import init_db as init_cluster_db
    await init_db()
    await init_cluster_db()
    if ALLOWED_TG_IDS:
        log.info("Доступ ограничен %d Telegram ID", len(ALLOWED_TG_IDS))
    else:
        log.warning(
            "ALLOWED_TG_IDS не задан — бот ОТКРЫТ всем. "
            "Задайте ALLOWED_TG_IDS, чтобы закрыть доступ по Telegram ID."
        )
    bot = Bot(BOT_TOKEN)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
