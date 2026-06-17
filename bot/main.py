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


def format_verdict(v: AddressVerdict) -> str:
    emoji = RISK_EMOJI[v.risk_level]
    lines = [
        f"{emoji} <b>{v.entity or '—'}</b>",
        f"<i>Тип:</i> {TYPE_RU[v.entity_type]}",
        f"<i>Риск:</i> {RISK_RU[v.risk_level]} · скор {v.risk_score}/100",
        f"<code>{_score_bar(v.risk_score)}</code>",
        "",
        f"<code>{v.address}</code>",
    ]
    aml = v.aml or {}
    if aml.get("transfers_analyzed"):
        s = aml.get("sanctions_exposure_pct", 0)
        se = aml.get("sanctioned_exchange_exposure_pct", 0)
        ex = aml.get("exchange_exposure_pct", 0)
        ot = aml.get("other_exposure_pct", 0)
        lines.append("")
        lines.append(f"<b>AML-экспозиция</b> (по {aml['transfers_analyzed']} переводам):")
        ind = aml.get("indirect_sanctions_pct", 0)
        lines.append(f"  🚨 санкц. адреса: {s}%")
        if se:
            lines.append(f"  🚫 санкц. биржи: {se}%")
        if ind:
            n = aml.get("hop2_intermediaries_checked", 0)
            lines.append(f"  🔗 косвенно (2-й хоп): ~{ind}%")
        lines.append(f"  🏦 биржи: {ex}%")
        lines.append(f"  ❔ прочее: {ot}%")
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
    if v.risk_flags:
        lines.append("")
        lines.append("<b>Флаги:</b>")
        for f in v.risk_flags[:10]:
            lines.append(f"  • {f}")
    if v.sources:
        lines.append("")
        lines.append(f"<i>Источники:</i> {', '.join(v.sources)}")
    if v.cached:
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
