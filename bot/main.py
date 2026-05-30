"""Telegram-бот: /start + любой текст → проверка адреса."""
from __future__ import annotations

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import Message

from core import check_address
from core.models import AddressVerdict, EntityType, RiskLevel, is_valid_trc20_address

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "")

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
    if aml.get("direct_sanctioned"):
        lines.append("")
        lines.append("🚨 <b>Адрес в санкционном списке OFAC SDN</b>")
    elif aml.get("transfers_analyzed"):
        s = aml.get("sanctions_exposure_pct", 0)
        ex = aml.get("exchange_exposure_pct", 0)
        ot = aml.get("other_exposure_pct", 0)
        lines.append("")
        lines.append(f"<b>AML-экспозиция</b> (по {aml['transfers_analyzed']} переводам):")
        lines.append(f"  🚨 санкции: {s}%")
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
            lines.append(f"  • {e['name']}: {', '.join(parts)}")
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
            v = await check_address(addr)
            await message.answer(format_verdict(v), parse_mode=ParseMode.HTML)
        except Exception as e:
            log.exception("check failed")
            await message.answer(f"⚠️ Ошибка при проверке: {e}")


async def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN env var is required")
    from core.cache import init_db
    await init_db()
    bot = Bot(BOT_TOKEN)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
