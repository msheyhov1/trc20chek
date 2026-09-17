"""Telegram-бот: /start + любой текст → проверка адреса."""
from __future__ import annotations

import asyncio
import html
import logging
import os
from datetime import UTC, datetime

from aiogram import BaseMiddleware, Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest
from aiogram.filters import CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    TelegramObject,
)

from core import check_address
from core.models import AddressVerdict, RiskLevel, is_valid_trc20_address

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "")


def _parse_ids(raw: str) -> set[int]:
    """Разбор списка TG-ID из env: '123, 456 789' → {123,456,789}.

    Терпим к типичным ошибкам оператора: кавычки вокруг значения (их добавляет
    raw-редактор Railway), «;» вместо запятой, лишние пробелы. Всё, что не
    похоже на положительный user_id, отбрасываем с warning — при fail-closed
    молча пустой белый список означает бота, который не отвечает никому."""
    out: set[int] = set()
    for chunk in raw.replace(",", " ").replace(";", " ").split():
        chunk = chunk.strip("\"'")
        try:
            uid = int(chunk)
        except ValueError:
            log.warning("ALLOWED_TG_IDS: пропускаю невалидный id %r", chunk)
            continue
        if uid <= 0:  # отрицательные — это id чатов/каналов, не пользователей
            log.warning("ALLOWED_TG_IDS: %r не похоже на user_id (нужно положительное число)", chunk)
            continue
        out.add(uid)
    return out


# Белый список Telegram user_id — единственный способ попасть в бота.
# Сырое значение храним, чтобы отличить «не задан» от «задан, но не разобрался».
ALLOWED_TG_IDS_RAW = os.getenv("ALLOWED_TG_IDS", "")
ALLOWED_TG_IDS = _parse_ids(ALLOWED_TG_IDS_RAW)


def _is_allowed(user_id: int | None) -> bool:
    """Fail-closed: пускаем ТОЛЬКО тех, кто явно перечислен в ALLOWED_TG_IDS.

    Пустой список = бот закрыт для ВСЕХ (раньше был открыт). Каждая проверка
    жжёт платные лимиты KYT (Swapster + Bitok), поэтому «по умолчанию открыт»
    — недопустимый дефолт. Разлочка: незнакомец видит свой user_id в отказе,
    админ добавляет его в env и передеплоивает."""
    return user_id is not None and user_id in ALLOWED_TG_IDS


def log_access_mode(logger: logging.Logger) -> None:
    """Строка в логе старта: сразу видно, кого пускает бот.
    Зовут оба входа — main() здесь и lifespan в api/main.py."""
    if ALLOWED_TG_IDS:
        logger.info("Доступ к боту: %d Telegram ID в белом списке", len(ALLOWED_TG_IDS))
    elif ALLOWED_TG_IDS_RAW.strip():
        # Самая частая ошибка оператора: @username, кавычки, id канала.
        # Сказать «не задан» здесь — отправить его чинить не ту вещь.
        logger.error(
            "ALLOWED_TG_IDS задан (%r), но ни один id не распознан — бот НИКОГО не пустит. "
            "Нужны числовые user_id через запятую, без кавычек и без @username.",
            ALLOWED_TG_IDS_RAW,
        )
    else:
        logger.error(
            "ALLOWED_TG_IDS не задан — бот НИКОГО не пустит (fail-closed). "
            "Задайте ALLOWED_TG_IDS=<ваш_id> в env и передеплойте."
        )


class AccessMiddleware(BaseMiddleware):
    """Гейт доступа по Telegram user_id. Незнакомцам — отказ, дальше не пускаем."""

    async def __call__(self, handler, event: TelegramObject, data: dict):
        user = data.get("event_from_user")
        if not _is_allowed(user.id if user else None):
            uid = user.id if user else "?"
            log.warning("Доступ запрещён: user_id=%s", uid)
            # Уведомление об отказе — best-effort: юзер мог заблокировать бота,
            # колбэк — протухнуть. Сбой отправки не должен ронять гейт и сыпать
            # трейсбеками на флуде, но из обработчика выходим в любом случае.
            try:
                if isinstance(event, Message):
                    await event.answer(
                        "⛔ Доступ к боту ограничен.\n"
                        f"Ваш Telegram ID: <code>{uid}</code> — передайте его администратору "
                        "для добавления в белый список.",
                        parse_mode=ParseMode.HTML,
                    )
                elif isinstance(event, CallbackQuery):
                    await event.answer(f"⛔ Доступ ограничен. Ваш ID: {uid}", show_alert=True)
            except TelegramAPIError as e:
                log.warning("Не удалось отправить отказ user_id=%s: %s", uid, e)
            return  # обработчик не вызываем
        return await handler(event, data)

RISK_EMOJI = {
    RiskLevel.SAFE: "🟢",
    RiskLevel.CAUTION: "🟡",
    RiskLevel.DANGEROUS: "🔴",
    RiskLevel.UNKNOWN: "⚪",
}

# Подписи типа и уровня берём из core.models (ENTITY_TYPE_RU / RISK_LEVEL_RU)
# через verdict.entity_type_ru() / risk_level_ru(). Раньше словари дублировались
# здесь и в web/static/app.js: они расходились при любой правке, а тип SANCTIONED
# был жёстко подписан «(OFAC)» даже для санкций UK/EU. Плюс новый тип в перечислении
# ронял рендер по KeyError — теперь подпись приходит из одного места.


def _score_bar(score: int) -> str:
    """Визуальная шкала риск-скора 0-100 (10 делений)."""
    filled = max(0, min(10, round(score / 10)))
    return "▰" * filled + "▱" * (10 - filled)


# Технические флаги провайдеров → человеческий русский.
_FLAG_PREFIX_RU = (
    ("TronScan red tag:", "🚩 Красная метка TronScan:"),
    ("TronScan grey tag:", "⚠️ Серая метка TronScan:"),
    ("Local note:", "📝 Локальная заметка:"),
    ("GoPlus:", "🛡 GoPlus:"),
)
_FLAG_EXACT_RU = {
    "Exchange hot wallet": "🔥 Горячий кошелёк биржи",
    "Exchange cold wallet": "❄️ Холодный кошелёк биржи",
}


def _flag_ru(flag: str) -> str:
    if flag in _FLAG_EXACT_RU:
        return _FLAG_EXACT_RU[flag]
    for prefix, ru in _FLAG_PREFIX_RU:
        if flag.startswith(prefix):
            return ru + flag[len(prefix):]
    return flag


_AML_GROUPS = [
    ("HIGH_RISK", "⛔️ Высокий риск"),
    ("MEDIUM_RISK", "⚠️ Средний риск"),
    ("LOW_RISK", "✅ Минимальный риск"),
]

# Родной уровень Bitok → подпись рядом с процентом.
_BITOK_LEVEL_RU = {
    "none": "чисто",
    "low": "низкий",
    "medium": "средний",
    "high": "высокий",
    "severe": "критический",
    "undefined": "не определён",
}


def _fmt_pct(value) -> str:
    """48 -> '48%', 69.3 -> '69.3%', 0.9 -> '0.9%', None -> '—'."""
    if value is None:
        return "—"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "—"
    if abs(v - round(v)) < 0.05:
        return f"{v:.0f}%"
    if abs(v) < 1:
        return f"{v:.2f}".rstrip("0").rstrip(".") + "%"
    return f"{v:.1f}".rstrip("0").rstrip(".") + "%"


def _aml_risk_emoji(pct) -> str:
    if pct is None:
        return "❔"
    try:
        pct = float(pct)
    except (TypeError, ValueError):
        return "❔"
    return "✅" if pct < 25 else ("⚠️" if pct < 75 else "⛔️")


def _fmt_amount(x: float) -> str:
    """Компактно: 1 234.56 (без лишних нулей для целых)."""
    try:
        x = float(x)
    except (TypeError, ValueError):
        return "0"
    s = f"{x:,.2f}".replace(",", " ")
    return s[:-3] if s.endswith(".00") else s


def _esc(x) -> str:
    return html.escape(str(x if x is not None else "—"), quote=False)


def _fmt_when(iso: str | None) -> str:
    """ISO-время проверки → «17.09.2026 22:19 UTC». Без даты отчёт нельзя
    приложить к решению по операции, поэтому показываем её всегда."""
    if not iso:
        return "—"
    try:
        ts = datetime.fromisoformat(iso)
    except ValueError:
        return str(iso)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC")


def _fmt_age(seconds: int | None) -> str:
    """«, 3 ч назад» — насколько устарели данные из кеша."""
    if seconds is None:
        return ""
    if seconds < 60:
        return ", только что"
    if seconds < 3600:
        return f", {seconds // 60} мин назад"
    if seconds < 86400:
        return f", {seconds // 3600} ч назад"
    return f", {seconds // 86400} дн назад"


def _aml_provider_lines(ext: dict, number: int) -> list[str]:
    """Блок одного внешнего AML-сервиса (Swapster/Bitok) — формат общий."""
    provider = _esc(ext.get("provider") or "AML")
    head = f"<b>{number}) {provider}</b>"

    if not ext.get("available"):
        return [f"{head} — <i>{_esc(ext.get('reason') or 'не настроен')}</i>"]
    if ext.get("pending"):
        return [f"{head} — ⏳ считается, повторите через минуту"]

    pct = ext.get("risk_score")
    level_ru = _BITOK_LEVEL_RU.get(ext.get("level_raw") or "")
    suffix = f" · {level_ru}" if level_ru else ""
    lines = [f"{head} — {_aml_risk_emoji(pct)} <b>{_fmt_pct(pct)}</b>{suffix}"]

    # Опознанная сущность (Bitok отдаёт имя + категорию)
    if ext.get("entity"):
        category = ext.get("entity_category_ru") or ext.get("entity_category")
        tail = f" · {_esc(category)}" if category else ""
        lines.append(f"    🏷 {_esc(ext['entity'])}{tail}")

    entities = [e for e in (ext.get("entities") or []) if isinstance(e, dict)]
    for level, title in _AML_GROUPS:
        items = sorted(
            (e for e in entities if e.get("level") == level),
            key=lambda e: e.get("risk_score") or 0,
            reverse=True,
        )
        if not items:
            continue
        lines.append(f"    <i>{title}:</i>")
        for it in items[:6]:
            prox = " (прямая)" if it.get("proximity") == "direct" else (
                " (косвенная)" if it.get("proximity") == "indirect" else ""
            )
            lines.append(
                f"    • {_esc(it.get('entity'))} — {_fmt_pct(it.get('risk_score'))}{prox}"
            )
    return lines


def _exposure_line(aml: dict) -> list[str]:
    """Разбивка объёма переводов по типам контрагентов (наш on-chain анализ)."""
    if not aml or not aml.get("transfers_analyzed"):
        return []
    parts = []
    for key, title in (
        ("sanctions_exposure_pct", "санкции"),
        ("sanctioned_exchange_exposure_pct", "санкц. биржи"),
        ("exchange_exposure_pct", "биржи"),
        ("other_exposure_pct", "прочее"),
    ):
        value = aml.get(key) or 0
        if value:
            parts.append(f"{title} {_fmt_pct(value)}")
    if not parts:
        return []
    lines = [
        "",
        f"<b>🧭 Экспозиция</b> <i>(по {aml['transfers_analyzed']} переводам)</i>",
        "• " + " · ".join(parts),
    ]
    if aml.get("indirect_sanctions_pct"):
        lines.append(
            f"• 2-й хоп: ~{_fmt_pct(aml['indirect_sanctions_pct'])} через "
            f"{len(aml.get('hop2_flagged') or [])} посредник(ов)"
        )
    return lines


def format_verdict(v: AddressVerdict) -> str:
    emoji = RISK_EMOJI.get(v.risk_level, "⚪")
    lines = [
        f"{emoji} <b>{_esc(v.risk_level_ru())}</b> · риск {v.risk_score}/100",
        f"<code>{_score_bar(v.risk_score)}</code>",
        "",
        f"🏷 <b>{_esc(v.entity or '—')}</b>",
        f"<i>Тип:</i> {_esc(v.entity_type_ru())}",
        f"<code>{_esc(v.address)}</code>",
        f"💰 {_fmt_amount(v.balance_usdt)} USDT · {_fmt_amount(v.balance_trx)} TRX",
    ]

    # Что нашли (флаги провайдеров + пояснения агрегатора)
    if v.risk_flags:
        lines.append("")
        lines.append("<b>⚠️ Что нашли</b>")
        for flag in v.risk_flags[:8]:
            lines.append(f"• {_esc(_flag_ru(str(flag)))}")
        if len(v.risk_flags) > 8:
            lines.append(f"<i>…и ещё {len(v.risk_flags) - 8}</i>")

    # Связи с биржами (по контрагентам переводов)
    if v.exchange_links:
        lines.append("")
        lines.append("<b>🏦 Связи с биржами</b>")
        for e in v.exchange_links[:5]:
            parts = []
            if e.get("deposits"):
                parts.append(f"депозиты ×{e['deposits']}")
            if e.get("withdrawals"):
                parts.append(f"выводы ×{e['withdrawals']}")
            mark = " 🚫<b>САНКЦ.</b>" if e.get("sanctioned") else ""
            lines.append(f"• {_esc(e['name'])}{mark} — {_esc(', '.join(parts))}")

    lines += _exposure_line(v.aml)

    # Кластер депозитников биржи (накопительная база)
    cluster = (v.raw_labels or {}).get("cluster") or {}
    if cluster.get("siblings_on_anchor") or cluster.get("known_deposits_exchange"):
        lines.append("")
        lines.append(
            f"<b>🔗 Кластер {_esc(cluster.get('exchange'))}</b> — "
            f"родственных депозитников: {cluster.get('siblings_on_anchor', 0)} "
            f"на том же хот-кошельке, {cluster.get('known_deposits_exchange', 0)} по бирже"
        )

    # Внешние AML-сервисы: туннель — для бирж/контрактов не запрашиваются
    providers = [p for p in (v.external_aml, v.bitok_aml) if p]
    shown = [p for p in providers if not p.get("skipped")]
    if shown:
        lines.append("")
        lines.append("<b>🔍 AML-сервисы</b> <i>(USDT · TRC20)</i>")
        for i, ext in enumerate(shown, 1):
            lines += _aml_provider_lines(ext, i)
    elif providers:
        lines.append("")
        lines.append("<i>🔍 AML-сервисы: биржа/сервис — проверка не требуется</i>")

    if v.sources:
        lines.append("")
        lines.append(f"<i>Источники: {_esc(' · '.join(dict.fromkeys(v.sources)))}</i>")
    if v.checked_at:
        lines.append(f"<i>Проверено: {_esc(_fmt_when(v.checked_at))}</i>")
    if v.cached:
        lines.append(f"<i>(из кеша{_esc(_fmt_age(v.cache_age_seconds))})</i>")
    return "\n".join(lines)


def _verdict_kb(address: str) -> InlineKeyboardMarkup:
    """Кнопки под вердиктом: перепроверить и открыть адрес в TronScan."""
    return InlineKeyboardMarkup(
        inline_keyboard=[[
            InlineKeyboardButton(text="🔄 Перепроверить", callback_data=f"recheck:{address}"),
            InlineKeyboardButton(
                text="🔎 TronScan", url=f"https://tronscan.org/#/address/{address}"
            ),
        ]]
    )


PROGRESS_TEXT = (
    "⏳ Проверяю адрес…\n<code>{addr}</code>\n\n"
    "<i>TronScan · GoPlus · OFAC · Swapster · Bitok</i>"
)


dp = Dispatcher()
dp.message.middleware(AccessMiddleware())
dp.callback_query.middleware(AccessMiddleware())


@dp.message(CommandStart())
async def cmd_start(message: Message):
    await message.answer(
        "👋 Пришлите TRC20-адрес (начинается с <code>T</code>, длина 34 символа).\n\n"
        "Я определю, кому он принадлежит (биржа, смарт-контракт, скам, кошелёк) "
        "и проверю AML: наши on-chain связи + два внешних сервиса — "
        "<b>Swapster</b> и <b>Bitok</b>.\n\n"
        "Можно прислать до 5 адресов одним сообщением.",
        parse_mode=ParseMode.HTML,
    )


# Лимит длины сообщения в Telegram — 4096 символов.
TG_MESSAGE_LIMIT = 4096


async def _check_and_render(addr: str) -> str:
    """Свежая проверка (без кеша — для AML важна актуальность транзакций)."""
    v = await check_address(addr, use_cache=False)
    text = format_verdict(v)
    if len(text) > TG_MESSAGE_LIMIT:
        text = text[: TG_MESSAGE_LIMIT - 40].rsplit("\n", 1)[0] + "\n<i>…обрезано</i>"
    return text


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
        # Проверка идёт десятки секунд (два внешних AML) — показываем прогресс,
        # затем правим это же сообщение готовым вердиктом.
        progress = await message.answer(
            PROGRESS_TEXT.format(addr=addr), parse_mode=ParseMode.HTML
        )
        try:
            await progress.edit_text(
                await _check_and_render(addr),
                parse_mode=ParseMode.HTML,
                reply_markup=_verdict_kb(addr),
            )
        except Exception as e:
            log.exception("check failed")
            await progress.edit_text(f"⚠️ Ошибка при проверке: {e}")


@dp.callback_query(F.data.startswith("recheck:"))
async def on_recheck(callback: CallbackQuery):
    addr = (callback.data or "").split(":", 1)[1]
    if not is_valid_trc20_address(addr):
        await callback.answer("Невалидный адрес", show_alert=True)
        return
    await callback.answer("Проверяю заново…")
    try:
        text = await _check_and_render(addr)
    except Exception as e:
        log.exception("recheck failed")
        await callback.answer(f"Ошибка: {e}", show_alert=True)
        return
    try:
        await callback.message.edit_text(
            text, parse_mode=ParseMode.HTML, reply_markup=_verdict_kb(addr)
        )
    except TelegramBadRequest as e:
        # Telegram ругается, если текст не изменился — это нормальный исход.
        if "not modified" not in str(e):
            raise


async def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN env var is required")
    from core.cache import init_db
    from core.cluster import init_db as init_cluster_db
    await init_db()
    await init_cluster_db()
    log_access_mode(log)
    bot = Bot(BOT_TOKEN)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
