"""Telegram-бот: /start + любой текст → проверка адреса."""
from __future__ import annotations

import asyncio
import html
import logging
import os
import time
from datetime import UTC, datetime

from aiogram import BaseMiddleware, Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    TelegramObject,
)

from core import check_address, history, labels, watchlist
from core.addresses import extract_addresses, looks_like_address_attempt
from core.models import AddressVerdict, EntityType, RiskLevel, is_valid_trc20_address

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# Сколько адресов проверяем из одного сообщения. Проверки последовательны и
# каждая тратит платные лимиты KYT, поэтому лимит нужен.
MAX_ADDRESSES_PER_MESSAGE = int(os.getenv("MAX_ADDRESSES_PER_MESSAGE", "5"))
# Пакетная проверка из файла: лимит выше, но тоже есть — каждая строка платная.
MAX_ADDRESSES_PER_FILE = int(os.getenv("MAX_ADDRESSES_PER_FILE", "25"))
BATCH_FILE_MAX_BYTES = int(os.getenv("BATCH_FILE_MAX_BYTES", str(256 * 1024)))


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

_ENTITY_TYPE_VALUES = {e.value for e in EntityType}
_RISK_LEVEL_VALUES = {r.value for r in RiskLevel}


def _level(value: str | None) -> RiskLevel:
    """Строка из журнала → RiskLevel. Незнакомое значение не должно ронять вывод."""
    try:
        return RiskLevel(value)
    except (ValueError, TypeError):
        return RiskLevel.UNKNOWN


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
        if not value:
            continue
        # Для санкционных категорий показываем направление: «получено от» и
        # «отправлено на» — это разные обвинения к адресу.
        got = aml.get(key.replace("_exposure_pct", "_received_pct")) or 0
        sent = aml.get(key.replace("_exposure_pct", "_sent_pct")) or 0
        if got or sent:
            dirs = []
            if got:
                dirs.append(f"↓{_fmt_pct(got)}")
            if sent:
                dirs.append(f"↑{_fmt_pct(sent)}")
            parts.append(f"{title} {_fmt_pct(value)} ({' '.join(dirs)})")
        else:
            parts.append(f"{title} {_fmt_pct(value)}")
    if not parts:
        return []
    lines = [
        "",
        f"<b>🧭 Экспозиция</b> <i>(по {aml['transfers_analyzed']} переводам; "
        f"↓ получено, ↑ отправлено)</i>",
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
    "⏳ Проверяю адрес{counter}…\n<code>{addr}</code>\n\n"
    "<i>TronScan · GoPlus · OFAC · блэклист Tether · Swapster · Bitok</i>\n"
    "<i>Два платных KYT считаются десятки секунд — это нормально.</i>"
)

HELP_TEXT = (
    "<b>Что я делаю</b>\n"
    "Определяю, кому принадлежит TRON-адрес (биржа, депозитник биржи, "
    "смарт-контракт, скам, санкционный, личный кошелёк) и считаю AML-риск.\n\n"
    "<b>Источники</b>\n"
    "• TronScan — публичные метки, баланс, признаки токенов\n"
    "• Переводы TronScan — связи с биржами, экспозиция, 2-й хоп\n"
    "• OFAC SDN — прямое попадание в санкционный список\n"
    "• Блэклист Tether — заблокированы ли средства эмитентом USDT\n"
    "• GoPlus — риск-флаги адреса\n"
    "• Swapster и Bitok — два независимых платных KYT\n\n"
    "<b>Как присылать</b>\n"
    "Просто текстом. Понимаю адрес с пунктуацией вокруг, ссылку на TronScan "
    f"и hex-формат <code>41…</code>. До {MAX_ADDRESSES_PER_MESSAGE} адресов одним сообщением.\n\n"
    "<b>Команды</b>\n"
    "/help — эта справка\n"
    "/id — ваш Telegram ID (нужен для белого списка)\n"
    "/status — что сконфигурировано на сервере\n"
    "/history — последние проверки\n"
    "/stats — сколько проверок сделано (расход платных лимитов)\n"
    "/labels, /label, /unlabel — свои метки адресов без редеплоя\n"
    "/watch, /unwatch, /watchlist — следить за адресом и узнать об изменении\n\n"
    "<b>Пакетная проверка</b>\n"
    "Пришлите файлом список адресов (по одному на строку или CSV) — проверю "
    "по очереди.\n\n"
    "<b>Важно</b>\n"
    "«Нет находок» и «не удалось проверить» — разные вещи. Если источник "
    "недоступен, я пишу об этом первой строкой вердикта."
)


dp = Dispatcher()
dp.message.middleware(AccessMiddleware())
dp.callback_query.middleware(AccessMiddleware())


@dp.message(CommandStart())
async def cmd_start(message: Message):
    await message.answer(
        "👋 Пришлите TRON-адрес — определю владельца и проверю AML.\n\n"
        "Понимаю адрес в любом виде: с текстом вокруг, в скобках, ссылкой на "
        "TronScan или в hex-формате <code>41…</code>.\n\n"
        f"До {MAX_ADDRESSES_PER_MESSAGE} адресов одним сообщением. Подробнее — /help",
        parse_mode=ParseMode.HTML,
    )


@dp.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(HELP_TEXT, parse_mode=ParseMode.HTML)


@dp.message(Command("id"))
async def cmd_id(message: Message):
    """Свой ID нужен, чтобы попасть в белый список. Раньше узнать его можно
    было только получив отказ от бота — то есть не будучи в списке."""
    uid = message.from_user.id if message.from_user else "?"
    await message.answer(
        f"Ваш Telegram ID: <code>{uid}</code>\n\n"
        "Его добавляют в переменную <code>ALLOWED_TG_IDS</code> на сервере.",
        parse_mode=ParseMode.HTML,
    )


@dp.message(Command("status"))
async def cmd_status(message: Message):
    """Что сконфигурировано. Пустые ключи — штатная причина пустых вердиктов,
    и видеть её должен не только тот, у кого есть доступ к логам."""
    from core import aml_bitok, aml_external
    from core.providers import flow as flow_provider
    from core.providers import goplus, tether

    def mark(ok: bool) -> str:
        return "✅" if ok else "➖"

    lines = [
        "<b>Конфигурация сервера</b>",
        f"{mark(bool(flow_provider.TRONSCAN_API_KEY))} ключ TronScan "
        f"<i>(без него ниже лимиты)</i>",
        f"{mark(bool(goplus.GOPLUS_API_KEY))} ключ GoPlus <i>(работает и без него)</i>",
        f"{mark(tether.is_enabled())} проверка блэклиста Tether",
        f"{mark(aml_external.is_configured())} Swapster",
        f"{mark(aml_bitok.is_configured())} Bitok",
        "",
        f"Доступ к боту: {len(ALLOWED_TG_IDS)} Telegram ID в белом списке",
        f"Страниц истории переводов: {flow_provider.FLOW_PAGES} "
        f"(по {flow_provider.TRANSFERS_LIMIT})",
    ]
    await message.answer("\n".join(lines), parse_mode=ParseMode.HTML)


@dp.message(Command("history"))
async def cmd_history(message: Message):
    """Последние проверки. Возвращаться к уже смотренному адресу приходится
    постоянно, а раньше его нужно было вводить заново."""
    items = await history.recent(limit=10)
    if not items:
        await message.answer(
            "Журнал пуст. Он ведётся на диске сервера и наполняется по мере проверок.",
            parse_mode=ParseMode.HTML,
        )
        return
    lines = ["<b>🕘 Последние проверки</b>"]
    for it in items:
        emoji = RISK_EMOJI.get(_level(it.get("risk_level")), "⚪")
        when = _fmt_age(int(time.time() - (it.get("checked_at") or 0))).lstrip(", ")
        lines.append(
            f"{emoji} <code>{_esc(it['address'])}</code>\n"
            f"    {_esc(it.get('entity') or '—')} · {it.get('risk_score', 0)}/100 · {_esc(when)}"
        )
    await message.answer("\n".join(lines), parse_mode=ParseMode.HTML)


@dp.message(Command("stats"))
async def cmd_stats(message: Message):
    """Расход платных лимитов KYT по факту, а не по счёту от провайдера."""
    st = await history.stats()
    if not st.get("enabled"):
        await message.answer("Журнал проверок выключен (HISTORY_ENABLED=0).")
        return
    by = st.get("by_risk_level") or {}
    lines = [
        "<b>📊 Статистика проверок</b>",
        f"Всего: {st.get('total', 0)} · уникальных адресов: {st.get('unique_addresses', 0)}",
        f"За последние сутки: {st.get('last_24h', 0)}",
        "",
        "<i>По вердиктам:</i>",
    ]
    for level, title in (("dangerous", "🔴 опасно"), ("caution", "🟡 осторожно"),
                         ("safe", "🟢 безопасно"), ("unknown", "⚪ нет данных")):
        if by.get(level):
            lines.append(f"• {title}: {by[level]}")
    lines.append("")
    lines.append(f"Ручных меток в базе: {labels.count()}")
    await message.answer("\n".join(lines), parse_mode=ParseMode.HTML)


@dp.message(Command("labels"))
async def cmd_labels(message: Message):
    items = await labels.all_labels(limit=20)
    if not items:
        await message.answer(
            "Ручных меток нет.\n\n"
            "Добавить: <code>/label АДРЕС тип уровень заметка</code>\n"
            "Например: <code>/label TR7N… labeled safe наш горячий кошелёк</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    lines = ["<b>🏷 Ручные метки</b> <i>(наивысший приоритет в вердикте)</i>"]
    for it in items:
        lines.append(
            f"• <code>{_esc(it['address'])}</code> — {_esc(it.get('entity') or '—')}"
            f" · {_esc(it.get('entity_type') or '?')} · {_esc(it.get('risk_level') or '?')}"
        )
    lines.append("")
    lines.append("Удалить: <code>/unlabel АДРЕС</code>")
    await message.answer("\n".join(lines), parse_mode=ParseMode.HTML)


_LABEL_USAGE = (
    "Формат: <code>/label АДРЕС [тип] [уровень] [заметка]</code>\n\n"
    "тип: exchange, contract, project, scam, sanctioned, high_risk_service, "
    "frozen, labeled, wallet, unknown\n"
    "уровень: safe, caution, dangerous, unknown\n\n"
    "Например:\n"
    "<code>/label TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t labeled safe наш кошелёк</code>"
)


@dp.message(Command("label"))
async def cmd_label(message: Message):
    """Своя метка без правки кода и редеплоя.

    Метка имеет наивысший приоритет в вердикте, поэтому автор записывается в
    базу: это сильное действие, и должно быть видно, кто его сделал."""
    parts = (message.text or "").split()
    addresses = extract_addresses(" ".join(parts[1:2]) if len(parts) > 1 else "")
    if not addresses:
        await message.answer(_LABEL_USAGE, parse_mode=ParseMode.HTML)
        return
    addr = addresses[0]
    rest = parts[2:]
    entity_type = rest[0] if rest and rest[0] in _ENTITY_TYPE_VALUES else None
    if entity_type:
        rest = rest[1:]
    risk_level = rest[0] if rest and rest[0] in _RISK_LEVEL_VALUES else None
    if risk_level:
        rest = rest[1:]
    note = " ".join(rest) or None
    author = str(message.from_user.id) if message.from_user else "?"
    try:
        saved = await labels.put(
            addr, entity=note, entity_type=entity_type, risk_level=risk_level,
            note=None, author=author,
        )
    except Exception as e:
        log.exception("не удалось сохранить метку")
        await message.answer(f"⚠️ Не удалось сохранить метку: {_esc(e)}",
                             parse_mode=ParseMode.HTML)
        return
    await message.answer(
        f"✅ Метка сохранена для <code>{_esc(addr)}</code>\n"
        f"название: {_esc(note or '—')}\n"
        f"тип: {_esc(saved.get('entity_type') or 'не задан')} · "
        f"уровень: {_esc(saved.get('risk_level') or 'не задан')}",
        parse_mode=ParseMode.HTML,
    )


@dp.message(Command("unlabel"))
async def cmd_unlabel(message: Message):
    parts = (message.text or "").split()
    addresses = extract_addresses(" ".join(parts[1:2]) if len(parts) > 1 else "")
    if not addresses:
        await message.answer("Формат: <code>/unlabel АДРЕС</code>", parse_mode=ParseMode.HTML)
        return
    removed = await labels.delete(addresses[0])
    await message.answer(
        f"{'✅ Метка удалена' if removed else 'Метки на этом адресе не было'}: "
        f"<code>{_esc(addresses[0])}</code>",
        parse_mode=ParseMode.HTML,
    )


@dp.message(Command("watch"))
async def cmd_watch(message: Message):
    """Поставить адрес под наблюдение: сообщу, если уровень риска изменится."""
    addresses = extract_addresses(message.text or "")
    if not addresses:
        await message.answer(
            "Формат: <code>/watch АДРЕС</code>\n\n"
            "Буду перепроверять адрес и напишу, если уровень риска изменится.",
            parse_mode=ParseMode.HTML,
        )
        return
    ok, note = await watchlist.add(addresses[0], message.chat.id)
    await message.answer(
        f"{'👁 ' if ok else '⚠️ '}<code>{_esc(addresses[0])}</code>\n{_esc(note)}",
        parse_mode=ParseMode.HTML,
    )


@dp.message(Command("unwatch"))
async def cmd_unwatch(message: Message):
    addresses = extract_addresses(message.text or "")
    if not addresses:
        await message.answer("Формат: <code>/unwatch АДРЕС</code>", parse_mode=ParseMode.HTML)
        return
    removed = await watchlist.remove(addresses[0], message.chat.id)
    await message.answer(
        f"{'✅ Снято с наблюдения' if removed else 'Этот адрес не был под наблюдением'}: "
        f"<code>{_esc(addresses[0])}</code>",
        parse_mode=ParseMode.HTML,
    )


@dp.message(Command("watchlist"))
async def cmd_watchlist(message: Message):
    items = await watchlist.list_for(message.chat.id)
    if not items:
        await message.answer(
            "Список наблюдения пуст.\n\n"
            "Добавить: <code>/watch АДРЕС</code> — напишу, когда уровень риска "
            "изменится.",
            parse_mode=ParseMode.HTML,
        )
        return
    lines = ["<b>👁 Под наблюдением</b>"]
    for it in items:
        emoji = RISK_EMOJI.get(_level(it.get("last_level")), "⚪")
        when = (
            _fmt_age(int(time.time() - it["last_check"])).lstrip(", ")
            if it.get("last_check") else "ещё не проверялся"
        )
        lines.append(
            f"{emoji} <code>{_esc(it['address'])}</code>\n"
            f"    {it.get('last_score') if it.get('last_score') is not None else '—'}/100 · "
            f"{_esc(when)}"
        )
    lines.append("")
    lines.append("Снять: <code>/unwatch АДРЕС</code>")
    await message.answer("\n".join(lines), parse_mode=ParseMode.HTML)


@dp.message(F.document)
async def on_document(message: Message):
    """Пакетная проверка из файла: по адресу на строку или CSV.

    Полезно, когда список контрагентов выгружен из таблицы. Лимит на файл
    отдельный и заметно выше, чем на сообщение, но всё равно есть: каждая
    строка — это платная проверка."""
    doc = message.document
    if doc.file_size and doc.file_size > BATCH_FILE_MAX_BYTES:
        await message.answer(
            f"Файл слишком большой ({doc.file_size} Б). "
            f"Лимит — {BATCH_FILE_MAX_BYTES} Б."
        )
        return
    bot = message.bot
    try:
        buf = await bot.download(doc)
        text = buf.read().decode("utf-8", errors="replace")
    except Exception as e:
        log.exception("не удалось прочитать файл")
        await message.answer(f"⚠️ Не удалось прочитать файл: {_esc(e)}",
                             parse_mode=ParseMode.HTML)
        return

    addresses = extract_addresses(text, limit=MAX_ADDRESSES_PER_FILE)
    if not addresses:
        await message.answer(
            "В файле не нашёл TRON-адресов. Ожидаю по адресу на строку или CSV "
            "с адресами в любой колонке."
        )
        return
    await message.answer(
        f"Нашёл адресов: {len(addresses)}. Проверяю по очереди — каждая "
        f"проверка занимает десятки секунд."
    )
    for i, addr in enumerate(addresses, 1):
        await _check_one(message, addr, f" ({i} из {len(addresses)})")


# Лимит длины сообщения в Telegram — 4096 символов.
TG_MESSAGE_LIMIT = 4096


def _fit_message(text: str) -> str:
    """Укладывает вердикт в лимит Telegram.

    Режем по границе строки и предупреждаем об обрезке, иначе пользователь не
    отличит полный отчёт от усечённого. Сам порядок блоков в format_verdict
    таков, что первыми идут вердикт и находки, а не второстепенное."""
    if len(text) <= TG_MESSAGE_LIMIT:
        return text
    note = "\n<i>…отчёт обрезан, часть блоков не показана</i>"
    head = text[: TG_MESSAGE_LIMIT - len(note)]
    if "\n" in head:
        head = head.rsplit("\n", 1)[0]
    return head + note


async def _check_and_render(addr: str) -> str:
    """Свежая проверка (без кеша — для AML важна актуальность транзакций)."""
    v = await check_address(addr, use_cache=False, source="bot")
    return _fit_message(format_verdict(v))


async def _check_one(message: Message, addr: str, counter: str = "") -> None:
    """Одна проверка: сообщение-прогресс, затем правка его же вердиктом."""
    progress = await message.answer(
        PROGRESS_TEXT.format(addr=addr, counter=counter), parse_mode=ParseMode.HTML
    )
    try:
        text = await _check_and_render(addr)
    except Exception as e:
        log.exception("check failed for %s", addr)
        await progress.edit_text(
            f"⚠️ Не удалось проверить <code>{_esc(addr)}</code>: {_esc(e)}",
            parse_mode=ParseMode.HTML,
        )
        return
    await progress.edit_text(
        text, parse_mode=ParseMode.HTML, reply_markup=_verdict_kb(addr)
    )


@dp.message(F.text)
async def on_text(message: Message):
    text = message.text or ""
    addresses = extract_addresses(text, limit=MAX_ADDRESSES_PER_MESSAGE)

    if not addresses:
        if looks_like_address_attempt(text):
            await message.answer(
                "❌ Похоже на TRON-адрес, но контрольная сумма не сходится — "
                "проверьте, не потерялся ли символ при копировании.",
                parse_mode=ParseMode.HTML,
            )
        else:
            await message.answer(
                "Не нашёл TRON-адреса. Пришлите его текстом, ссылкой на TronScan "
                "или в hex-формате <code>41…</code>. Справка — /help",
                parse_mode=ParseMode.HTML,
            )
        return

    total = len(addresses)
    if total > 1:
        # Проверки идут последовательно (платные лимиты KYT), поэтому сразу
        # говорим, сколько их: иначе человек не понимает, сколько ждать.
        await message.answer(
            f"Нашёл адресов: {total}. Проверяю по очереди, каждый занимает "
            f"десятки секунд.",
            parse_mode=ParseMode.HTML,
        )
    for i, addr in enumerate(addresses, 1):
        counter = f" ({i} из {total})" if total > 1 else ""
        await _check_one(message, addr, counter)


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
    from core.providers.local import LOCAL_LABELS
    await init_db()
    await init_cluster_db()
    await history.init_db()
    await labels.init_db(LOCAL_LABELS)
    await watchlist.init_db()
    log_access_mode(log)
    bot = Bot(BOT_TOKEN)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
