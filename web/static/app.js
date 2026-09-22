const form = document.getElementById("form");
const input = document.getElementById("addr");
const btn = document.getElementById("submitBtn");
const result = document.getElementById("result");
const historyBlock = document.getElementById("historyBlock");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistory");

// Адрес принимаем в любом виде: с текстом вокруг, ссылкой на TronScan, hex 41…
// (та же логика, что в core/addresses.py на стороне бота).
const B58 = "[1-9A-HJ-NP-Za-km-z]";
const ADDR_RE = new RegExp(`(?<!${B58})(T${B58}{33})(?!${B58})`);
const HEX_RE = /(?<![0-9A-Fa-fx])(41[0-9A-Fa-f]{40})(?![0-9A-Fa-f])/;

function extractAddress(text) {
  const b58 = ADDR_RE.exec(text || "");
  if (b58) return b58[1];
  const hex = HEX_RE.exec(text || "");
  // hex конвертирует сервер: тут достаточно передать как есть, /check его отвергнет,
  // поэтому подсказываем пользователю вместо молчаливой ошибки.
  return hex ? hex[1] : (text || "").trim();
}

// Подписи типа и уровня приходят готовыми из API (entity_type_ru / risk_level_ru,
// см. core/models.py). Раньше словари дублировались здесь и в bot/main.py — они
// расходились при любой правке, а тип sanctioned был жёстко подписан «(OFAC)»
// даже для санкций UK/EU. Локальные таблицы оставлены только как запасной
// вариант для ответа старой версии API.
const TYPE_RU_FALLBACK = {
  exchange: "Биржа",
  contract: "Смарт-контракт",
  project: "Проект",
  scam: "СКАМ",
  sanctioned: "САНКЦИОННЫЙ",
  high_risk_service: "Высокорисковый сервис",
  frozen: "СРЕДСТВА ЗАБЛОКИРОВАНЫ",
  labeled: "Маркированный",
  wallet: "Кошелёк",
  unknown: "Неизвестно",
};

const RISK_RU_FALLBACK = {
  safe: "БЕЗОПАСНО",
  caution: "ОСТОРОЖНО",
  dangerous: "ОПАСНО",
  unknown: "НЕТ ДАННЫХ",
};

function typeRu(v) {
  return v.entity_type_ru || TYPE_RU_FALLBACK[v.entity_type] || v.entity_type || "—";
}

function riskRu(v) {
  const level = v.risk_level || "unknown";
  return v.risk_level_ru || RISK_RU_FALLBACK[level] || level;
}

/** «17.09.2026 22:19 UTC» — без даты отчёт нельзя приложить к решению. */
function fmtWhen(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}.${p(d.getUTCMonth() + 1)}.${d.getUTCFullYear()} `
    + `${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

function fmtAge(seconds) {
  if (seconds === null || seconds === undefined) return "";
  if (seconds < 60) return ", только что";
  if (seconds < 3600) return `, ${Math.floor(seconds / 60)} мин назад`;
  if (seconds < 86400) return `, ${Math.floor(seconds / 3600)} ч назад`;
  return `, ${Math.floor(seconds / 86400)} дн назад`;
}

// Родной уровень Bitok → подпись рядом с процентом
const LEVEL_RU = {
  none: "чисто",
  low: "низкий",
  medium: "средний",
  high: "высокий",
  severe: "критический",
  undefined: "не определён",
};

// Группы рисков внутри блока провайдера (порядок = сверху вниз)
const AML_GROUPS = [
  ["HIGH_RISK", "⛔️ Высокий риск"],
  ["MEDIUM_RISK", "⚠️ Средний риск"],
  ["LOW_RISK", "✅ Минимальный риск"],
];

// Технические флаги провайдеров → человеческий русский
const FLAG_PREFIX_RU = [
  ["TronScan red tag:", "🚩 Красная метка TronScan:"],
  ["TronScan grey tag:", "⚠️ Серая метка TronScan:"],
  ["Local note:", "📝 Локальная заметка:"],
  ["GoPlus:", "🛡 GoPlus:"],
];
const FLAG_EXACT_RU = {
  "Exchange hot wallet": "🔥 Горячий кошелёк биржи",
  "Exchange cold wallet": "❄️ Холодный кошелёк биржи",
};

function flagRu(flag) {
  if (FLAG_EXACT_RU[flag]) return FLAG_EXACT_RU[flag];
  for (const [prefix, ru] of FLAG_PREFIX_RU) {
    if (flag.startsWith(prefix)) return ru + flag.slice(prefix.length);
  }
  return flag;
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function fmtAmount(x) {
  const n = Number(x) || 0;
  return n.toLocaleString("ru-RU", { minimumFractionDigits: 0, maximumFractionDigits: 2 });
}

function fmtPct(value) {
  if (value === null || value === undefined) return "—";
  const v = Number(value);
  if (Number.isNaN(v)) return "—";
  if (Math.abs(v - Math.round(v)) < 0.05) return `${Math.round(v)}%`;
  if (Math.abs(v) < 1) return `${parseFloat(v.toFixed(2))}%`;
  return `${parseFloat(v.toFixed(1))}%`;
}

function riskEmoji(pct) {
  if (pct === null || pct === undefined) return "❔";
  return pct < 25 ? "✅" : (pct < 75 ? "⚠️" : "⛔️");
}

function section(title, inner) {
  return inner ? `<div class="flags"><h3>${title}</h3>${inner}</div>` : "";
}

/** Блок одного внешнего AML-сервиса (Swapster / Bitok) — формат общий. */
function amlProvider(ext) {
  const name = escapeHtml(ext.provider || "AML");
  if (!ext.available) {
    return `<div class="provider"><div class="provider-head">${name}</div>`
      + `<div class="flag muted">${escapeHtml(ext.reason || "не настроен")}</div></div>`;
  }
  if (ext.pending) {
    return `<div class="provider"><div class="provider-head">${name}</div>`
      + `<div class="flag">⏳ Результат ещё готовится, повторите через минуту</div></div>`;
  }

  const pct = ext.risk_score;
  const levelRu = LEVEL_RU[ext.level_raw] || "";
  let inner = `<div class="provider-head">${name}`
    + `<span class="badge ${escapeHtml(ext.risk_level || "unknown")}">`
    + `${riskEmoji(pct)} ${escapeHtml(fmtPct(pct))}${levelRu ? ` · ${escapeHtml(levelRu)}` : ""}`
    + `</span></div>`;

  if (ext.entity) {
    const cat = ext.entity_category_ru || ext.entity_category;
    inner += `<div class="flag">🏷 ${escapeHtml(ext.entity)}`
      + `${cat ? ` · ${escapeHtml(cat)}` : ""}</div>`;
  }

  const entities = (ext.entities || []).filter(e => e && typeof e === "object");
  for (const [level, title] of AML_GROUPS) {
    const items = entities.filter(e => e.level === level)
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 6);
    if (!items.length) continue;
    inner += `<div class="aml-group">${title}:</div>`;
    for (const it of items) {
      const prox = it.proximity === "direct" ? " (прямая)"
        : (it.proximity === "indirect" ? " (косвенная)" : "");
      inner += `<div class="flag">• ${escapeHtml(it.entity || "—")} — `
        + `${escapeHtml(fmtPct(it.risk_score))}${escapeHtml(prox)}</div>`;
    }
  }
  return `<div class="provider">${inner}</div>`;
}

/** Разбивка объёма переводов по типам контрагентов (наш on-chain анализ). */
function exposureBlock(aml) {
  if (!aml || !aml.transfers_analyzed) return "";
  const parts = [];
  for (const [key, title] of [
    ["sanctions_exposure_pct", "санкции"],
    ["sanctioned_exchange_exposure_pct", "санкц. биржи"],
    ["exchange_exposure_pct", "биржи"],
    ["other_exposure_pct", "прочее"],
  ]) {
    if (aml[key]) parts.push(`${title} ${fmtPct(aml[key])}`);
  }
  if (!parts.length) return "";
  let inner = `<div class="flag">${escapeHtml(parts.join(" · "))}</div>`;
  if (aml.indirect_sanctions_pct) {
    inner += `<div class="flag">2-й хоп: ~${escapeHtml(fmtPct(aml.indirect_sanctions_pct))} `
      + `через ${(aml.hop2_flagged || []).length} посредник(ов)</div>`;
  }
  return section(`Экспозиция (по ${aml.transfers_analyzed} переводам)`, inner);
}

function render(verdict) {
  const score = Number(verdict.risk_score) || 0;
  const level = verdict.risk_level || "unknown";

  const flags = (verdict.risk_flags || [])
    .map(f => `<div class="flag">${escapeHtml(flagRu(String(f)))}</div>`).join("");

  const links = (verdict.exchange_links || []).slice(0, 5).map(e => {
    const parts = [];
    if (e.deposits) parts.push(`депозиты ×${e.deposits}`);
    if (e.withdrawals) parts.push(`выводы ×${e.withdrawals}`);
    const mark = e.sanctioned ? " 🚫 САНКЦ." : "";
    return `<div class="flag">${escapeHtml(e.name)}${mark}: ${escapeHtml(parts.join(", "))}</div>`;
  }).join("");

  // Профиль адреса: приходит бесплатно в ответе TronScan вместе с метками и
  // отвечает на первый вопрос про незнакомый адрес — он вчера создан или
  // работает годами.
  const profile = (verdict.raw_labels || {}).profile || {};
  const profileParts = [];
  if (typeof profile.age_days === "number") {
    profileParts.push(profile.age_days < 400
      ? `возраст ${Math.round(profile.age_days)} дн.`
      : `возраст ${(profile.age_days / 365).toFixed(1)} г.`);
  }
  if (typeof profile.tx_in === "number" && typeof profile.tx_out === "number") {
    profileParts.push(`переводов ↓${profile.tx_in} ↑${profile.tx_out}`);
  }
  const profileBlock = profileParts.length
    ? `<div class="meta">${escapeHtml(profileParts.join(" · "))}</div>`
    : "";

  const cluster = (verdict.raw_labels || {}).cluster || {};
  const clusterBlock = (cluster.siblings_on_anchor || cluster.known_deposits_exchange)
    ? section(`Кластер ${escapeHtml(cluster.exchange || "")}`,
      `<div class="flag">Родственных депозитников: ${cluster.siblings_on_anchor || 0} `
      + `на том же хот-кошельке, ${cluster.known_deposits_exchange || 0} по бирже</div>`)
    : "";

  // Туннель: для бирж/контрактов внешние AML не запрашиваются
  const providers = [verdict.external_aml, verdict.bitok_aml].filter(p => p && Object.keys(p).length);
  const shown = providers.filter(p => !p.skipped);
  let amlBlock = "";
  if (shown.length) {
    amlBlock = section("AML-сервисы (USDT · TRC20)", shown.map(amlProvider).join(""));
  } else if (providers.length) {
    amlBlock = `<div class="meta">AML-сервисы: ${escapeHtml(providers[0].reason || "не запрашивались")}</div>`;
  }

  const sources = [...new Set(verdict.sources || [])].join(" · ");

  result.innerHTML = `
    <div class="verdict-header">
      <span class="dot ${escapeHtml(level)}"></span>
      <span class="entity">${escapeHtml(verdict.entity || "—")}</span>
    </div>
    <div class="score">
      <div class="score-bar"><div class="score-fill ${escapeHtml(level)}" style="width:${Math.min(100, score)}%"></div></div>
      <div class="score-label">Риск ${score}/100 · ${escapeHtml(riskRu(verdict))}</div>
    </div>
    <div class="meta">Тип: ${escapeHtml(typeRu(verdict))}</div>
    <div class="address-mono">${escapeHtml(verdict.address)}</div>
    <div class="meta">Баланс: ${fmtAmount(verdict.balance_usdt)} USDT · ${fmtAmount(verdict.balance_trx)} TRX</div>
    ${profileBlock}
    ${section("Что нашли", flags)}
    ${section("Связи с биржами", links)}
    ${exposureBlock(verdict.aml)}
    ${clusterBlock}
    ${amlBlock}
    ${sources ? `<div class="sources">Источники: ${escapeHtml(sources)}</div>` : ""}
    ${verdict.checked_at ? `<div class="sources">Проверено: ${escapeHtml(fmtWhen(verdict.checked_at))}</div>` : ""}
    ${verdict.cached ? `<div class="sources">из кеша${escapeHtml(fmtAge(verdict.cache_age_seconds))}</div>` : ""}
    <div class="actions">
      <button type="button" class="link-btn" data-act="recheck">🔄 Перепроверить</button>
      <button type="button" class="link-btn" data-act="copy">📋 Скопировать отчёт</button>
      <a class="link-btn" href="https://tronscan.org/#/address/${encodeURIComponent(verdict.address)}"
         target="_blank" rel="noopener noreferrer">🔎 TronScan</a>
    </div>
  `;
  result.classList.remove("hidden");
  wireActions(verdict);
}

/** Текстовый отчёт для копирования: то же, что на экране, но без разметки. */
function verdictToText(v) {
  const lines = [
    `Адрес: ${v.address}`,
    `Вердикт: ${riskRu(v)} · риск ${v.risk_score || 0}/100`,
    `Тип: ${typeRu(v)}`,
    `Сущность: ${v.entity || "—"}`,
    `Баланс: ${fmtAmount(v.balance_usdt)} USDT · ${fmtAmount(v.balance_trx)} TRX`,
  ];
  if (v.checked_at) lines.push(`Проверено: ${fmtWhen(v.checked_at)}`);
  if ((v.risk_flags || []).length) {
    lines.push("", "Что нашли:");
    for (const f of v.risk_flags) lines.push(`- ${flagRu(String(f))}`);
  }
  if ((v.sources || []).length) {
    lines.push("", `Источники: ${[...new Set(v.sources)].join(" · ")}`);
  }
  return lines.join("\n");
}

function wireActions(verdict) {
  const recheck = result.querySelector('[data-act="recheck"]');
  if (recheck) recheck.addEventListener("click", () => check(verdict.address));
  const copy = result.querySelector('[data-act="copy"]');
  if (copy) {
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(verdictToText(verdict));
        copy.textContent = "✅ Скопировано";
      } catch {
        copy.textContent = "⚠️ Не вышло скопировать";
      }
      setTimeout(() => { copy.textContent = "📋 Скопировать отчёт"; }, 2000);
    });
  }
}

// ---------- История последних проверок (только в этом браузере) ----------
// Хранится локально: сервер журнала проверок не ведёт, а возвращаться к
// адресу, который смотрел вчера, нужно постоянно.
const HISTORY_KEY = "trc20-history";
const HISTORY_MAX = 10;

function readHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];   // приватный режим или заблокированное хранилище
  }
}

function saveHistory(items) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, HISTORY_MAX)));
  } catch {
    /* не критично: история — удобство, а не часть вердикта */
  }
}

function rememberCheck(v) {
  const items = readHistory().filter(x => x.address !== v.address);
  items.unshift({
    address: v.address,
    level: v.risk_level || "unknown",
    score: v.risk_score || 0,
    entity: v.entity || "",
    at: v.checked_at || new Date().toISOString(),
  });
  saveHistory(items);
  renderHistory();
}

function renderHistory() {
  const items = readHistory();
  if (!items.length) {
    historyBlock.classList.add("hidden");
    historyList.innerHTML = "";
    return;
  }
  historyBlock.classList.remove("hidden");
  historyList.innerHTML = items.map(it => `
    <button type="button" class="history-item" data-addr="${escapeHtml(it.address)}">
      <span class="dot ${escapeHtml(it.level)}"></span>
      <span class="history-addr">${escapeHtml(it.address.slice(0, 10))}…${escapeHtml(it.address.slice(-6))}</span>
      <span class="history-meta">${escapeHtml(it.entity || "—")} · ${it.score}/100</span>
    </button>
  `).join("");
  for (const el of historyList.querySelectorAll(".history-item")) {
    el.addEventListener("click", () => {
      input.value = el.dataset.addr;
      check(el.dataset.addr);
    });
  }
}

clearHistoryBtn.addEventListener("click", () => {
  saveHistory([]);
  renderHistory();
});

function renderError(msg) {
  result.innerHTML = `<div class="error">${escapeHtml(msg)}</div>`;
  result.classList.remove("hidden");
}

async function check(rawAddress) {
  const addr = extractAddress(rawAddress);
  if (!addr) return;
  input.value = addr;
  btn.disabled = true;
  btn.textContent = "Проверка...";
  // Проверка идёт десятки секунд (два платных KYT) — показываем, что процесс идёт.
  result.innerHTML = `<div class="meta">⏳ Проверяю адрес… TronScan · GoPlus · OFAC · `
    + `блэклист Tether · Swapster · Bitok<br><small>Два платных KYT считаются `
    + `десятки секунд — это нормально.</small></div>`;
  result.classList.remove("hidden");

  // Постоянная ссылка: отчёт можно переслать или открыть заново.
  const url = new URL(window.location);
  url.searchParams.set("addr", addr);
  window.history.replaceState({}, "", url);

  try {
    const r = await fetch(`/check/${encodeURIComponent(addr)}`);
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      renderError(err.detail || `Ошибка ${r.status}`);
      return;
    }
    const data = await r.json();
    render(data);
    rememberCheck(data);
  } catch (err) {
    renderError(`Сетевая ошибка: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Проверить";
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  check(input.value);
});

// Открытие по ссылке с ?addr=… сразу запускает проверку.
renderHistory();
const initial = new URLSearchParams(window.location.search).get("addr");
if (initial) {
  input.value = initial;
  check(initial);
}
