const form = document.getElementById("form");
const input = document.getElementById("addr");
const btn = document.getElementById("submitBtn");
const result = document.getElementById("result");

const TYPE_RU = {
  exchange: "Биржа",
  contract: "Смарт-контракт",
  project: "Проект",
  scam: "СКАМ",
  sanctioned: "САНКЦИОННЫЙ (OFAC)",
  labeled: "Маркированный",
  wallet: "Кошелёк",
  unknown: "Неизвестно",
};

const RISK_RU = {
  safe: "безопасно",
  caution: "осторожно",
  dangerous: "ОПАСНО",
  unknown: "нет данных",
};

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
  const s = n.toLocaleString("ru-RU", { minimumFractionDigits: 0, maximumFractionDigits: 2 });
  return s;
}

function render(verdict) {
  const links = (verdict.exchange_links || []).map(e => {
    const parts = [];
    if (e.deposits) parts.push(`депозиты ×${e.deposits}`);
    if (e.withdrawals) parts.push(`выводы ×${e.withdrawals}`);
    const mark = e.sanctioned ? " 🚫 САНКЦ." : "";
    return `<div class="flag">${escapeHtml(e.name)}${mark}: ${escapeHtml(parts.join(", "))}</div>`;
  }).join("");

  // Туннель: AML показываем только для НЕ-биржевых кошельков
  const ext = verdict.external_aml || {};
  let amlBlock = "";
  if (ext.skipped) {
    amlBlock = "";
  } else if (ext.available) {
    const tail = [
      ext.risk_level ? (RISK_RU[ext.risk_level] || ext.risk_level) : null,
      (ext.risk_score !== undefined && ext.risk_score !== null) ? `скор ${ext.risk_score}/100` : null,
    ].filter(Boolean).join(" · ");
    amlBlock = `<div class="flags"><h3>AML (${escapeHtml(ext.provider || "AML")})</h3>`
      + `<div class="flag">${escapeHtml(tail || "—")}</div></div>`;
  } else if (Object.keys(ext).length) {
    amlBlock = `<div class="meta">AML: ${escapeHtml(ext.reason || "внешний API не настроен")}</div>`;
  }

  result.innerHTML = `
    <div class="verdict-header">
      <span class="dot ${escapeHtml(verdict.risk_level)}"></span>
      <span class="entity">${escapeHtml(verdict.entity || "—")}</span>
    </div>
    <div class="meta">Тип: ${TYPE_RU[verdict.entity_type] || verdict.entity_type}</div>
    <div class="address-mono">${escapeHtml(verdict.address)}</div>
    <div class="meta">Баланс: ${fmtAmount(verdict.balance_usdt)} USDT · ${fmtAmount(verdict.balance_trx)} TRX</div>
    ${links ? `<div class="flags"><h3>Связи с биржами</h3>${links}</div>` : ""}
    ${amlBlock}
    ${verdict.cached ? `<div class="sources">из кеша</div>` : ""}
  `;
  result.classList.remove("hidden");
}

function renderError(msg) {
  result.innerHTML = `<div class="error">${escapeHtml(msg)}</div>`;
  result.classList.remove("hidden");
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const addr = input.value.trim();
  if (!addr) return;
  btn.disabled = true;
  btn.textContent = "Проверка...";
  try {
    const r = await fetch(`/check/${encodeURIComponent(addr)}`);
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      renderError(err.detail || `Ошибка ${r.status}`);
      return;
    }
    const data = await r.json();
    render(data);
  } catch (err) {
    renderError(`Сетевая ошибка: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Проверить";
  }
});
