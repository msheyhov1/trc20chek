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

function render(verdict) {
  const flags = (verdict.risk_flags || []).map(f => `<div class="flag">${escapeHtml(f)}</div>`).join("");
  const sources = (verdict.sources || []).join(", ") || "—";
  const links = (verdict.exchange_links || []).map(e => {
    const parts = [];
    if (e.deposits) parts.push(`депозиты ×${e.deposits}`);
    if (e.withdrawals) parts.push(`выводы ×${e.withdrawals}`);
    const mark = e.sanctioned ? " 🚫 САНКЦ." : "";
    return `<div class="flag">${escapeHtml(e.name)}${mark}: ${escapeHtml(parts.join(", "))}</div>`;
  }).join("");
  const aml = verdict.aml || {};
  const score = verdict.risk_score || 0;
  let amlBlock = "";
  if (aml.transfers_analyzed) {
    const se = aml.sanctioned_exchange_exposure_pct || 0;
    const ind = aml.indirect_sanctions_pct || 0;
    amlBlock = `<div class="flags"><h3>AML-экспозиция (по ${aml.transfers_analyzed} переводам)</h3>`
      + `<div class="flag">🚨 санкц. адреса: ${aml.sanctions_exposure_pct || 0}%</div>`
      + (se ? `<div class="flag">🚫 санкц. биржи: ${se}%</div>` : "")
      + (ind ? `<div class="flag">🔗 косвенно (2-й хоп): ~${ind}%</div>` : "")
      + `<div class="flag">🏦 биржи: ${aml.exchange_exposure_pct || 0}%</div>`
      + `<div class="flag">❔ прочее: ${aml.other_exposure_pct || 0}%</div></div>`;
  }
  result.innerHTML = `
    <div class="verdict-header">
      <span class="dot ${escapeHtml(verdict.risk_level)}"></span>
      <span class="entity">${escapeHtml(verdict.entity || "—")}</span>
    </div>
    <div class="meta">Тип: ${TYPE_RU[verdict.entity_type] || verdict.entity_type}</div>
    <div class="meta">Риск: ${RISK_RU[verdict.risk_level] || verdict.risk_level} · скор ${score}/100</div>
    <div class="address-mono">${escapeHtml(verdict.address)}</div>
    ${amlBlock}
    ${links ? `<div class="flags"><h3>Связи с биржами</h3>${links}</div>` : ""}
    ${flags ? `<div class="flags"><h3>Флаги</h3>${flags}</div>` : ""}
    <div class="sources">Источники: ${escapeHtml(sources)}${verdict.cached ? " · из кеша" : ""}</div>
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
