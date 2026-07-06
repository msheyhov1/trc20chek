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

function fmtPct(value) {
  if (value === null || value === undefined) return "—";
  const v = Number(value);
  if (Number.isNaN(v)) return "—";
  if (Math.abs(v - Math.round(v)) < 0.05) return `${Math.round(v)}%`;
  if (Math.abs(v) < 1) return `${parseFloat(v.toFixed(2))}%`;
  return `${parseFloat(v.toFixed(1))}%`;
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
  const AML_GROUPS = [
    ["LOW_RISK", "✅ Минимальный риск"],
    ["MEDIUM_RISK", "⚠️ Средний риск"],
    ["HIGH_RISK", "⛔️ Высокий риск"],
  ];
  if (ext.skipped) {
    amlBlock = "";
  } else if (ext.available) {
    const prov = escapeHtml(ext.provider || "AML");
    if (ext.pending) {
      amlBlock = `<div class="flags"><h3>🔍 AML-проверка (${prov} · USDT · TRC20)</h3>`
        + `<div class="flag">⏳ Результат ещё готовится, повторите через минуту</div></div>`;
    } else {
      const rs = ext.risk_score;
      const emoji = (rs === null || rs === undefined) ? "❔" : (rs < 25 ? "✅" : (rs < 75 ? "⚠️" : "⛔️"));
      let inner = `<div class="flag">${emoji} Риск: <b>${escapeHtml(fmtPct(rs))}</b></div>`;
      for (const [level, title] of AML_GROUPS) {
        const items = (ext.entities || []).filter(e => e.level === level)
          .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
        if (!items.length) continue;
        inner += `<div class="aml-group"><b>${title}:</b></div>`;
        for (const it of items) {
          inner += `<div class="flag">• ${escapeHtml(it.entity || "—")} — ${escapeHtml(fmtPct(it.risk_score))}</div>`;
        }
      }
      amlBlock = `<div class="flags"><h3>🔍 AML-проверка (${prov} · USDT · TRC20)</h3>${inner}</div>`;
    }
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
