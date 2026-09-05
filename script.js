/* ==========================================================================
   CVSS 3.1 Calculator — scoring engine + UI
   Formulas follow the official FIRST.org CVSS v3.1 Specification Document
   (https://www.first.org/cvss/v3.1/specification-document)
   ========================================================================== */

/* ---------------------------------------------------------------------- *
 * 1. Metric definitions
 * ---------------------------------------------------------------------- */

const METRICS = {
  base: {
    AV: { name: "Attack Vector", options: [
      { v: "N", l: "Network", n: 0.85 },
      { v: "A", l: "Adjacent", n: 0.62 },
      { v: "L", l: "Local", n: 0.55 },
      { v: "P", l: "Physical", n: 0.2 },
    ]},
    AC: { name: "Attack Complexity", options: [
      { v: "L", l: "Low", n: 0.77 },
      { v: "H", l: "High", n: 0.44 },
    ]},
    PR: { name: "Privileges Required", options: [
      { v: "N", l: "None" },
      { v: "L", l: "Low" },
      { v: "H", l: "High" },
    ]}, // numeric value depends on Scope — see prValue()
    UI: { name: "User Interaction", options: [
      { v: "N", l: "None", n: 0.85 },
      { v: "R", l: "Required", n: 0.62 },
    ]},
    S: { name: "Scope", options: [
      { v: "U", l: "Unchanged" },
      { v: "C", l: "Changed" },
    ]},
    C: { name: "Confidentiality", options: [
      { v: "H", l: "High", n: 0.56 },
      { v: "L", l: "Low", n: 0.22 },
      { v: "N", l: "None", n: 0 },
    ]},
    I: { name: "Integrity", options: [
      { v: "H", l: "High", n: 0.56 },
      { v: "L", l: "Low", n: 0.22 },
      { v: "N", l: "None", n: 0 },
    ]},
    A: { name: "Availability", options: [
      { v: "H", l: "High", n: 0.56 },
      { v: "L", l: "Low", n: 0.22 },
      { v: "N", l: "None", n: 0 },
    ]},
  },
  temporal: {
    E: { name: "Exploit Code Maturity", optional: true, options: [
      { v: "X", l: "Not Defined", n: 1 },
      { v: "H", l: "High", n: 1 },
      { v: "F", l: "Functional", n: 0.97 },
      { v: "P", l: "Proof-of-Concept", n: 0.94 },
      { v: "U", l: "Unproven", n: 0.91 },
    ]},
    RL: { name: "Remediation Level", optional: true, options: [
      { v: "X", l: "Not Defined", n: 1 },
      { v: "U", l: "Unavailable", n: 1 },
      { v: "W", l: "Workaround", n: 0.97 },
      { v: "T", l: "Temporary Fix", n: 0.96 },
      { v: "O", l: "Official Fix", n: 0.95 },
    ]},
    RC: { name: "Report Confidence", optional: true, options: [
      { v: "X", l: "Not Defined", n: 1 },
      { v: "C", l: "Confirmed", n: 1 },
      { v: "R", l: "Reasonable", n: 0.96 },
      { v: "U", l: "Unknown", n: 0.92 },
    ]},
  },
  environmental: {
    CR: { name: "Confidentiality Requirement", optional: true, options: [
      { v: "X", l: "Not Defined", n: 1 },
      { v: "H", l: "High", n: 1.5 },
      { v: "M", l: "Medium", n: 1 },
      { v: "L", l: "Low", n: 0.5 },
    ]},
    IR: { name: "Integrity Requirement", optional: true, options: [
      { v: "X", l: "Not Defined", n: 1 },
      { v: "H", l: "High", n: 1.5 },
      { v: "M", l: "Medium", n: 1 },
      { v: "L", l: "Low", n: 0.5 },
    ]},
    AR: { name: "Availability Requirement", optional: true, options: [
      { v: "X", l: "Not Defined", n: 1 },
      { v: "H", l: "High", n: 1.5 },
      { v: "M", l: "Medium", n: 1 },
      { v: "L", l: "Low", n: 0.5 },
    ]},
    MAV: { name: "Modified Attack Vector", optional: true, options: [
      { v: "X", l: "Not Defined" },
      { v: "N", l: "Network", n: 0.85 },
      { v: "A", l: "Adjacent", n: 0.62 },
      { v: "L", l: "Local", n: 0.55 },
      { v: "P", l: "Physical", n: 0.2 },
    ]},
    MAC: { name: "Modified Attack Complexity", optional: true, options: [
      { v: "X", l: "Not Defined" },
      { v: "L", l: "Low", n: 0.77 },
      { v: "H", l: "High", n: 0.44 },
    ]},
    MPR: { name: "Modified Privileges Required", optional: true, options: [
      { v: "X", l: "Not Defined" },
      { v: "N", l: "None" },
      { v: "L", l: "Low" },
      { v: "H", l: "High" },
    ]},
    MUI: { name: "Modified User Interaction", optional: true, options: [
      { v: "X", l: "Not Defined" },
      { v: "N", l: "None", n: 0.85 },
      { v: "R", l: "Required", n: 0.62 },
    ]},
    MS: { name: "Modified Scope", optional: true, options: [
      { v: "X", l: "Not Defined" },
      { v: "U", l: "Unchanged" },
      { v: "C", l: "Changed" },
    ]},
    MC: { name: "Modified Confidentiality", optional: true, options: [
      { v: "X", l: "Not Defined" },
      { v: "H", l: "High", n: 0.56 },
      { v: "L", l: "Low", n: 0.22 },
      { v: "N", l: "None", n: 0 },
    ]},
    MI: { name: "Modified Integrity", optional: true, options: [
      { v: "X", l: "Not Defined" },
      { v: "H", l: "High", n: 0.56 },
      { v: "L", l: "Low", n: 0.22 },
      { v: "N", l: "None", n: 0 },
    ]},
    MA: { name: "Modified Availability", optional: true, options: [
      { v: "X", l: "Not Defined" },
      { v: "H", l: "High", n: 0.56 },
      { v: "L", l: "Low", n: 0.22 },
      { v: "N", l: "None", n: 0 },
    ]},
  },
};

const GROUP_ORDER = ["base", "temporal", "environmental"];
const METRIC_ORDER = {
  base: ["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
  temporal: ["E", "RL", "RC"],
  environmental: ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"],
};

const DEFAULTS = {
  AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N",
  E: "X", RL: "X", RC: "X",
  CR: "X", IR: "X", AR: "X",
  MAV: "X", MAC: "X", MPR: "X", MUI: "X", MS: "X", MC: "X", MI: "X", MA: "X",
};

/* ---------------------------------------------------------------------- *
 * 2. Scoring engine
 * ---------------------------------------------------------------------- */

function findOption(group, key, value) {
  return METRICS[group][key].options.find((o) => o.v === value);
}

function numeric(group, key, value) {
  const opt = findOption(group, key, value);
  return opt && typeof opt.n === "number" ? opt.n : null;
}

// Privileges Required (and Modified PR) depend on Scope.
function prValue(value, scope) {
  if (value === "N") return 0.85;
  if (scope === "C") {
    return value === "L" ? 0.68 : 0.5; // High
  }
  return value === "L" ? 0.62 : 0.27; // Unchanged, High
}

// Official Roundup(): avoids floating point drift, per Appendix A of the spec.
function roundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

function severityOf(score) {
  if (score === 0) return "none";
  if (score <= 3.9) return "low";
  if (score <= 6.9) return "medium";
  if (score <= 8.9) return "high";
  return "critical";
}

function computeScores(m) {
  const av = numeric("base", "AV", m.AV);
  const ac = numeric("base", "AC", m.AC);
  const pr = prValue(m.PR, m.S);
  const ui = numeric("base", "UI", m.UI);
  const c = numeric("base", "C", m.C);
  const i = numeric("base", "I", m.I);
  const a = numeric("base", "A", m.A);

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact =
    m.S === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * av * ac * pr * ui;

  let base = 0;
  if (impact > 0) {
    base = m.S === "U"
      ? roundUp(Math.min(impact + exploitability, 10))
      : roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  const e = numeric("temporal", "E", m.E);
  const rl = numeric("temporal", "RL", m.RL);
  const rc = numeric("temporal", "RC", m.RC);
  const temporal = roundUp(base * e * rl * rc);

  const cr = numeric("environmental", "CR", m.CR);
  const ir = numeric("environmental", "IR", m.IR);
  const ar = numeric("environmental", "AR", m.AR);

  const mav = m.MAV === "X" ? av : numeric("environmental", "MAV", m.MAV);
  const mac = m.MAC === "X" ? ac : numeric("environmental", "MAC", m.MAC);
  const ms = m.MS === "X" ? m.S : m.MS;
  const mpr = m.MPR === "X" ? prValue(m.PR, ms) : prValue(m.MPR, ms);
  const mui = m.MUI === "X" ? ui : numeric("environmental", "MUI", m.MUI);
  const mc = m.MC === "X" ? c : numeric("environmental", "MC", m.MC);
  const mi = m.MI === "X" ? i : numeric("environmental", "MI", m.MI);
  const ma = m.MA === "X" ? a : numeric("environmental", "MA", m.MA);

  const missRaw = 1 - (1 - cr * mc) * (1 - ir * mi) * (1 - ar * ma);
  const miss = Math.min(missRaw, 0.915);
  const modImpact =
    ms === "U"
      ? 6.42 * miss
      : 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);
  const modExploitability = 8.22 * mav * mac * mpr * mui;

  let environmental = 0;
  if (modImpact > 0) {
    environmental = ms === "U"
      ? roundUp(roundUp(Math.min(modImpact + modExploitability, 10)) * e * rl * rc)
      : roundUp(roundUp(Math.min(1.08 * (modImpact + modExploitability), 10)) * e * rl * rc);
  }

  return { base, temporal, environmental };
}

/* ---------------------------------------------------------------------- *
 * 3. Vector string
 * ---------------------------------------------------------------------- */

function toVectorString(m) {
  const parts = ["CVSS:3.1"];
  METRIC_ORDER.base.forEach((k) => parts.push(`${k}:${m[k]}`));
  ["temporal", "environmental"].forEach((group) => {
    METRIC_ORDER[group].forEach((k) => {
      if (m[k] !== "X") parts.push(`${k}:${m[k]}`);
    });
  });
  return parts.join("/");
}

function parseVectorString(str) {
  const trimmed = str.trim();
  if (!/^CVSS:3\.1\//.test(trimmed)) {
    throw new Error("Vector must start with CVSS:3.1/");
  }
  const m = { ...DEFAULTS };
  const tokens = trimmed.replace(/^CVSS:3\.1\//, "").split("/");
  const allKeys = [...METRIC_ORDER.base, ...METRIC_ORDER.temporal, ...METRIC_ORDER.environmental];
  tokens.forEach((tok) => {
    const [key, value] = tok.split(":");
    if (!key || !value) throw new Error(`Malformed segment "${tok}"`);
    if (!allKeys.includes(key)) throw new Error(`Unknown metric "${key}"`);
    const group = METRIC_ORDER.base.includes(key) ? "base"
      : METRIC_ORDER.temporal.includes(key) ? "temporal" : "environmental";
    if (!findOption(group, key, value)) throw new Error(`Invalid value "${value}" for ${key}`);
    m[key] = value;
  });
  METRIC_ORDER.base.forEach((k) => {
    if (!tokens.some((t) => t.startsWith(k + ":"))) {
      throw new Error(`Missing required base metric ${k}`);
    }
  });
  return m;
}

/* ---------------------------------------------------------------------- *
 * 4. State + persistence
 * ---------------------------------------------------------------------- */

const STORAGE_KEY = "cvss-calc-metrics";
const THEME_KEY = "cvss-calc-theme";

let state = { ...DEFAULTS };

function loadInitialState() {
  const params = new URLSearchParams(window.location.search);
  const vecParam = params.get("vector");
  if (vecParam) {
    try {
      return parseVectorString(decodeURIComponent(vecParam));
    } catch (e) {
      console.warn("Invalid vector in URL:", e.message);
    }
  }
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) return { ...DEFAULTS, ...JSON.parse(saved) };
  } catch (e) {
    /* localStorage unavailable — ignore */
  }
  return { ...DEFAULTS };
}

function persistState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (e) {
    /* ignore */
  }
}

/* ---------------------------------------------------------------------- *
 * 5. Rendering
 * ---------------------------------------------------------------------- */

const els = {};

function buildMetricGroup(group) {
  const container = document.createElement("div");
  container.className = "metric-grid";
  METRIC_ORDER[group].forEach((key) => {
    const def = METRICS[group][key];
    const wrap = document.createElement("div");
    wrap.className = "metric";

    const label = document.createElement("div");
    label.className = "metric-label";
    label.innerHTML = `<span>${def.name}</span><span class="abbr">${key}</span>`;
    wrap.appendChild(label);

    const row = document.createElement("div");
    row.className = "chip-row";
    def.options.forEach((opt) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "chip";
      chip.dataset.key = key;
      chip.dataset.value = opt.v;
      chip.setAttribute("aria-pressed", String(state[key] === opt.v));
      const weight = typeof opt.n === "number" ? `<span class="weight">${opt.n}</span>` : "";
      chip.innerHTML = `<span>${opt.l}</span>${weight}`;
      chip.addEventListener("click", () => {
        state[key] = opt.v;
        // Scope changes shift PR weighting — repaint chip labels affected by scope.
        recalculate();
        renderAll();
      });
      row.appendChild(chip);
    });
    wrap.appendChild(row);
    container.appendChild(wrap);
  });
  return container;
}

function renderMetricPanels() {
  GROUP_ORDER.forEach((group) => {
    const panel = document.getElementById(`panel-${group}`);
    panel.innerHTML = "";
    panel.appendChild(buildMetricGroup(group));
  });
}

function syncChipStates() {
  document.querySelectorAll(".chip").forEach((chip) => {
    const { key, value } = chip.dataset;
    chip.setAttribute("aria-pressed", String(state[key] === value));
  });
}

let scores = { base: 0, temporal: 0, environmental: 0 };
let activeTab = "base";

function activeScore() {
  return scores[activeTab];
}

function renderScore() {
  const score = activeScore();
  const sev = severityOf(score);
  els.scoreValue.textContent = score.toFixed(1);
  els.severityPill.textContent = sev === "none" ? "None" : sev.charAt(0).toUpperCase() + sev.slice(1);
  els.severityPill.className = `severity-pill ${sev}`;
  els.scoreLabel.textContent = `${activeTab.charAt(0).toUpperCase() + activeTab.slice(1)} Score`;

  const pct = Math.min(score, 10) / 10 * 100;
  els.gaugeMarker.style.left = `${pct}%`;

  els.subBase.textContent = scores.base.toFixed(1);
  els.subTemporal.textContent = scores.temporal.toFixed(1);
  els.subEnvironmental.textContent = scores.environmental.toFixed(1);

  document.querySelectorAll(".tab").forEach((tab) => {
    const g = tab.dataset.group;
    tab.querySelector(".tab-score").textContent = scores[g].toFixed(1);
  });
}

function renderVector() {
  els.vectorString.textContent = toVectorString(state);
}

function recalculate() {
  scores = computeScores(state);
  persistState();
}

function renderAll() {
  syncChipStates();
  renderScore();
  renderVector();
}

/* ---------------------------------------------------------------------- *
 * 6. Tabs
 * ---------------------------------------------------------------------- */

function setActiveTab(group) {
  activeTab = group;
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.group === group);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `panel-${group}`);
  });
  renderScore();
}

/* ---------------------------------------------------------------------- *
 * 7. Toast helper
 * ---------------------------------------------------------------------- */

let toastTimer = null;
function showToast(msg) {
  els.toast.textContent = msg;
  els.toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove("show"), 2200);
}

/* ---------------------------------------------------------------------- *
 * 8. Theme
 * ---------------------------------------------------------------------- */

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch (e) {
    /* ignore */
  }
  els.themeToggle.textContent = theme === "light" ? "🌙 Dark" : "☀️ Light";
}

function initTheme() {
  let theme;
  try {
    theme = localStorage.getItem(THEME_KEY);
  } catch (e) {
    theme = null;
  }
  if (!theme) {
    theme = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  applyTheme(theme);
}

/* ---------------------------------------------------------------------- *
 * 9. PDF export
 * ---------------------------------------------------------------------- */

function labelFor(group, key) {
  const opt = findOption(group, key, state[key]);
  return opt ? opt.l : state[key];
}

function downloadPDF() {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const vector = toVectorString(state);

  doc.setFillColor(21, 101, 192);
  doc.rect(0, 0, 210, 25, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("CVSS 3.1 VULNERABILITY REPORT", 20, 17);
  doc.setFontSize(10);
  doc.setFont("helvetica", "italic");
  doc.text(new Date().toLocaleString(), 200, 20, { align: "right" });

  let y = 35;
  const line = () => {
    doc.setDrawColor(21, 101, 192);
    doc.line(20, y, 190, y);
    y += 8;
  };
  const heading = (text) => {
    doc.setFont("helvetica", "bold");
    doc.setTextColor(21, 101, 192);
    doc.setFontSize(13);
    doc.text(text, 20, y);
    y += 8;
    doc.setFont("helvetica", "normal");
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(11);
  };

  heading("1. Vector String");
  doc.setFont("courier", "normal");
  doc.text(doc.splitTextToSize(vector, 165), 25, y);
  y += 10;
  doc.setFont("helvetica", "normal");
  line();

  heading("2. Scores");
  doc.text(`Base Score:          ${scores.base.toFixed(1)}  (${severityOf(scores.base)})`, 25, y); y += 7;
  doc.text(`Temporal Score:      ${scores.temporal.toFixed(1)}  (${severityOf(scores.temporal)})`, 25, y); y += 7;
  doc.text(`Environmental Score: ${scores.environmental.toFixed(1)}  (${severityOf(scores.environmental)})`, 25, y); y += 10;
  line();

  heading("3. Base Metrics");
  METRIC_ORDER.base.forEach((k) => {
    doc.text(`${METRICS.base[k].name} (${k}): ${labelFor("base", k)}`, 25, y);
    y += 6.5;
  });
  y += 4;
  line();

  const anyTemporalSet = METRIC_ORDER.temporal.some((k) => state[k] !== "X");
  if (anyTemporalSet) {
    heading("4. Temporal Metrics");
    METRIC_ORDER.temporal.forEach((k) => {
      doc.text(`${METRICS.temporal[k].name} (${k}): ${labelFor("temporal", k)}`, 25, y);
      y += 6.5;
    });
    y += 4;
    line();
  }

  const anyEnvSet = METRIC_ORDER.environmental.some((k) => state[k] !== "X");
  if (anyEnvSet) {
    heading("5. Environmental Metrics");
    METRIC_ORDER.environmental.forEach((k) => {
      doc.text(`${METRICS.environmental[k].name} (${k}): ${labelFor("environmental", k)}`, 25, y);
      y += 6.5;
    });
    y += 4;
    line();
  }

  if (y > 240) { doc.addPage(); y = 25; }
  heading("6. Mitigation Recommendations");
  const mitText =
    "- Apply vendor security patches promptly.\n" +
    "- Restrict unnecessary privileges and enforce least-privilege policies.\n" +
    "- Segment network zones and implement proper access control.\n" +
    "- Deploy Intrusion Detection and Prevention Systems (IDS/IPS).\n" +
    "- Conduct regular vulnerability assessments and penetration tests.";
  doc.text(doc.splitTextToSize(mitText, 165), 25, y);

  doc.setFont("helvetica", "italic");
  doc.setFontSize(9);
  doc.setTextColor(120);
  doc.text("Generated with the CVSS 3.1 Calculator", 105, 290, { align: "center" });

  doc.save("cvss-report.pdf");
}

/* ---------------------------------------------------------------------- *
 * 10. Wire up
 * ---------------------------------------------------------------------- */

function resetAll() {
  state = { ...DEFAULTS };
  recalculate();
  renderAll();
  showToast("Form reset");
}

function copyVector() {
  navigator.clipboard.writeText(toVectorString(state)).then(
    () => showToast("Vector string copied"),
    () => showToast("Couldn't copy — select and copy manually")
  );
}

function shareLink() {
  const url = new URL(window.location.href);
  url.search = "";
  url.searchParams.set("vector", toVectorString(state));
  navigator.clipboard.writeText(url.toString()).then(
    () => showToast("Link copied to clipboard"),
    () => showToast("Couldn't copy — copy the URL manually")
  );
}

function init() {
  els.scoreValue = document.getElementById("scoreValue");
  els.scoreLabel = document.getElementById("scoreLabel");
  els.severityPill = document.getElementById("severityPill");
  els.gaugeMarker = document.getElementById("gaugeMarker");
  els.subBase = document.getElementById("subBase");
  els.subTemporal = document.getElementById("subTemporal");
  els.subEnvironmental = document.getElementById("subEnvironmental");
  els.vectorString = document.getElementById("vectorString");
  els.toast = document.getElementById("toast");
  els.themeToggle = document.getElementById("themeToggle");
  els.importRow = document.getElementById("importRow");
  els.importInput = document.getElementById("importInput");

  initTheme();
  state = loadInitialState();

  renderMetricPanels();
  recalculate();
  renderAll();
  setActiveTab("base");

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => setActiveTab(tab.dataset.group));
  });

  els.themeToggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme");
    applyTheme(current === "light" ? "dark" : "light");
  });

  document.getElementById("resetBtn").addEventListener("click", resetAll);
  document.getElementById("copyVectorBtn").addEventListener("click", copyVector);
  document.getElementById("shareBtn").addEventListener("click", shareLink);
  document.getElementById("pdfBtn").addEventListener("click", downloadPDF);

  document.getElementById("importToggle").addEventListener("click", () => {
    els.importRow.classList.toggle("open");
    if (els.importRow.classList.contains("open")) els.importInput.focus();
  });
  document.getElementById("importApply").addEventListener("click", () => {
    try {
      state = parseVectorString(els.importInput.value);
      recalculate();
      renderAll();
      els.importRow.classList.remove("open");
      els.importInput.value = "";
      showToast("Vector loaded");
    } catch (e) {
      showToast(e.message);
    }
  });
}

document.addEventListener("DOMContentLoaded", init);
