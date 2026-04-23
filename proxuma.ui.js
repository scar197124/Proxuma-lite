
(function(global){
  "use strict";

  const pages = ["home", "about", "scanner"];

  function showPage(id) {
    pages.forEach((pageId) => {
      const el = document.getElementById(pageId);
      if (el) el.classList.toggle("active-page", pageId === id);
    });

    document.querySelectorAll("[data-page]").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-page") === id);
    });
  }

  function verdictLabel(verdict) {
    switch ((verdict || "").toUpperCase()) {
      case "CRITICAL": return "Do Not Open";
      case "HIGH": return "High Risk";
      case "MEDIUM": return "Proceed With Caution";
      case "LOW": return "Low Risk";
      default: return "Unable To Verify";
    }
  }

  function primaryConcern(result) {
    if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
      return "No major concerns detected.";
    }
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    for (const level of order) {
      const found = result.findings.find((f) => (f.level || "").toUpperCase() === level);
      if (found) return found.msg || "No major concerns detected.";
    }
    return result.findings[0].msg || "No major concerns detected.";
  }

  function escapeHtml(str) {
    return String(str)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function renderResult(result) {
    const card = document.getElementById("scanCard");
    if (!card) return;

    const verdict = (result.verdict || "UNKNOWN").toUpperCase();
    const label = verdictLabel(verdict);
    const concern = result.summary || primaryConcern(result);
    const score = Number(result.score || 0);
    const confidence = Number(result.confidence || 0);
    const breakdown = result.breakdown || {
      domainRisk: 0, protocolRisk: 0, pathRisk: 0, redirectRisk: 0, encodingRisk: 0
    };

    const findingsHtml = (result.findings || []).map((f) => {
      const lvl = (f.level || "INFO").toUpperCase();
      return `<div class="finding finding-${lvl.toLowerCase()}"><strong>${escapeHtml(lvl)}</strong> ${escapeHtml(f.msg || "")}</div>`;
    }).join("");

    const badgeHtml = (result.threatBadges || []).map((b) =>
      `<span class="threat-badge">${escapeHtml(b)}</span>`
    ).join("");

    card.className = "scan-card glass";
    card.innerHTML = `
      <div class="verdict-banner verdict-${verdict.toLowerCase()}">${escapeHtml(label)}</div>
      <div class="result-block">
        ${badgeHtml ? `<div class="badge-row">${badgeHtml}</div>` : ""}

        <div class="primary-concern">
          <div class="mini-label">Primary Concern</div>
          <div>${escapeHtml(concern)}</div>
        </div>

        <div class="score-line">
          <div>
            <div class="score-head">${escapeHtml(verdict)} · ${score}/100</div>
            <div class="score-sub">Overall Risk Score</div>
          </div>
          <div><strong>${confidence}%</strong></div>
        </div>

        <div class="summary-block">
          <div class="mini-label">Summary</div>
          <div>${escapeHtml(result.summary || "No summary available.")}</div>
        </div>

        <div class="confidence-row">
          <div><strong>Confidence</strong></div>
          <div>${confidence}%</div>
        </div>

        <div class="risk-grid">
          <div><span>Domain Risk</span><strong>${breakdown.domainRisk}/24</strong></div>
          <div><span>Protocol Risk</span><strong>${breakdown.protocolRisk}/24</strong></div>
          <div><span>Path Risk</span><strong>${breakdown.pathRisk}/24</strong></div>
          <div><span>Redirect Risk</span><strong>${breakdown.redirectRisk}/24</strong></div>
          <div><span>Encoding Risk</span><strong>${breakdown.encodingRisk}/24</strong></div>
        </div>

        <div class="findings-block">
          <div class="mini-label">Findings</div>
          ${findingsHtml || '<div class="finding"><strong>INFO</strong> No findings.</div>'}
        </div>

        <details class="technical-details">
          <summary>Show technical details</summary>
          <div class="details-grid">
            <div><strong>Verdict:</strong> ${escapeHtml(verdict)}</div>
            <div><strong>Confidence:</strong> ${confidence}%</div>
            <div><strong>Domain Risk:</strong> ${breakdown.domainRisk}</div>
            <div><strong>Protocol Risk:</strong> ${breakdown.protocolRisk}</div>
            <div><strong>Path Risk:</strong> ${breakdown.pathRisk}</div>
            <div><strong>Redirect Risk:</strong> ${breakdown.redirectRisk}</div>
            <div><strong>Encoding Risk:</strong> ${breakdown.encodingRisk}</div>
          </div>
        </details>
      </div>
    `;
  }

  function analyzeURL(url) {
    if (!global.ProxumaSecurity || typeof global.ProxumaSecurity.analyze !== "function") {
      return {
        verdict: "UNKNOWN",
        score: 0,
        confidence: 0,
        summary: "Security engine not loaded.",
        findings: [],
        breakdown: { domainRisk: 0, protocolRisk: 0, pathRisk: 0, redirectRisk: 0, encodingRisk: 0 },
        threatBadges: []
      };
    }

    const raw = global.ProxumaSecurity.analyze(url);
    return global.ProxumaClean.adaptResult(raw);
  }

  function setStatus(text) {
    const status = document.getElementById("statusText");
    if (status) status.textContent = text;
  }

  function runAnalysis() {
    const input = document.getElementById("scanInput");
    const url = input ? input.value.trim() : "";

    if (!url) {
      setStatus("Enter a URL first.");
      alert("Enter a URL");
      return;
    }

    try {
      const result = analyzeURL(url);
      renderResult(result);
      setStatus("Analysis complete.");
      showPage("scanner");
    } catch (err) {
      console.error(err);
      setStatus("Analysis failed.");
      alert("Analysis failed. Check console.");
    }
  }

  function copyCurrentURL() {
    const input = document.getElementById("scanInput");
    if (!input || !input.value.trim()) {
      setStatus("Nothing to copy.");
      return;
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(input.value.trim())
        .then(() => setStatus("Copied current URL."))
        .catch(() => setStatus("Copy failed."));
    } else {
      input.select();
      document.execCommand("copy");
      setStatus("Copied current URL.");
    }
  }

  function loadSampleThreat() {
    const input = document.getElementById("scanInput");
    if (input) input.value = "http://paypal-login-secure.xyz/verify";
    setStatus("Sample threat loaded.");
    showPage("scanner");
  }

  function toggleTheme() {
    document.body.classList.toggle("theme-light");
    document.body.classList.toggle("theme-dark");
  }

  function init() {
    document.querySelectorAll("[data-page]").forEach((btn) => {
      btn.addEventListener("click", () => showPage(btn.getAttribute("data-page")));
    });

    const scanButton = document.getElementById("scanButton");
    if (scanButton) scanButton.addEventListener("click", runAnalysis);

    const copyButton = document.getElementById("copyCurrentButton");
    if (copyButton) copyButton.addEventListener("click", copyCurrentURL);

    const sampleButton = document.getElementById("sampleButton");
    if (sampleButton) sampleButton.addEventListener("click", loadSampleThreat);

    const themeToggle = document.getElementById("themeToggle");
    if (themeToggle) {
      themeToggle.checked = false;
      themeToggle.addEventListener("change", toggleTheme);
    }

    const input = document.getElementById("scanInput");
    if (input) {
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") runAnalysis();
      });
    }

    showPage("home");
  }

  global.addEventListener("DOMContentLoaded", init);
  global.ProxumaUI = { showPage, runAnalysis, toggleTheme };
})(window);


// === QR FIX FINAL ===
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("qrToggleButton");
  const wrap = document.getElementById("qrScannerWrap");
  const input = document.getElementById("scanInput");
  const scanBtn = document.getElementById("scanButton");
  const status = document.getElementById("statusText");

  let qr = null;
  let active = false;

  if (!btn || !wrap) return;

  btn.onclick = async () => {
    active = !active;

    if (active) {
      wrap.style.display = "block";
      btn.textContent = "Hide QR Scanner";

      try {
        qr = new Html5Qrcode("qrReader");
        await qr.start(
          { facingMode: "environment" },
          { fps: 10, qrbox: 250 },
          (text) => {
            if (input) input.value = text;
            if (status) status.textContent = "QR scanned.";
            if (scanBtn) scanBtn.click();
            stop();
          }
        );
      } catch (e) {
        if (status) status.textContent = "Camera blocked.";
      }

    } else {
      stop();
    }
  };

  async function stop() {
    active = false;
    wrap.style.display = "none";
    btn.textContent = "Show QR Scanner";
    try {
      if (qr) {
        await qr.stop();
        await qr.clear();
        qr = null;
      }
    } catch {}
  }
});
