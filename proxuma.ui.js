// Proxuma UI binding for the Security Engine
// Handles navigation, theme switching, and rendering of scan results.

(function () {
  const scanInput = () => document.getElementById("scanInput");
  const scanCard = () => document.getElementById("scanCard");
  const themeToggleEl = () => document.getElementById("themeToggle");
  const themeLabel = () => document.getElementById("themeLabel");

  function showPage(pageId) {
    const ids = ["home", "about", "scanner"];
    ids.forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.style.display = id === pageId ? "block" : "none";
    });
  }
  window.showPage = showPage;

  function applyTheme(theme) {
    const body = document.body;
    body.classList.remove("theme-light", "theme-dark");
    if (theme === "dark") {
      body.classList.add("theme-dark");
      if (themeToggleEl()) themeToggleEl().checked = true;
      if (themeLabel()) themeLabel().textContent = "Dark Neon Mode";
    } else {
      body.classList.add("theme-light");
      if (themeToggleEl()) themeToggleEl().checked = false;
      if (themeLabel()) themeLabel().textContent = "Light Mode";
    }
    try {
      localStorage.setItem("proxuma-theme", theme);
    } catch (e) {}
  }

  function initTheme() {
    let theme = "light";
    try {
      const stored = localStorage.getItem("proxuma-theme");
      if (stored === "light" || stored === "dark") theme = stored;
    } catch (e) {}
    applyTheme(theme);
  }

  function toggleTheme() {
    const body = document.body;
    const isDark = body.classList.contains("theme-dark");
    applyTheme(isDark ? "light" : "dark");
  }
  window.toggleTheme = toggleTheme;

  function severityToClass(sev) {
    switch (sev) {
      case "critical":
        return "sev-critical";
      case "high":
        return "sev-high";
      case "medium":
        return "sev-medium";
      default:
        return "sev-low";
    }
  }

  function riskLevelToBadgeClass(level) {
    switch (level) {
      case "critical":
        return "risk-critical";
      case "high":
        return "risk-high";
      case "medium":
        return "risk-medium";
      case "low":
        return "risk-low";
      default:
        return "risk-safe";
    }
  }

  function riskLevelToLabel(level) {
    switch (level) {
      case "critical":
        return "CRITICAL THREAT";
      case "high":
        return "DANGER";
      case "medium":
        return "CAUTION";
      case "low":
        return "LOW RISK";
      default:
        return "SAFE";
    }
  }

  function renderResult(result) {
    const card = scanCard();
    if (!card) return;

    if (!result.ok) {
      card.className = "scan-card";
      card.innerHTML = "<p><strong>Scan error:</strong> " + (result.error || "Unknown error") + "</p>";
      return;
    }

    card.className = "scan-card";

    const riskLabel = riskLevelToLabel(result.riskLevel);
    const badgeClass = riskLevelToBadgeClass(result.riskLevel);
    const riskScore = result.riskScore;
    const confidence = result.confidence || 0;
    const threatType = result.threatType || "URL Analysis";

    const domainRisk = result.categories?.domain ?? 0;
    const protocolRisk = result.categories?.protocol ?? 0;
    const pathRisk = result.categories?.path ?? 0;
    const redirectRisk = result.categories?.redirect ?? 0;
    const encodingRisk = result.categories?.encoding ?? 0;

    const findings = result.findings || [];
    const suggestions = result.suggestions || [];
    const entropy = typeof result.entropy === "number" ? result.entropy.toFixed(2) : "n/a";

    const encodedOriginal = escapeHtml(result.original || "");
    const encodedHost = escapeHtml(result.hostname || "");
    const encodedPath = escapeHtml(result.pathname || "");
    const encodedSearch = escapeHtml(result.search || "");

    const findingsHtml = findings.length
      ? "<ul class=\"findings-list\">" +
        findings
          .map((msg, i) => {
            let sev = "low";
            if (msg.toLowerCase().includes("double extension") || msg.toLowerCase().includes("danger") || msg.toLowerCase().includes("critical")) {
              sev = "critical";
            } else if (msg.toLowerCase().includes("brand") || msg.toLowerCase().includes("punycode") || msg.toLowerCase().includes("impersonation")) {
              sev = "high";
            } else if (msg.toLowerCase().includes("suspicious") || msg.toLowerCase().includes("encoded") || msg.toLowerCase().includes("redirect")) {
              sev = "medium";
            }
            const sevClass = severityToClass(sev);
            return "<li><span class=\"severity-chip " + sevClass + "\">" + sev.toUpperCase() + "</span>" + escapeHtml(msg) + "</li>";
          })
          .join("") +
        "</ul>"
      : "<p>No detailed findings available for this URL.</p>";

    const suggestionsHtml = suggestions.length
      ? "<ul class=\"suggestions-list\">" +
        suggestions.map((msg) => "<li>" + escapeHtml(msg) + "</li>").join("") +
        "</ul>"
      : "";

    const techText =
      "Original: " +
      encodedOriginal +
      "\n" +
      "Protocol: " +
      escapeHtml(result.protocol || "") +
      "\n" +
      "Hostname: " +
      encodedHost +
      "\n" +
      "Path: " +
      encodedPath +
      "\n" +
      "Query: " +
      encodedSearch +
      "\n" +
      "TLD: " +
      escapeHtml(result.tld || "") +
      "\n" +
      "Entropy: " +
      entropy +
      "\n" +
      "Engine: " +
      escapeHtml((result && result.engineLabel) || "Proxuma Security Engine – Heuristic v14.1")

    const shieldHtml =
      '<div class="shield-panel">' +
      '<div class="shield-panel-header">' +
      '<div class="shield-panel-title">Proxuma Shield · Local Threat Posture</div>' +
      '<div class="shield-panel-badge ' +
      badgeClass +
      '">Shield status: ' +
      riskLabel +
      "</div>" +
      "</div>" +
      '<p class="shield-panel-copy">Shield Stage 1 is running in Lite preview mode. This view mirrors the analysis above and is computed entirely on your device.</p>' +
      "</div>";
;

    const html =
      "<div class=\"risk-badge " +
      badgeClass +
      "\">" +
      riskLabel +
      " · " +
      riskScore +
      "/100</div>" +
      "<div class=\"heat-meter\">" +
      '<div class=\"heat-bar-wrapper\">' +
      '<div class=\"heat-bar-fill\" style=\"width:' +
      riskScore +
      '%\"></div>' +
      "</div>" +
      '<div class=\"heat-meter-label\">Overall Risk Score</div>' +
      "</div>" +
      "<p><strong>Threat Type:</strong> " +
      escapeHtml(threatType) +
      "</p>" +
      "<p><strong>Summary:</strong> " +
      escapeHtml(result.summary || "") +
      "</p>" +
      '<div class=\"scan-meta\">' +
      '<div class=\"scan-meta-block\"><strong>Confidence</strong><br>' +
      confidence +
      "%</div>" +
      '<div class=\"scan-meta-block\"><strong>Domain Risk</strong><br>' +
      domainRisk +
      "/20</div>" +
      '<div class=\"scan-meta-block\"><strong>Protocol Risk</strong><br>' +
      protocolRisk +
      "/20</div>" +
      '<div class=\"scan-meta-block\"><strong>Path Risk</strong><br>' +
      pathRisk +
      "/20</div>" +
      '<div class=\"scan-meta-block\"><strong>Redirect Risk</strong><br>' +
      redirectRisk +
      "/20</div>" +
      '<div class=\"scan-meta-block\"><strong>Encoding Risk</strong><br>' +
      encodingRisk +
      "/20</div>" +
      "</div>" +
      shieldHtml +
      "<h3>Findings</h3>" +
      findingsHtml +
      (suggestionsHtml
        ? "<h3>Suggestions</h3>" + suggestionsHtml
        : "") +
      '<div class=\"tech-toggle\" onclick=\"toggleTechDetails()\">Show technical details</div>' +
      '<div id=\"techDetails\" class=\"tech-details\">' +
      techText +
      "</div>";

    card.innerHTML = html;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  window.toggleTechDetails = function toggleTechDetails() {
    const el = document.getElementById("techDetails");
    if (!el) return;
    if (el.style.display === "block") {
      el.style.display = "none";
    } else {
      el.style.display = "block";
    }
  };

  function runScan() {
    const inputEl = scanInput();
    if (!inputEl) return;
    const value = inputEl.value;
    const result = window.ProxumaSecurity.analyze(value);
    renderResult(result);
  }
  window.runScan = runScan;

  function copyLastURL() {
    const inputEl = document.getElementById("scanInput");
    if (!inputEl || !inputEl.value) {
      try { alert("No URL to copy."); } catch(e){}
      return;
    }
    const text = inputEl.value;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(err=>console.warn("Clipboard failed:",err));
    } else {
      try {
        inputEl.select();
        document.execCommand("copy");
      } catch(e){
        console.warn("Fallback copy failed:",e);
      }
    }
  }
  window.copyLastURL = copyLastURL;



  

  // ==== QR SCANNER LOGIC (Browser-local, no network) ====
  let qrScanning = false;
  let qrStream = null;
  let qrDetector = null;

  function getQrElements() {
    return {
      panel: document.getElementById("qrPanel"),
      toggleButton: document.getElementById("qrToggleButton"),
      video: document.getElementById("qrVideo"),
      canvas: document.getElementById("qrCanvas"),
      overlay: document.getElementById("qrOverlay"),
      status: document.getElementById("qrStatus"),
      decoded: document.getElementById("qrDecoded"),
      analyzeButton: document.getElementById("qrAnalyzeButton"),
      startButton: document.getElementById("qrStartButton"),
      stopButton: document.getElementById("qrStopButton")
    };
  }

  function updateQrStatus(msg) {
    const { status } = getQrElements();
    if (status) status.textContent = msg;
  }

  function toggleQrPanel() {
    const { panel, toggleButton } = getQrElements();
    if (!panel) return;
    const isHidden = panel.style.display === "none" || panel.style.display === "";
    panel.style.display = isHidden ? "block" : "none";
    if (toggleButton) {
      toggleButton.textContent = isHidden ? "Hide QR scanner" : "Show QR scanner";
    }
    if (!isHidden) {
      // If we just hid the panel, stop camera if running.
      stopQrScan(false);
    }
  }

  async function ensureBarcodeDetector() {
    if ("BarcodeDetector" in window) {
      qrDetector = qrDetector || new window.BarcodeDetector({ formats: ["qr_code"] });
      return true;
    }
    updateQrStatus("QR scanning is not supported in this browser. You can still paste or type a link above. For camera scanning, try a recent Chrome, Edge, Firefox, or mobile browser.");
    return false;
  }



  async function getCameraStream() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      updateQrStatus("Camera access is not available in this browser. You can still upload an image or paste a link.");
      throw new Error("getUserMedia not supported");
    }

    const primary = { video: { facingMode: { ideal: "environment" } } };
    const fallback = { video: true };

    try {
      return await navigator.mediaDevices.getUserMedia(primary);
    } catch (err) {
      console.warn("Primary camera constraints failed, falling back to generic video:", err);
      return await navigator.mediaDevices.getUserMedia(fallback);
    }
  }

  async function startQrScan() {
    const { video, startButton, stopButton, overlay, decoded, analyzeButton } = getQrElements();
    if (!video) return;

    if (qrScanning) {
      updateQrStatus("Scanner already running.");
      return;
    }

    const supported = await ensureBarcodeDetector();
    if (!supported) return;

    try {
      qrStream = await getCameraStream();
      video.srcObject = qrStream;
      qrScanning = true;
      if (overlay) overlay.style.opacity = "1";
      if (startButton) startButton.disabled = true;
      if (stopButton) stopButton.disabled = false;
      if (decoded) decoded.value = "";
      if (analyzeButton) analyzeButton.disabled = true;
      updateQrStatus("Camera active. Align a QR code in the frame.");
      requestAnimationFrame(qrScanLoop);
    } catch (err) {
      console.error("QR camera error:", err);
      updateQrStatus("Unable to access camera. Check permissions and try again.");
    }
  }

  function stopQrScan(updateText = true) {
    const { video, startButton, stopButton, overlay } = getQrElements();
    qrScanning = false;
    if (qrStream) {
      qrStream.getTracks().forEach((t) => t.stop());
      qrStream = null;
    }
    if (video) {
      video.srcObject = null;
    }
    if (startButton) startButton.disabled = false;
    if (stopButton) stopButton.disabled = true;
    if (overlay) overlay.style.opacity = "0.4";
    if (updateText) updateQrStatus("QR scanner idle.");
  }

  async function qrScanLoop() {
    if (!qrScanning) return;
    const { video, canvas, decoded, analyzeButton } = getQrElements();
    if (!video || !canvas || !qrDetector) {
      qrScanning = false;
      return;
    }

    const w = video.videoWidth;
    const h = video.videoHeight;
    if (!w || !h) {
      requestAnimationFrame(qrScanLoop);
      return;
    }

    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0, w, h);

    try {
      const bitmap = await createImageBitmap(canvas);
      const codes = await qrDetector.detect(bitmap);
      if (codes && codes.length > 0) {
        const value = codes[0].rawValue || codes[0].rawValue === "" ? codes[0].rawValue : "";
        if (value) {
          stopQrScan(false);
          if (decoded) decoded.value = value;
          if (analyzeButton) analyzeButton.disabled = false;
          updateQrStatus("QR code decoded. Review the link, then analyze.");
          return;
        }
      }
    } catch (err) {
      console.warn("QR detect error:", err);
    }

    if (qrScanning) {
      requestAnimationFrame(qrScanLoop);
    }
  }

  async function handleQrFile(files) {
    if (!files || !files.length) return;
    const file = files[0];
    const { canvas, decoded, analyzeButton } = getQrElements();
    if (!canvas) return;

    const supported = await ensureBarcodeDetector();
    if (!supported) return;

    const img = new Image();
    img.onload = async function () {
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0);
      try {
        const bitmap = await createImageBitmap(canvas);
        const codes = await qrDetector.detect(bitmap);
        if (codes && codes.length > 0) {
          const value = codes[0].rawValue || "";
          if (decoded) decoded.value = value;
          if (analyzeButton) analyzeButton.disabled = !value;
          updateQrStatus(value ? "QR image decoded. Review the link, then analyze." : "No QR code detected in this image.");
        } else {
          updateQrStatus("No QR code detected in this image.");
        }
      } catch (err) {
        console.error("QR image detect error:", err);
        updateQrStatus("Could not read QR image.");
      }
    };
    img.onerror = function () {
      updateQrStatus("Could not load the selected image.");
    };
    img.src = URL.createObjectURL(file);
  }

  function analyzeDecoded() {
    const { decoded } = getQrElements();
    if (!decoded || !decoded.value) {
      updateQrStatus("No decoded URL to analyze yet.");
      return;
    }
    const inputEl = scanInput();
    if (inputEl) {
      inputEl.value = decoded.value;
    }
    runScan();
  }

  // Expose QR functions for inline handlers
  window.toggleQrPanel = toggleQrPanel;
  window.startQrScan = startQrScan;
  window.stopQrScan = stopQrScan;
  window.handleQrFile = handleQrFile;
  window.analyzeDecoded = analyzeDecoded;

document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    const inputEl = scanInput();
    if (inputEl) {
      inputEl.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          runScan();
        }
      });
    }
  });

})();
