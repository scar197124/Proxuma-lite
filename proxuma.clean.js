
(function(global){
  "use strict";

  function mapVerdict(level) {
    switch ((level || "").toLowerCase()) {
      case "critical": return "CRITICAL";
      case "high": return "HIGH";
      case "medium": return "MEDIUM";
      case "low": return "LOW";
      case "safe": return "LOW";
      default: return "UNKNOWN";
    }
  }

  function normalizeFindingLevel(text) {
    const value = String(text || "").toLowerCase();
    if (value.includes("critical")) return "CRITICAL";
    if (value.includes("high")) return "HIGH";
    if (value.includes("medium")) return "MEDIUM";
    if (value.includes("low")) return "LOW";
    return "INFO";
  }

  function adaptResult(r) {
    if (!r || typeof r !== "object") {
      return {
        verdict: "UNKNOWN",
        score: 0,
        confidence: 0,
        summary: "No result returned.",
        findings: [],
        breakdown: { domainRisk: 0, protocolRisk: 0, pathRisk: 0, redirectRisk: 0, encodingRisk: 0 },
        threatBadges: []
      };
    }

    const categories = r.categories || r.vectors || {};
    const explanationFindings = Array.isArray(r.explanation) ? r.explanation : [];
    const findings = [];

    (r.findings || []).forEach((msg) => {
      findings.push({ level: normalizeFindingLevel(msg), msg });
    });

    explanationFindings.slice(0, 4).forEach((msg) => {
      findings.push({ level: "INFO", msg });
    });

    return {
      verdict: mapVerdict(r.riskLevel),
      score: Number(r.riskScore || 0),
      confidence: Number(r.confidence || 0),
      summary: r.summary || "No summary available.",
      findings,
      breakdown: {
        domainRisk: Number(categories.domain || 0),
        protocolRisk: Number(categories.protocol || 0),
        pathRisk: Number(categories.path || 0),
        redirectRisk: Number(categories.redirect || 0),
        encodingRisk: Number(categories.encoding || 0)
      },
      threatBadges: Array.isArray(r.threatBadges) ? r.threatBadges : [],
      raw: r
    };
  }

  global.ProxumaClean = { adaptResult };
})(window);
