
function analyzeURL(url) {
  let findings = [];
  let score = 0;

  let hostname = "";
  let protocol = "";
  let pathname = "";
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname || "";
    protocol = parsed.protocol || "";
    pathname = parsed.pathname || "";
  } catch (e) {
    return {
      verdict: "UNKNOWN",
      confidence: 0,
      score: 0,
      summary: "Invalid URL.",
      breakdown: {
        domainRisk: 0,
        protocolRisk: 0,
        pathRisk: 0,
        redirectRisk: 0,
        encodingRisk: 0
      },
      findings: [{ level: "INFO", msg: "URL could not be parsed." }]
    };
  }

  let domainRisk = 0;
  let protocolRisk = 0;
  let pathRisk = 0;
  let redirectRisk = 0;
  let encodingRisk = 0;

  const trusted = ["google.com", "google", "gstatic.com"];
  const isTrusted = trusted.some(d => hostname === d || hostname.endsWith("." + d));

  if (protocol === "https:") {
    findings.push({
      level: "LOW",
      msg: "Connection uses HTTPS. This helps protect transport but does not guarantee safety."
    });
  } else if (protocol && protocol !== "https:") {
    protocolRisk += 10;
    findings.push({
      level: "MEDIUM",
      msg: "Connection is not using HTTPS."
    });
  }

  if (isTrusted) {
    findings.push({
      level: "LOW",
      msg: "Trusted platform detected."
    });
  }

  if (hostname.includes("share")) {
    redirectRisk += 10;
    findings.push({
      level: "MEDIUM",
      msg: "Redirect or shared link detected."
    });
  }

  if (url.includes("share.google")) {
    findings.push({
      level: "INFO",
      msg: "Content requires access (restricted)."
    });
  }

  if (/%[0-9A-Fa-f]{2}/.test(url)) {
    encodingRisk += 5;
    findings.push({
      level: "LOW",
      msg: "Encoded characters present in URL."
    });
  }

  if ((pathname || "").length > 60 || url.length > 100) {
    pathRisk += 5;
    findings.push({
      level: "LOW",
      msg: "Long path or URL length detected."
    });
  }

  score = domainRisk + protocolRisk + pathRisk + redirectRisk + encodingRisk;

  let verdict = "LOW";
  if (url.includes("share.google")) {
    verdict = "UNKNOWN";
  } else if (score > 60) {
    verdict = "HIGH";
  } else if (score > 30) {
    verdict = "MEDIUM";
  }

  let confidence = Math.min(100, Math.max(35, score + 35));
  if (verdict === "UNKNOWN") confidence = 70;
  if (verdict === "LOW") confidence = Math.max(confidence, 65);

  let summary = "Link appears relatively safe.";
  if (verdict === "UNKNOWN") {
    summary = "The platform appears trusted, but the content cannot be verified because access is restricted.";
  } else if (verdict === "MEDIUM") {
    summary = "This link shows some suspicious characteristics and should be reviewed carefully.";
  } else if (verdict === "HIGH") {
    summary = "This link shows strong indicators of elevated risk.";
  }

  return {
    verdict,
    score,
    confidence,
    summary,
    breakdown: {
      domainRisk,
      protocolRisk,
      pathRisk,
      redirectRisk,
      encodingRisk
    },
    findings
  };
}
