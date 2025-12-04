// Proxuma Security Engine – Heuristic v10
// v10: structural + behavioral + contextual heuristics with guardrails and complexity checks.

;(function (global) {
  "use strict";

  const SAFE_TLDS = [
    "com","net","org","io","co","ca","edu","gov","uk","de","fr","nl","eu",
    "biz","info","me","app","dev","ai","bank","finance","money","shop","store"
  ];

  const SUSPICIOUS_TLDS = [
    "ru","su","cn","top","tk","gq","ml","cf","xyz","work","click","country",
    "zip","party","link","loan","mom","quest","cam","kim","men"
  ];

  const DANGEROUS_EXT = [
    ".exe",".scr",".bat",".cmd",".vbs",".js",".jar",".msi",".ps1",".apk"
  ];

  const URL_SHORTENERS = [
    "bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","buff.ly","is.gd","cutt.ly",
    "rebrand.ly","lnkd.in","adf.ly"
  ];

  const BRAND_PROFILES = [
    "google","rbc","td","cibc","bmo","scotiabank","paypal","amazon","apple",
    "microsoft","outlook","office","facebook","instagram","whatsapp","twitter",
    "x","binance","coinbase","kraken","metamask","netflix","spotify","chase",
    "wellsfargo","bankofamerica","hsbc","santander","cbc","gmail","yahoo","bbc"
  ];

  const SUSPICIOUS_PROTOCOLS = [
    "javascript","data","file","ftp","chrome","chrome-extension","ms-settings"
  ];

  function clamp(v, min, max) {
    return v < min ? min : v > max ? max : v;
  }

  function computeEntropy(str) {
    if (!str) return 0;
    const map = Object.create(null);
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      map[c] = (map[c] || 0) + 1;
    }
    let h = 0;
    const len = str.length;
    for (const ch in map) {
      const p = map[ch] / len;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function looksLikeIp(host) {
    if (!host) return false;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) return true;
    if (/^[0-9a-f:]+$/i.test(host) && host.indexOf(":") !== -1) return true;
    return false;
  }

  function hasPunycode(host) {
    return typeof host === "string" && host.toLowerCase().indexOf("xn--") !== -1;
  }

  function hasNonAscii(host) {
    return /[^\x00-\x7F]/.test(host || "");
  }

  function hasMixedLatinCyrillic(host) {
    if (!host) return false;
    const hasLatin = /[A-Za-z]/.test(host);
    const hasCyr = /[А-Яа-яЁё]/.test(host);
    return hasLatin && hasCyr;
  }

  function isUrlShortener(hostname) {
    if (!hostname) return false;
    const h = hostname.toLowerCase();
    return URL_SHORTENERS.some((s) => h === s || h.endsWith("." + s));
  }

  function percentEncodedRatio(str) {
    if (!str) return 0;
    const total = str.length;
    if (!total) return 0;
    const enc = (str.match(/%[0-9A-Fa-f]{2}/g) || []).length;
    return (enc * 3) / total;
  }

  function hasDangerousExtension(pathname) {
    if (!pathname) return null;
    const lower = pathname.toLowerCase();
    const lastDot = lower.lastIndexOf(".");
    if (lastDot === -1) return null;
    const ext = lower.slice(lastDot);
    if (DANGEROUS_EXT.includes(ext)) return ext;
    return null;
  }

  function hasDoubleExtension(pathname) {
    if (!pathname) return false;
    const lower = pathname.toLowerCase();
    return /(\.txt|\.pdf|\.docx?|\.jpe?g|\.png|\.gif)\.(exe|scr|bat|cmd|vbs|js|jar|msi|apk)$/.test(lower);
  }

  function isLikelyBase64(str) {
    if (!str || str.length < 16) return false;
    if (!/^[A-Za-z0-9+/_=-]+$/.test(str)) return false;
    return true;
  }

  function safeAtobValue(v) {
    try {
      if (typeof atob === "function") {
        return atob(v);
      }
    } catch (e) {
      return null;
    }
    return null;
  }

  function deepDecodeBase64(value, maxDepth) {
    const out = [];
    let current = value;
    for (let d = 0; d < maxDepth; d++) {
      if (!isLikelyBase64(current)) break;
      let attempt = current.replace(/-/g, "+").replace(/_/g, "/");
      while (attempt.length % 4 !== 0) attempt += "=";
      const res = safeAtobValue(attempt);
      if (!res) break;
      out.push(res);
      current = res;
    }
    return out;
  }

  function levenshtein(a, b) {
    if (!a || !b) return (a || "").length + (b || "").length;
    const dp = Array(a.length + 1).fill(0).map(() => Array(b.length + 1).fill(0));
    for (let i = 0; i <= a.length; i++) dp[i][0] = i;
    for (let j = 0; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        if (a[i - 1] === b[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = Math.min(
            dp[i - 1][j] + 1,
            dp[i][j - 1] + 1,
            dp[i - 1][j - 1] + 1
          );
        }
      }
    }
    return dp[a.length][b.length];
  }

  function getRegisteredDomain(hostname) {
    if (!hostname) return "";
    const parts = hostname.toLowerCase().split(".");
    if (parts.length <= 2) return hostname.toLowerCase();
    return parts.slice(-2).join(".");
  }

  function detectBrandImpersonation(hostname) {
    const host = (hostname || "").toLowerCase();
    const reg = getRegisteredDomain(host);
    for (const brand of BRAND_PROFILES) {
      if (!host.includes(brand)) continue;
      const expected1 = brand + ".com";
      const expected2 = brand + ".ca";
      if (reg !== expected1 && reg !== expected2) {
        return {
          brand,
          registered: reg,
          message:
            'Hostname appears to impersonate the brand "' +
            brand +
            '" (' +
            reg +
            "). Possible brand impersonation / phishing."
        };
      }
    }
    return null;
  }

  function looksLikeBrandSpoof(hostname) {
    const host = (hostname || "").toLowerCase();
    const reg = getRegisteredDomain(host);
    const bare = reg.replace(/\.[^.]+$/, "");
    for (const brand of BRAND_PROFILES) {
      const dist = levenshtein(bare, brand);
      if (dist === 1) {
        return {
          brand,
          registered: reg,
          message:
            'Registered domain "' +
            reg +
            '" is visually close to "' +
            brand +
            '" (possible typo-squatting / brand spoof).'
        };
      }
    }
    return null;
  }

  // Normalize user input: dot-substitution, www:example.com, commas, etc.
  function preprocessInput(rawInput) {
    let input = rawInput.trim();
    let normalized = input;
    const reasons = [];

    // spaces around dot
    const wsDotPattern = /([A-Za-z0-9])\s*\.\s*([A-Za-z0-9])/g;
    if (wsDotPattern.test(normalized)) {
      normalized = normalized.replace(wsDotPattern, "$1.$2");
      reasons.push("Input contained spaces around a dot; normalized into a standard dot.");
    }

    // www:example.com -> www.example.com
    const wwwMisplacedPattern = /(www)\s*[:;\/\\]+([A-Za-z0-9.-]+\.[A-Za-z]{2,})/i;
    if (wwwMisplacedPattern.test(normalized)) {
      normalized = normalized.replace(wwwMisplacedPattern, "$1.$2");
      reasons.push("Input used a colon/semicolon/slash after 'www'; normalized into 'www.' form.");
    }

    // cbc,com or unicode dots
    const dotSubPattern = /([A-Za-z0-9])[,•·…]([A-Za-z0-9])/g;
    if (dotSubPattern.test(normalized)) {
      normalized = normalized.replace(dotSubPattern, "$1.$2");
      reasons.push("Input used comma or unicode dot characters between domain parts; normalized into standard dots.");
    }

    const changed = normalized !== input;
    return {
      originalInput: input,
      normalizedInput: normalized,
      reasons,
      changed
    };
  }

  function analyze(urlInput) {
    const findings = [];
    const suggestions = [];
    const explanation = [];

    const categories = {
      domain: 0,
      protocol: 0,
      path: 0,
      redirect: 0,
      encoding: 0
    };

    const threatFlags = {
      phishing: false,
      credentialHarvest: false,
      malwareDownload: false,
      prizeScam: false,
      redirectAbuse: false,
      qrSuspicion: false,
      obfuscation: false,
      domainObfuscation: false
    };

    const decodedRedirects = [];

    if (!urlInput || typeof urlInput !== "string" || urlInput.trim() === "") {
      return {
        ok: false,
        error: "Empty input.",
        riskLevel: "safe",
        riskScore: 0
      };
    }

    const pre = preprocessInput(urlInput);
    let raw = pre.normalizedInput;
    const original = pre.originalInput;

    let risk = 0;
    let signalCount = 0;

    if (pre.changed && pre.reasons.length > 0) {
      threatFlags.domainObfuscation = true;
      categories.domain += 10;
      risk += 18;
      signalCount++;
      findings.push("Input looked like it used dot-substitution or unusual separators; Proxuma normalized it before analysis.");
      pre.reasons.forEach((r) => explanation.push(r));
    }

    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)) {
      raw = "https://" + raw;
    }

    let parsed;
    try {
      parsed = new URL(raw);
    } catch (e) {
      return {
        ok: false,
        error: "Invalid URL format even after normalization.",
        riskLevel: "safe",
        riskScore: 0,
        original
      };
    }

    const protocol = (parsed.protocol || "").replace(":", "").toLowerCase();
    const hostname = (parsed.hostname || "").toLowerCase();
    const pathname = parsed.pathname || "";
    const search = parsed.search || "";
    const tld = (hostname.split(".").pop() || "").toLowerCase();
    const fullPath = pathname + (search || "");
    const lowerFull = (parsed.href || "").toLowerCase();
    const urlLength = (parsed.href || "").length;
    const hasAtSymbol = (parsed.href || "").indexOf("@") !== -1;
    const port = parsed.port ? parseInt(parsed.port, 10) : null;

    // Protocol heuristics
    if (protocol === "https") {
      findings.push("Connection uses HTTPS. This helps protect transport but does not guarantee safety.");
    } else if (protocol === "http") {
      categories.protocol += 10;
      risk += 16;
      signalCount++;
      findings.push("Connection is not using HTTPS (http).");
      suggestions.push("Avoid entering credentials or sensitive data on HTTP pages.");
    } else if (SUSPICIOUS_PROTOCOLS.includes(protocol)) {
      categories.protocol += 22;
      risk += 32;
      signalCount++;
      threatFlags.malwareDownload = true;
      findings.push("Uncommon or high-risk protocol detected: " + protocol + ".");
      suggestions.push("Only continue if you fully trust the source and understand this protocol.");
    } else {
      categories.protocol += 6;
      risk += 8;
      signalCount++;
      findings.push("Non-standard web protocol detected: " + protocol + ".");
    }

    // Extra structural heuristics: length, '@', non-standard ports
    if (urlLength > 300) {
      categories.path += 8;
      risk += 12;
      signalCount++;
      findings.push("URL is very long (" + urlLength + " characters), which is common in tracking or attack URLs.");
    } else if (urlLength > 200) {
      categories.path += 4;
      risk += 6;
      signalCount++;
      findings.push("URL is unusually long (" + urlLength + " characters).");
    }

    if (hasAtSymbol) {
      categories.path += 10;
      risk += 15;
      signalCount++;
      threatFlags.phishing = true;
      findings.push("URL contains '@' in the address, which can be used to hide the true destination before the '@'.");
    }

    if (port && port !== 80 && port !== 443) {
      categories.protocol += 8;
      risk += 12;
      signalCount++;
      findings.push("URL uses a non-standard port (" + port + "), which is less common for normal websites.");
    }

    // Domain analysis
    if (!hostname) {
      categories.domain += 18;
      risk += 26;
      signalCount++;
      findings.push("URL does not contain a valid hostname.");
      suggestions.push("Do not trust URLs without a clear domain.");
    } else {
      if (looksLikeIp(hostname)) {
        categories.domain += 12;
        risk += 18;
        signalCount++;
        findings.push("Hostname is a bare IP address. This is common in evasive or temporary hosts.");
      }

      if (hasPunycode(hostname) || hasNonAscii(hostname)) {
        categories.domain += 20;
        risk += 28;
        signalCount++;
        threatFlags.phishing = true;
        findings.push("Hostname uses punycode or non-ASCII characters. Possible homograph attack.");
      }

      if (hasMixedLatinCyrillic(hostname)) {
        categories.domain += 16;
        risk += 22;
        signalCount++;
        threatFlags.phishing = true;
        findings.push("Hostname mixes Latin and Cyrillic characters, a strong indicator of homograph-style attacks.");
      }

      // Strict detection for suspicious "www" prefix without a dot (e.g. wwwpaypal.com, wwwnationnews.com)
      if (/^www[a-zA-Z0-9]/.test(hostname) && !hostname.startsWith("www.")) {
        categories.domain += 14;
        risk += 22;
        signalCount++;
        threatFlags.phishing = true;
        findings.push("Hostname begins with 'www' but is missing a dot after the prefix. Suspicious WWW prefix — possible impersonation.");
        explanation.push("Hostname starts with an attached 'www' prefix (e.g. 'wwwpaypal.com'), which is a common phishing pattern: missing dot after 'www' and visual impersonation of trusted domains.");
      }

      const subCount = hostname.split(".").length - 1;
      if (subCount >= 3) {
        categories.domain += 8;
        risk += 12;
        signalCount++;
        findings.push("Hostname uses many subdomains, which can hide the true base domain.");
      }

      const digits = (hostname.match(/\d/g) || []).length;
      if (digits >= 6) {
        categories.domain += 8;
        risk += 12;
        signalCount++;
        findings.push("Domain contains many digits, which is common in auto-generated or disposable hosts.");
      }

      if (tld) {
        if (!SAFE_TLDS.includes(tld)) {
          categories.domain += 8;
          risk += 11;
          signalCount++;
          findings.push("Uncommon top-level domain detected: ." + tld + ".");
        }
        if (SUSPICIOUS_TLDS.includes(tld)) {
          categories.domain += 12;
          risk += 18;
          signalCount++;
          findings.push("Top-level domain ." + tld + " is frequently associated with abuse or spam.");
        }
      }

      const brandImpersonation = detectBrandImpersonation(hostname);
      if (brandImpersonation) {
        categories.domain += 22;
        risk += 32;
        signalCount++;
        threatFlags.phishing = true;
        threatFlags.credentialHarvest = true;
        findings.push(brandImpersonation.message + " (brand impersonation / phishing risk).");
      }

      const brandSpoof = looksLikeBrandSpoof(hostname);
      if (brandSpoof) {
        categories.domain += 18;
        risk += 26;
        signalCount++;
        threatFlags.phishing = true;
        findings.push(brandSpoof.message + " This may be a typo-squatting domain.");
      }
    }

    // Path / query behavioral heuristics
    const loginRegex = /(login|signin|sign-in|password|reset|2fa|mfa|verify|update|billing|pay|payment|checkout)/i;
    const hasLoginKeyword = loginRegex.test(pathname) || loginRegex.test(search);

    if (hasLoginKeyword) {
      categories.path += 14;
      risk += 20;
      signalCount++;
      threatFlags.credentialHarvest = true;
      findings.push("Path or query suggests a login, verification, or payment page.");
    }

    const pathSegments = pathname.split("/").filter(Boolean);
    const folderDepth = pathSegments.length;
    if (folderDepth >= 5) {
      categories.path += 6;
      risk += 10;
      signalCount++;
      findings.push("URL path is very deep (" + folderDepth + " segments), which is common in obfuscated or generated attack paths.");
    }
    if (hasLoginKeyword && folderDepth >= 3) {
      categories.path += 6;
      risk += 10;
      signalCount++;
      findings.push("Login or billing keywords appear inside a deep path, increasing phishing likelihood.");
    }

    // Embedded domain patterns inside deep paths (phishing kits)
    const embeddedDomainPattern = /(https?:\/\/|www\.|[a-z0-9.-]+\.(com|net|org|io|ru|cn|top))/i;
    if (folderDepth >= 4 && embeddedDomainPattern.test(pathname)) {
      categories.path += 8;
      risk += 12;
      signalCount++;
      findings.push("Path contains embedded domain-like patterns inside a deep folder structure, which is common in phishing kit URLs.");
    }

    // File extension heuristics
    const dangerousExt = hasDangerousExtension(pathname);
    const doubleExt = hasDoubleExtension(pathname);

    if (dangerousExt) {
      categories.path += 20;
      risk += 30;
      signalCount++;
      threatFlags.malwareDownload = true;
      findings.push("URL points to a potentially dangerous file type (" + dangerousExt + ").");
    }

    if (doubleExt) {
      categories.path += 26;
      risk += 36;
      signalCount++;
      threatFlags.malwareDownload = true;
      findings.push("URL uses a double extension (e.g. .pdf.exe). Classic malware pattern.");
    }

    // Encoding / obfuscation
    const encRatio = percentEncodedRatio(fullPath);
    if (encRatio > 0.3) {
      categories.encoding += 16;
      risk += 24;
      signalCount++;
      threatFlags.obfuscation = true;
      findings.push("URL path/query is heavily percent-encoded, which can hide payloads or redirects.");
    } else if (encRatio > 0.2) {
      categories.encoding += 12;
      risk += 18;
      signalCount++;
      threatFlags.obfuscation = true;
      findings.push("URL uses a significant amount of percent-encoding.");
    } else if (encRatio > 0.1) {
      categories.encoding += 6;
      risk += 9;
      signalCount++;
      findings.push("URL contains some encoding. Not inherently malicious, but worth noting.");
    }

    // Keyword-based phishing / scam signals
    const phishingWords = [
      "secure-login","account-verify","account-update","security-check",
      "billing-update","verify-identity","password-reset"
    ];
    for (const kw of phishingWords) {
      if (lowerFull.indexOf(kw) !== -1) {
        categories.path += 10;
        risk += 14;
        signalCount++;
        threatFlags.phishing = true;
        threatFlags.credentialHarvest = true;
        findings.push('URL contains phishing-style keyword "' + kw + '".');
      }
    }

    const scamWords = [
      "claim-prize","you-won","limited-offer","act-now","gift-card","lottery","urgent-action"
    ];
    for (const kw of scamWords) {
      if (lowerFull.indexOf(kw) !== -1) {
        categories.path += 8;
        risk += 12;
        signalCount++;
        threatFlags.prizeScam = true;
        findings.push('URL contains scam-related keyword "' + kw + '".');
      }
    }

    // Query parameters: redirects & tokens
    const params = new URLSearchParams(search);
    let v10ParamCount = 0;
    for (const _ of params.entries()) {
      v10ParamCount++;
    }
    if (v10ParamCount >= 8) {
      categories.redirect += 8;
      risk += 12;
      signalCount++;
      findings.push("URL uses many query parameters (" + v10ParamCount + "), which is common in tracking, cloaking, or exploitation URLs.");
    } else if (v10ParamCount >= 5) {
      categories.redirect += 4;
      risk += 6;
      signalCount++;
      findings.push("URL has an unusually large number of query parameters (" + v10ParamCount + ").");
    }

    for (const [key, value] of params.entries()) {
      const lk = key.toLowerCase();
      const isRedirectKey = [
        "redirect","redir","url","target","dest","destination","r","u","continue","return","flow"
      ].includes(lk);

      if (isRedirectKey) {
        categories.redirect += 14;
        risk += 20;
        signalCount++;
        threatFlags.redirectAbuse = true;
        findings.push('Parameter "' + key + '" suggests a redirect or navigation flow.');
        const decodedLayers = deepDecodeBase64(value, 2);
        decodedLayers.forEach((dec, idx) => {
          if (/^https?:\/\//i.test(dec)) {
            decodedRedirects.push(dec);
            categories.redirect += 5;
            risk += 10;
            signalCount++;
            findings.push("Encoded layer " + (idx + 1) + " decodes to URL: " + dec);
          }
        });
      }

      if (/(token|session|auth|sid|id_token|cookie|jwt)/i.test(lk) && value && value.length >= 24) {
        categories.redirect += 4;
        categories.encoding += 4;
        risk += 10;
        signalCount++;
        findings.push('Parameter "' + key + '" looks like an authentication or session token.');
      }
    }

    // URL shortener
    if (isUrlShortener(hostname)) {
      categories.redirect += 12;
      risk += 18;
      signalCount++;
      threatFlags.redirectAbuse = true;
      findings.push("Hostname is a known URL shortener. Final destination is hidden until opened.");
    }

    // Entropy
    const entropy = computeEntropy(hostname + pathname.replace(/\//g, ""));
    if (entropy > 4.0) {
      categories.domain += 8;
      risk += 12;
      signalCount++;
      findings.push("Domain/path has high character entropy, which can indicate auto-generated or obfuscated URLs.");
    }

    // Cluster-based escalation
    const suspiciousTldUsed = !!tld && SUSPICIOUS_TLDS.includes(tld);
    const clusterSize =
      (threatFlags.phishing ? 1 : 0) +
      (threatFlags.credentialHarvest ? 1 : 0) +
      (threatFlags.malwareDownload ? 1 : 0) +
      (threatFlags.redirectAbuse ? 1 : 0) +
      (threatFlags.obfuscation ? 1 : 0) +
      (threatFlags.domainObfuscation ? 1 : 0);

    if (threatFlags.phishing && threatFlags.credentialHarvest) {
      risk += 12;
      categories.path += 6;
    }
    if (threatFlags.malwareDownload && encRatio > 0.2) {
      risk += 12;
      categories.encoding += 6;
    }
    if (threatFlags.redirectAbuse && decodedRedirects.length > 0) {
      risk += 10;
      categories.redirect += 6;
      if (decodedRedirects.length >= 2) {
        risk += 6;
        categories.redirect += 4;
      }
    }
    if (threatFlags.domainObfuscation) {
      risk += 14;
      categories.domain += 6;
    }
    if (hasLoginKeyword && (suspiciousTldUsed || threatFlags.redirectAbuse || encRatio > 0.1)) {
      risk += 18;
      categories.path += 8;
    }

    // Clamp category scores
    categories.domain = clamp(categories.domain, 0, 24);
    categories.protocol = clamp(categories.protocol, 0, 24);
    categories.path = clamp(categories.path, 0, 24);
    categories.redirect = clamp(categories.redirect, 0, 24);
    categories.encoding = clamp(categories.encoding, 0, 24);

    const categoriesTotal = categories.domain + categories.protocol + categories.path + categories.redirect + categories.encoding;

    let riskScore = clamp(Math.round(risk + categoriesTotal * 1.18), 0, 100);

    // Safe-anchor guardrail: structurally clean URLs shouldn't be rated too high
    const v10NoFlags =
      !threatFlags.phishing &&
      !threatFlags.credentialHarvest &&
      !threatFlags.malwareDownload &&
      !threatFlags.prizeScam &&
      !threatFlags.redirectAbuse &&
      !threatFlags.obfuscation &&
      !threatFlags.domainObfuscation;

    const v10LooksStructurallyClean =
      !looksLikeIp(hostname) &&
      (!tld || SAFE_TLDS.includes(tld)) &&
      encRatio < 0.05 &&
      folderDepth <= 3 &&
      !hasLoginKeyword &&
      !isUrlShortener(hostname) &&
      !hasAtSymbol &&
      urlLength < 200;

    if (v10NoFlags && v10LooksStructurallyClean && riskScore > 30) {
      riskScore = 30;
    }

    // Floors / escalations
    if (threatFlags.domainObfuscation && riskScore < 35) {
      riskScore = 35;
    }
    if (clusterSize >= 3 && riskScore < 55) riskScore = 55;
    if (clusterSize >= 4 && riskScore < 70) riskScore = 70;

    // Hard kill-switch rules
    let hardCritical = false;
    if (doubleExt || (dangerousExt && encRatio > 0.15)) {
      hardCritical = true;
      explanation.push("Executable or double extension combined with other risk factors triggers a critical kill-switch.");
    }
    if (SUSPICIOUS_PROTOCOLS.includes(protocol)) {
      hardCritical = true;
    }
    if (looksLikeIp(hostname) && hasLoginKeyword) {
      hardCritical = true;
    }
    if (hardCritical && riskScore < 90) riskScore = 90;

    // Confidence
    const baseConfidence = signalCount * 6 + clusterSize * 10;
    const scoreFactor = riskScore / 1.6;
    let confidence = clamp(Math.round(baseConfidence + scoreFactor), 20, 100);
    if (hardCritical && confidence < 85) confidence = 85;

    // Threat typing + intent
    let threatType = "General URL Analysis";
    let intentType = "General Navigation";
    let summary = "No strong malicious pattern detected. Still exercise normal caution when visiting unknown links.";
    let verdict = "Safe to open in most cases, but always double-check the context and sender.";

    if (riskScore <= 10) {
      summary = "URL appears low-risk based on structural analysis. This does not guarantee safety; always verify context.";
      verdict = "Low risk. Safe to open in normal situations, but remain aware.";
    } else if (riskScore <= 30) {
      threatType = "Low-Risk / Suspicious Elements";
      summary = "Some mild suspicious patterns were detected, but no clear attack archetype.";
      verdict = "Proceed with caution. Do not enter sensitive information unless you fully trust the source.";
    } else if (riskScore <= 60) {
      threatType = "Suspicious URL";
      summary = "Multiple suspicious patterns detected. This link may be part of a phishing or scam attempt.";
      verdict = "Do not enter passwords or financial data. Only continue if you can independently verify the link.";
    } else if (riskScore <= 80) {
      threatType = "High-Risk URL";
      summary = "Strong signals of malicious or high-risk behavior were detected.";
      verdict = "Avoid interacting with this link. Treat it as dangerous unless you have very strong reasons to trust it.";
    } else {
      threatType = "Critical Threat URL";
      summary = "This URL matches multiple critical danger patterns (phishing/malware/redirect abuse).";
      verdict = "Do not open this link. Treat it as a likely phishing or malware delivery attempt.";
      intentType = "Critical Threat / Do Not Open";
    }

    if (threatFlags.malwareDownload && riskScore >= 40) {
      threatType = "Malware / Suspicious Download";
      intentType = "Malware / File Delivery";
      summary = "This URL appears to lead to a potentially dangerous executable or script download.";
    } else if (threatFlags.credentialHarvest && riskScore >= 40) {
      threatType = "Credential Phishing / Account Theft";
      intentType = "Credential Theft / Account Access";
      summary = "This URL looks like a login or verification page designed to harvest credentials.";
    } else if (threatFlags.prizeScam && riskScore >= 30) {
      threatType = "Prize / Lottery Scam";
      intentType = "Scam / Reward Lure";
      summary = "This URL matches common language used in prize, lottery, or gift card scams.";
    } else if (threatFlags.redirectAbuse && riskScore >= 30) {
      threatType = "Obfuscated Redirect Chain";
      intentType = "Redirect Cloaking / Traffic Laundering";
      summary = "This URL appears to hide its final destination using redirects or shorteners.";
    } else if (threatFlags.obfuscation && riskScore >= 30) {
      threatType = "Obfuscated / Encoded URL";
      intentType = "Obfuscated / Hidden Payload";
      summary = "This URL contains significant encoding or obfuscation, which is often used to conceal payloads.";
    } else if (threatFlags.domainObfuscation && riskScore >= 30) {
      threatType = "Domain Obfuscation / Dot-Substitution Attack";
      intentType = "Domain Obfuscation Attack";
      summary = "This URL appears to have used unusual characters instead of dots in the domain, a known obfuscation trick.";
    }

    if (hardCritical) {
      threatType = "Critical Threat URL";
      intentType = "Critical Threat / Do Not Open";
      summary = "Engine kill-switch triggered: this URL matches one or more high-danger patterns.";
      verdict = "Do not open this link. Treat it as a likely phishing or malware attempt.";
    }

    const riskLevel =
      riskScore >= 85
        ? "critical"
        : riskScore >= 60
        ? "high"
        : riskScore >= 35
        ? "medium"
        : riskScore >= 15
        ? "low"
        : "safe";

    const threatBadges = [];
    if (threatFlags.credentialHarvest) threatBadges.push("Credential Theft / Phishing");
    if (threatFlags.malwareDownload) threatBadges.push("Malicious Download");
    if (threatFlags.redirectAbuse) threatBadges.push("Redirect Cloaking");
    if (threatFlags.obfuscation) threatBadges.push("Obfuscated URL");
    if (threatFlags.prizeScam) threatBadges.push("Prize / Lottery Scam");
    if (threatFlags.phishing && !threatFlags.credentialHarvest) {
      threatBadges.push("Suspicious Login / Verification");
    }
    if (threatFlags.domainObfuscation) {
      threatBadges.push("Domain Obfuscation / Dot-Substitution");
    }

    const vectors = {
      domain: categories.domain,
      protocol: categories.protocol,
      path: categories.path,
      redirect: categories.redirect,
      encoding: categories.encoding
    };

    return {
      ok: true,
      original,
      protocol,
      hostname,
      pathname,
      search,
      tld,
      riskLevel,
      riskScore,
      confidence,
      threatType,
      intentType,
      summary,
      verdict,
      findings,
      suggestions,
      explanation,
      entropy,
      categories,
      vectors,
      threatBadges,
      decodedRedirects
    };
  }

  global.ProxumaSecurity = {
    analyze
  };
})(window);
