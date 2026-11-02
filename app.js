(function () {
  "use strict";

  const TRUSTED_BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "github", "instagram", "facebook"];

  function levenshtein(a, b) {
    const row = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      let previous = row[0];
      row[0] = i;
      for (let j = 1; j <= b.length; j++) {
        const old = row[j];
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
        previous = old;
      }
    }
    return row[b.length];
  }

  function isIPAddress(host) {
    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
    const ipv6 = host.includes(":") && /^[0-9a-f:]+$/i.test(host);
    return ipv4 || ipv6;
  }

  function analyzeURL(input) {
    const findings = [];
    const raw = String(input || "").trim();
    if (!raw) return { error: "Please enter a URL to analyze." };

    let parsed;
    try {
      parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : "http://" + raw);
    } catch (_) {
      return { error: "That URL could not be parsed. Check the spelling and try again." };
    }

    const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    if (!host || !host.includes(".") && !isIPAddress(host)) {
      return { error: "Please enter a complete domain name or IP-based URL." };
    }

    if (parsed.protocol !== "https:") {
      findings.push({ points: 10, indicator: "No HTTPS", explanation: "The URL does not use HTTPS. This alone does not prove phishing." });
    }
    if (isIPAddress(host)) {
      findings.push({ points: 25, indicator: "IP-based link", explanation: "The link uses an IP address instead of a recognizable domain." });
    }
    if (parsed.username || parsed.password) {
      findings.push({ points: 25, indicator: "Embedded URL credentials", explanation: "The URL contains user information before the host, which can disguise the real destination." });
    }

    const firstLabel = host.split(".")[0];
    for (const brand of TRUSTED_BRANDS) {
      if (host === brand + ".com" || host.endsWith("." + brand + ".com")) continue;
      const firstTokens = firstLabel.split(/[^a-z0-9]+/).filter(Boolean);
      const resemblesBrand = firstTokens.some(token =>
        token.includes(brand) || (token.length >= 5 && levenshtein(token, brand) <= 1)
      );
      if (resemblesBrand) {
        findings.push({ points: 25, indicator: "Possible typosquatting", explanation: "The domain label resembles the well-known brand " + brand + ". This is a warning signal, not proof of impersonation." });
        break;
      }
    }

    const labels = host.split(".");
    if (!isIPAddress(host) && labels.length >= 4) {
      findings.push({ points: 10, indicator: "Many subdomain levels", explanation: "The hostname has several domain levels. Check which part is the registered domain." });
    }

    const score = Math.min(100, findings.reduce((sum, item) => sum + item.points, 0));
    const level = score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";
    return {
      input: raw, normalizedURL: parsed.href, host, riskScore: score, riskLevel: level,
      findings,
      summary: findings.length ? "One or more URL characteristics deserve a closer look." : "No configured suspicious URL indicators were detected."
    };
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { analyzeURL, isIPAddress, riskLevel: score => score >= 60 ? "High" : score >= 30 ? "Medium" : "Low" };
  }

  function init() {
    const input = document.getElementById("urlInput");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const sampleBtn = document.getElementById("sampleBtn");
    const error = document.getElementById("errorMessage");
    const results = document.getElementById("results");
    const resetBtn = document.getElementById("resetBtn");
    if (!input || !analyzeBtn || !results) return;

    function render() {
      const report = analyzeURL(input.value);
      error.hidden = true;
      if (report.error) {
        results.hidden = true;
        error.textContent = report.error;
        error.hidden = false;
        return;
      }
      results.hidden = false;
      document.getElementById("riskScore").textContent = report.riskScore;
      document.getElementById("riskChip").textContent = report.riskLevel + " risk";
      document.getElementById("riskChip").className = "risk-chip " + report.riskLevel.toLowerCase();
      document.getElementById("scoreTitle").textContent = report.riskLevel + " risk indicators";
      document.getElementById("scoreDescription").textContent = report.summary;
      document.getElementById("scoreFill").style.width = report.riskScore + "%";
      document.getElementById("scoreFill").style.background = report.riskLevel === "High" ? "var(--red)" : report.riskLevel === "Medium" ? "var(--amber)" : "var(--green)";
      document.getElementById("checkedUrl").textContent = report.normalizedURL;
      document.getElementById("findingCount").textContent = report.findings.length + (report.findings.length === 1 ? " finding" : " findings");
      const list = document.getElementById("findingsList");
      list.replaceChildren();
      if (!report.findings.length) {
        const empty = document.createElement("div");
        empty.className = "no-findings";
        empty.textContent = "✓ " + report.summary;
        list.appendChild(empty);
      } else {
        report.findings.forEach(item => {
          const row = document.createElement("article");
          row.className = "finding";
          const points = document.createElement("span");
          points.className = "finding-score";
          points.textContent = "+" + item.points;
          const content = document.createElement("div");
          const title = document.createElement("h4");
          title.textContent = item.indicator;
          const detail = document.createElement("p");
          detail.textContent = item.explanation;
          content.append(title, detail);
          row.append(points, content);
          list.appendChild(row);
        });
      }
      results.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    analyzeBtn.addEventListener("click", render);
    input.addEventListener("keydown", event => { if (event.key === "Enter") render(); });
    sampleBtn.addEventListener("click", () => {
      input.value = "https://paypaI-security.example/login";
      render();
    });
    resetBtn.addEventListener("click", () => {
      input.value = "";
      results.hidden = true;
      error.hidden = true;
      input.focus();
    });
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }
})();
