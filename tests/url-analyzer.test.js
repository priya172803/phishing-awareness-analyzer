const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeURL } = require("../app.js");

test("detects lookalike PayPal-style domain in supplied sample", () => {
  const result = analyzeURL("https://paypaI-security.example/login");
  assert.equal(result.riskLevel, "Low");
  assert.ok(result.findings.some(item => item.indicator === "Possible typosquatting"));
});

test("flags IP address and non-HTTPS", () => {
  const result = analyzeURL("http://192.0.2.44/login");
  assert.ok(result.findings.some(item => item.indicator === "IP-based link"));
  assert.ok(result.findings.some(item => item.indicator === "No HTTPS"));
  assert.ok(!result.findings.some(item => item.indicator === "Many subdomain levels"));
});

test("does not flag a standard HTTPS reference URL", () => {
  const result = analyzeURL("https://docs.python.org/3/");
  assert.equal(result.riskLevel, "Low");
  assert.equal(result.findings.length, 0);
});

test("rejects empty and malformed input", () => {
  assert.ok(analyzeURL("").error);
  assert.ok(analyzeURL("not a valid url with spaces").error);
});
