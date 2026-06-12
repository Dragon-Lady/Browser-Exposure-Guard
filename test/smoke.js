"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scanTarget } = require("../src/scanner");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "browser-exposure-guard-"));
try {
  fs.writeFileSync(
    path.join(root, "chromium-watch.md"),
    [
      "CVE-2026-3921",
      "TextEncoding use-after-free",
      "issues.chromium.org/issues/484946544",
      "Canvas2D beginLayer issues.chromium.org/issues/485677960",
    ].join("\n")
  );

  fs.writeFileSync(
    path.join(root, "repro.html"),
    [
      "<!doctype html>",
      "<script>",
      "const c = document.createElement('canvas');",
      "const ctx = c.getContext('2d');",
      "ctx.beginLayer?.({ filter: 'blur(1px)' });",
      "const d = new TextDecoder();",
      "// CVE-2026-3921 use-after-free crash repro PoC",
      "</script>",
    ].join("\n")
  );

  fs.writeFileSync(
    path.join(root, "flags.html"),
    "chrome://flags --enable-experimental-web-platform-features\n"
  );

  fs.writeFileSync(
    path.join(root, ".html"),
    [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"800\" height=\"600\" style=\"opacity: 0; visibility: hidden;\">",
      "  <title>Business Analytics Chart</title>",
      "  <rect width=\"100%\" height=\"100%\" fill=\"transparent\" opacity=\"0\"/>",
      "  <text opacity=\"0\" fill=\"transparent\">Business Performance Dashboard</text>",
      "  <text id=\"analyticsSourcec0d82e\" data-analytics=\"revenue-1195,client-earningsannualriskannualsharesannual-yieldannual-statementquarterly-capitalquarterly-budgetquarterly-reportannual-summaryquarterly-investmentannual-earningsannualriskannualsharesannual-yieldannual-statementquarterly-capitalquarterly-budgetquarterly-reportannual-summaryquarterly-investmentannual\"></text>",
      "  <script>",
      "    const platformKeys = [String.fromCharCode(119,105,110,100,111,119), String.fromCharCode(108,111,99,97,116,105,111,110)];",
      "    const securityHash = 'fb2a4eddd2e063dc';",
      "    setTimeout(() => { const x = securityHash.charCodeAt(0) ^ 7; new Function('userIdentifier0445', 'return userIdentifier0445 + x'); }, 213);",
      "  </script>",
      "</svg>",
    ].join("\n")
  );

  const report = scanTarget(root);
  const ids = new Set(report.findings.map((finding) => finding.id));
  assert(ids.has("chromium-advisory-watch-note"));
  assert(ids.has("browser-poc-artifact"));
  assert(ids.has("browser-experimental-flag-note"));
  assert(ids.has("phishing-svg-disguised-as-html"));
  assert(ids.has("phishing-invisible-svg-script"));
  assert(ids.has("phishing-business-term-steganography"));
  assert(ids.has("kratos-phishing-campaign-watch"));
  assert.strictEqual(report.summary.high, 4);
  console.log("smoke tests passed");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
