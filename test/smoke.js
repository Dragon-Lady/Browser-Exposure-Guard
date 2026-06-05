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

  const report = scanTarget(root);
  const ids = new Set(report.findings.map((finding) => finding.id));
  assert(ids.has("chromium-advisory-watch-note"));
  assert(ids.has("browser-poc-artifact"));
  assert(ids.has("browser-experimental-flag-note"));
  assert.strictEqual(report.summary.high, 1);
  console.log("smoke tests passed");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
