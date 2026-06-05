"use strict";

const fs = require("fs");
const path = require("path");

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "coverage", ".next"]);
const TEXT_EXTENSIONS = new Set([
  "",
  ".css",
  ".har",
  ".htm",
  ".html",
  ".json",
  ".log",
  ".md",
  ".mhtml",
  ".svg",
  ".txt",
  ".xml",
]);

const BROWSER_ARTIFACT_EXTENSIONS = new Set([".html", ".htm", ".svg", ".mhtml", ".har"]);

const CHROMIUM_ADVISORY_TERMS = [
  "CVE-2026-3921",
  "TextEncoding",
  "use-after-free",
  "Canvas2D",
  "beginLayer",
  "issues.chromium.org/issues/484946544",
  "issues.chromium.org/issues/485677960",
];

function scanTarget(targetPath) {
  const root = path.resolve(targetPath || ".");
  const findings = [];
  let filesScanned = 0;

  walk(root, (filePath) => {
    filesScanned += 1;
    const text = readTextFile(filePath);
    if (text === null) return;
    inspectFile(filePath, root, text, findings);
  });

  return {
    tool: "browser-exposure-guard",
    version: "0.1.0",
    scannedAt: new Date().toISOString(),
    target: root,
    summary: summarize(filesScanned, findings),
    findings,
  };
}

function inspectFile(filePath, root, text, findings) {
  const relative = path.relative(root, filePath).replace(/\\/g, "/") || path.basename(filePath);
  const extension = path.extname(filePath).toLowerCase();

  if (BROWSER_ARTIFACT_EXTENSIONS.has(extension)) {
    scanBrowserArtifact(relative, text, findings);
  }

  scanChromiumAdvisoryNotes(relative, text, findings);
}

function scanBrowserArtifact(relative, text, findings) {
  const hasScript = /<script\b|javascript:/i.test(text);
  const hasBrowserRiskApi = /\b(CanvasRenderingContext2D|beginLayer|TextDecoder|TextEncoder|OffscreenCanvas|createImageBitmap|WebGL2RenderingContext|AudioWorklet|SharedArrayBuffer)\b/i.test(text);
  const hasExploitLanguage = /\b(CVE-\d{4}-\d+|use-after-free|type confusion|heap corruption|renderer rce|sandbox escape|poc|proof.of.concept|crash repro)\b/i.test(text);

  if (hasScript && hasBrowserRiskApi && hasExploitLanguage) {
    addFinding(
      findings,
      "high",
      "browser-poc-artifact",
      relative,
      "Local browser-rendered artifact combines script, browser attack-surface APIs, and exploit/repro language.",
      "script + browser API + exploit language",
      "Do not open this file in a normal browser profile. Review in an isolated text viewer or disposable VM."
    );
  }

  if (/--enable-blink-features|--enable-experimental-web-platform-features|chrome:\/\/flags|about:flags/i.test(text)) {
    addFinding(
      findings,
      "medium",
      "browser-experimental-flag-note",
      relative,
      "File references experimental browser flags or feature toggles.",
      "experimental browser flags",
      "Avoid enabling experimental flags on daily-driver browsers when reviewing untrusted repro artifacts."
    );
  }
}

function scanChromiumAdvisoryNotes(relative, text, findings) {
  const matched = CHROMIUM_ADVISORY_TERMS.filter((term) => text.includes(term));
  if (matched.length < 2) return;

  addFinding(
    findings,
    "medium",
    "chromium-advisory-watch-note",
    relative,
    "File references Chromium browser vulnerability watch terms.",
    matched.slice(0, 4).join(", "),
    "Verify browser patch state and avoid running linked PoCs or repro artifacts outside isolation."
  );
}

function walk(root, onFile) {
  let stat;
  try {
    stat = fs.statSync(root);
  } catch (_error) {
    return;
  }

  if (stat.isFile()) {
    onFile(root);
    return;
  }

  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && shouldReadFile(fullPath)) {
        onFile(fullPath);
      }
    }
  }
}

function shouldReadFile(filePath) {
  if (!TEXT_EXTENSIONS.has(path.extname(filePath).toLowerCase())) return false;
  try {
    return fs.statSync(filePath).size <= MAX_FILE_BYTES;
  } catch (_error) {
    return false;
  }
}

function readTextFile(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (_error) {
    return null;
  }
}

function addFinding(findings, severity, id, filePath, reason, evidence, guidance) {
  findings.push({ severity, id, path: filePath, reason, evidence, guidance });
}

function summarize(filesScanned, findings) {
  const summary = { filesScanned, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    summary[finding.severity] = (summary[finding.severity] || 0) + 1;
  }
  return summary;
}

module.exports = { scanTarget };
