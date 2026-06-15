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

const BUSINESS_TERM_STEGO_TERMS = [
  "quarterly",
  "annual",
  "monthly",
  "revenue",
  "profit",
  "growth",
  "market",
  "sales",
  "customer",
  "analytics",
  "metrics",
  "forecast",
  "performance",
  "strategy",
  "operations",
  "budget",
  "finance",
  "report",
  "dashboard",
  "insight",
  "data",
  "trends",
  "analysis",
  "business",
  "overview",
  "summary",
  "review",
  "target",
  "goal",
  "objective",
  "kpi",
  "roi",
  "segment",
  "portfolio",
  "investment",
  "return",
  "cost",
  "expense",
  "value",
  "margin",
  "earnings",
  "income",
  "assets",
  "equity",
  "debt",
  "cash",
  "flow",
  "capital",
  "shares",
  "stock",
  "dividend",
  "yield",
  "risk",
  "beta",
  "alpha",
  "ratio",
  "balance",
  "sheet",
  "statement",
  "audit",
  "tax",
  "fiscal",
  "quarter",
  "year",
];

const CHROMIUM_ADVISORY_TERMS = [
  "CVE-2026-3921",
  "TextEncoding",
  "use-after-free",
  "Canvas2D",
  "beginLayer",
  "issues.chromium.org/issues/484946544",
  "issues.chromium.org/issues/485677960",
];

const AI_EXTENSION_WATCHLIST = new Map([
  [
    "difoiogjjojoaoomphldepapgpbgkhkb",
    {
      name: "SiderAI / Sider: Chat with all AI",
      issue: "Spyder UXSG exposure",
      impact: "arbitrary website-driven clicking and typing through extension-controlled embedded pages",
    },
  ],
  [
    "mhnlakgilnojmhinhkckjpncpbhabphi",
    {
      name: "MaxAI / MaxAI.me",
      issue: "MaXSS UXSS exposure",
      impact: "arbitrary website access to extension-level browser permissions",
    },
  ],
]);

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
  const extension = browserArtifactExtension(filePath);

  if (BROWSER_ARTIFACT_EXTENSIONS.has(extension)) {
    scanBrowserArtifact(relative, text, findings);
  }

  scanChromiumAdvisoryNotes(relative, text, findings);
  scanKnownAiExtensionManifest(relative, text, findings);
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

  scanPhishingAttachmentArtifact(relative, text, findings);
}

function scanPhishingAttachmentArtifact(relative, text, findings) {
  const extension = browserArtifactExtension(relative);
  const hasSvg = /<svg\b/i.test(text);
  const hasScript = /<script\b|javascript:|new\s+Function\s*\(|eval\s*\(/i.test(text);
  const htmlNamedSvg = (extension === ".html" || extension === ".htm") && hasSvg && !/<html\b/i.test(text.slice(0, 1000));
  const hiddenRenderMarkers = countMatches(text, /\b(?:opacity\s*=\s*["']?0["']?|visibility\s*:\s*hidden|visibility\s*=\s*["']hidden["']|fill\s*=\s*["']transparent["']|fill\s*:\s*transparent)\b/gi);
  const hasInvisibleSvgDashboard = hasSvg && hiddenRenderMarkers >= 3 && /\b(?:Business|Analytics|Dashboard|Performance|Revenue|Report)\b/i.test(text);
  const hasBusinessTermPayload = hasBusinessTermStegoPayload(text);
  const hasDynamicExecutionChain = /String\.fromCharCode\s*\(/i.test(text)
    && /(?:new\s+Function\s*\(|eval\s*\(|window\.location|location\.href)/i.test(text)
    && /(?:setTimeout\s*\(|charCodeAt\s*\(|\^\s*[^=]|%\s*256)/i.test(text);
  const hasKratosCampaignHash = /fb2a4eddd2e063dc/i.test(text);

  if (htmlNamedSvg && (hasScript || hasInvisibleSvgDashboard)) {
    addFinding(
      findings,
      "high",
      "phishing-svg-disguised-as-html",
      relative,
      "HTML-named browser artifact appears to contain SVG content, a common phishing attachment smuggling pattern.",
      "html extension + svg content",
      "Do not open this attachment in a normal browser profile. Review as text or in an isolated analysis environment."
    );
  }

  if (hasSvg && hasScript && hasInvisibleSvgDashboard) {
    addFinding(
      findings,
      "high",
      "phishing-invisible-svg-script",
      relative,
      "SVG artifact combines embedded script with invisible business-dashboard rendering camouflage.",
      "svg script + hidden visual elements",
      "Treat this as an active browser-executed attachment until proven benign."
    );
  }

  if (hasBusinessTermPayload && hasDynamicExecutionChain) {
    addFinding(
      findings,
      "high",
      "phishing-business-term-steganography",
      relative,
      "Browser artifact appears to combine business-term encoded payload data with dynamic JavaScript execution.",
      "business-term payload + dynamic execution",
      "Do not decode or execute the payload on a daily-driver host. Preserve the file and review in isolation."
    );
  }

  if (hasKratosCampaignHash || (hasBusinessTermPayload && hasInvisibleSvgDashboard && hasDynamicExecutionChain)) {
    addFinding(
      findings,
      "medium",
      "kratos-phishing-campaign-watch",
      relative,
      "File matches Kratos-style SVG phishing attachment watch signals reported by Sublime Security.",
      hasKratosCampaignHash ? "campaign hash marker" : "svg + business-term encoding + dynamic execution",
      "Correlate with sender reputation, authentication results, and attachment metadata before user exposure."
    );
  }
}

function hasBusinessTermStegoPayload(text) {
  const attributeMatches = text.match(/\bdata-[a-z0-9_-]+\s*=\s*["'][^"']{250,}["']/gi) || [];
  const candidateText = attributeMatches.length > 0 ? attributeMatches.join("\n") : text;
  const termMatches = BUSINESS_TERM_STEGO_TERMS.reduce((count, term) => {
    const pattern = new RegExp(`\\b${escapeRegExp(term)}\\b`, "gi");
    return count + countMatches(candidateText, pattern);
  }, 0);
  const concatenatedPairHits = countMatches(
    candidateText,
    /(?:earningsannual|riskannual|sharesannual|yieldannual|statementquarterly|capitalquarterly|budgetquarterly|reportannual|summaryquarterly|investmentannual)/gi
  );

  return termMatches >= 24 || concatenatedPairHits >= 3;
}

function countMatches(text, pattern) {
  return Array.from(text.matchAll(pattern)).length;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function browserArtifactExtension(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  if (extension) return extension;
  const base = path.basename(filePath).toLowerCase();
  return BROWSER_ARTIFACT_EXTENSIONS.has(base) ? base : "";
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

function scanKnownAiExtensionManifest(relative, text, findings) {
  if (path.basename(relative).toLowerCase() !== "manifest.json") return;

  const normalized = relative.replace(/\\/g, "/").toLowerCase();
  for (const [extensionId, metadata] of AI_EXTENSION_WATCHLIST.entries()) {
    if (!normalized.split("/").includes(extensionId)) continue;

    const version = manifestVersion(text) || versionFromExtensionPath(normalized, extensionId) || "unknown";
    addFinding(
      findings,
      "high",
      "known-vulnerable-ai-browser-extension",
      relative,
      `${metadata.name} is installed in the scanned browser profile and matches Rebora's ${metadata.issue} watchlist.`,
      `extension id ${extensionId}; manifest version ${version}; risk: ${metadata.impact}`,
      "Disable or remove the extension until vendor remediation is independently verified. Review recently visited sites and browser account activity if exposure is suspected."
    );
  }
}

function manifestVersion(text) {
  try {
    const manifest = JSON.parse(text);
    return typeof manifest.version === "string" && manifest.version.trim() ? manifest.version.trim() : "";
  } catch (_error) {
    return "";
  }
}

function versionFromExtensionPath(normalizedRelative, extensionId) {
  const parts = normalizedRelative.split("/");
  const idIndex = parts.indexOf(extensionId);
  if (idIndex < 0 || idIndex + 1 >= parts.length) return "";
  return parts[idIndex + 1] || "";
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
