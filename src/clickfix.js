"use strict";

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// Huntress, 2026-09-30. These are campaign-specific leads, not proof that a
// browser visit executed the payload. Keep the published IDs exact.
const GPT_IDS = [
  "g-6ab595ad6554819181b686d4876efb80-plus-5-6",
  "g-6ab6ba039440819185ed491740b11cf8-plus-5-6",
];
const BROWSER_EXTENSIONS = new Set([".har", ".htm", ".html", ".mhtml"]);
const WINDOWS_EVIDENCE_EXTENSIONS = new Set([".json", ".log", ".txt", ".xml"]);
const SOURCE = "https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat";
const MAX_BINARY_BYTES = 100 * 1024 * 1024;
const MALICIOUS_FILE_HASHES = new Map([
  ["isosimple.msi", "6761aad48a3f987238994d92bca97e4b8550e0150607bd67b47b1b6366a371fc"],
  ["ceiinfolog.dll", "e58831766e8d4313db9f8b85f90c3a840aa0d84cfeac285beefa40e39ad0d1fb"],
  ["rdcore.dll", "b77575413c0f97eaf31e4a44c884c1ecdc0049ec89916ceb0bf3aaaedc0442fe"],
  ["iconedit2turb.msi", "91a22cf3154944897cbcaffc7d20d4596e972d280ee134197d41d8d8eefb0fe2"],
  ["deelevator64.dll", "0457414c4504b70115798eee9c8384a8bf9e793461ffb2e0661a6dcc6ed4809f"],
]);

function isClickfixCandidateBinary(filePath) {
  return MALICIOUS_FILE_HASHES.has(path.basename(filePath).toLowerCase());
}

function scanClickfixBinary(filePath, relative, findings) {
  const name = path.basename(filePath).toLowerCase();
  const expected = MALICIOUS_FILE_HASHES.get(name);
  if (!expected) return;
  const actual = hashFile(filePath);
  if (actual !== expected) return;
  add(findings, "high", "huntress-clickfix-malicious-file-hash", relative,
    "File SHA-256 matches a malicious installer or modified DLL reported by Huntress.",
    `${name} SHA-256 ${expected}`,
    `Preserve the file and surrounding process, installation, task, and Run-key evidence. Do not execute it. ${SOURCE}`);
}

function hashFile(filePath) {
  let handle;
  try {
    const size = fs.statSync(filePath).size;
    if (size > MAX_BINARY_BYTES) return null;
    handle = fs.openSync(filePath, "r");
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let read;
    while ((read = fs.readSync(handle, buffer, 0, buffer.length, null)) > 0) {
      hash.update(buffer.subarray(0, read));
    }
    return hash.digest("hex");
  } catch (_error) {
    return null;
  } finally {
    if (handle !== undefined) fs.closeSync(handle);
  }
}

function scanClickfixArtifact(relative, text, findings) {
  const extension = path.extname(relative).toLowerCase();
  if (BROWSER_EXTENSIONS.has(extension)) scanBrowserEvidence(relative, text, findings);
  if (WINDOWS_EVIDENCE_EXTENSIONS.has(extension) && isWindowsEvidencePath(relative)) {
    scanWindowsEvidence(relative, text, findings);
  }
}

function scanBrowserEvidence(relative, text, findings) {
  if (/<title[^>]*>[^<]*Attackers Abuse ChatGPT Custom GPTs to Deliver RAT/i.test(text)) return;
  const normalized = decodeBrowserText(text).toLowerCase();
  const knownGpt = GPT_IDS.some((id) => normalized.includes(id));
  const knownSite = /sites(?:\[\.\]|\.)google(?:\[\.\]|\.)com\/view\/antibot172881/i.test(normalized);
  const fakeAvailability = /service availability notice|continue using the service through our backup domain/i.test(normalized);
  const clickfixLure = /(?:cloudflare|captcha|verification)[\s\S]{0,700}(?:powershell|paste|win\s*\+\s*r|windows key)/i.test(normalized);

  if (knownGpt && (knownSite || fakeAvailability)) {
    add(findings, "medium", "huntress-custom-gpt-clickfix-lure", relative,
      "Saved browser artifact matches a reported fake Custom GPT and its redirect lure.",
      "exact reported GPT ID plus backup-site or availability lure",
      `Do not follow the backup link or run a verification command. Preserve the artifact and review browser and Windows execution evidence. A visit alone does not prove infection. ${SOURCE}`);
  } else if (knownGpt) {
    add(findings, "medium", "huntress-custom-gpt-visit-lead", relative,
      "Saved browser artifact references a reported fake Custom GPT.",
      "exact reported GPT ID",
      `Review the visit and any redirect or command execution. A URL reference alone does not prove interaction or infection. ${SOURCE}`);
  }

  if (knownSite && clickfixLure && !knownGpt) {
    add(findings, "medium", "huntress-google-sites-clickfix-lure", relative,
      "Saved browser artifact combines the reported Google Sites page with a fake verification command lure.",
      "exact reported Google Sites path plus verification and command cues",
      `Do not run the offered command. Preserve the artifact and correlate with Windows process and installer evidence. ${SOURCE}`);
  }
}

function isWindowsEvidencePath(relative) {
  return /(?:^|\/)[^/]*(?:windows|event|sysmon|process|powershell|task|registry|autoruns|triage|export)[^/]*\.(?:json|log|txt|xml)$/i.test(relative);
}

function scanWindowsEvidence(relative, text, findings) {
  const normalized = decodeBrowserText(text);
  const records = normalized.split(/\r?\n/);
  const hasScriptStage = records.some((record) =>
    /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i.test(record)
    && /\b(?:1614733393|96(?:\[\.\]|\.)62(?:\[\.\]|\.)224(?:\[\.\]|\.)81)\b/i.test(record)
    && /\b(?:irm|Invoke-RestMethod|Invoke-WebRequest|iwr)\b/i.test(record)
    && /(?:\$env:temp|%temp%|\\temp\\)[^\r\n]{0,100}\.ps1/i.test(record)
  );
  const hasInstallerPersistence = records.some((record) =>
    /\bmsiexec(?:\.exe)?\b[^\r\n]{0,240}(?:ISOSimple\.msi|IconEdit2Turb\.msi|\.msi[^\r\n]{0,100}\/qn)/i.test(record)
    && /Canon Configuration Reader|Advanced Printer Configuration Reader/i.test(record)
  );

  if (hasScriptStage) {
    add(findings, "high", "huntress-clickfix-powershell-stage", relative,
      "Windows evidence matches the reported ClickFix PowerShell staging pattern.",
      "PowerShell fetch from reported host into a temporary PS1",
      `Preserve the process command line, parent process, file timestamps, and related installer evidence. This is an execution lead, not proof of the final RAT. ${SOURCE}`);
  }
  if (hasInstallerPersistence) {
    add(findings, "high", "huntress-clickfix-installer-persistence", relative,
      "Windows evidence combines the reported MSI install and persistence names.",
      "reported MSI installation plus persistence/product marker",
      `Preserve MSI, scheduled-task, Run-key, and DLL evidence; verify hashes against Huntress before concluding infection. ${SOURCE}`);
  }
}

function decodeBrowserText(text) {
  // HAR and saved-page exports often escape slashes or percent-encode URLs.
  const unescaped = text.replace(/\\\//g, "/")
    .replace(/%2f/gi, "/").replace(/%3a/gi, ":").replace(/%2e/gi, ".");
  try {
    return decodeURIComponent(unescaped);
  } catch (_error) {
    return unescaped;
  }
}

function add(findings, severity, id, filePath, reason, evidence, guidance) {
  findings.push({ severity, id, path: filePath, reason, evidence, guidance });
}

module.exports = { scanClickfixArtifact, scanClickfixBinary, isClickfixCandidateBinary, hashFile };
