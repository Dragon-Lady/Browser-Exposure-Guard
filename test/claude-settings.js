"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scanTarget } = require("../src/scanner");

const officialId = "fcoeoabgfenejglbffodgkkbkcdhcgfn";
const privilegedId = "claude-for-chrome-act-without-asking";

function scanFile(relative, content) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "browser-settings-"));
  try {
    const target = path.join(root, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, typeof content === "string" || Buffer.isBuffer(content) ? content : JSON.stringify(content));
    return scanTarget(root).findings;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

for (const homepage of [
  "https://claude.ai.attacker.example",
  "https://anthropic.com.attacker.example",
  "https://attacker.example/claude.ai",
  "https://claude.ai@attacker.example",
  "not-a-url",
  "file://claude.ai/settings",
]) {
  const findings = scanFile("unpacked/manifest.json", {
    name: "Claude", author: "Anthropic", homepage_url: homepage,
  });
  assert(!findings.some((f) => f.id.startsWith("claude-for-chrome-")), homepage);
}
for (const homepage of ["https://claude.ai", "https://www.anthropic.com", "https://CLAUDE.AI./"]) {
  assert(scanFile("unpacked/manifest.json", {
    name: "Claude", homepage_url: homepage,
  }).some((f) => f.id === "claude-for-chrome-on-disk-enablement-unknown"), homepage);
}

for (const basename of ["Preferences", "Secure Preferences"]) {
  for (const includeOfficial of [false, true]) {
    const settings = {
      unrelated: { state: 1, skipPermissions: true, label: "Act without asking" },
    };
    if (includeOfficial) settings[officialId] = { state: 1, skip_all_permission_checks: false };
    assert(!scanFile(`profile/${basename}`, { extensions: { settings } })
      .some((f) => f.id === privilegedId));
  }
  const settings = { [officialId]: { state: 1, permissionMode: "skip_all_permission_checks" } };
  assert(scanFile(`profile/${basename}`, { extensions: { settings } })
    .some((f) => f.id === privilegedId && f.severity === "high"));
}

const storagePath = `profile/Local Extension Settings/${officialId}/000003.log`;
for (const disabled of [
  { skip_all_permission_checks: false },
  { skipPermissions: false },
  { skipPermissions: "false" },
  { label: "Act without asking", description: "skip_all_permission_checks" },
  { permissionMode: "ask" },
  "skip_all_permission_checks=false\nAct without asking",
  "skipPermissions=false",
]) {
  assert(!scanFile(storagePath, disabled).some((f) => f.id === privilegedId));
}
for (const enabled of [
  { skip_all_permission_checks: true },
  { skipPermissions: true },
  { skipPermissions: "true" },
  { lastPermissionModePreference: "skip_all_permission_checks" },
  { permissionMode: "skip_all_permission_checks" },
  "lastPermissionModePreference\nskip_all_permission_checks",
  "CLAUDE_CHROME_PERMISSION_MODE=skip_all_permission_checks",
  "skipPermissions=true",
]) {
  assert(scanFile(storagePath, enabled).some((f) => f.id === privilegedId));
}

function leveldbPut(key, value) {
  const keyBytes = Buffer.from(key);
  const valueBytes = Buffer.from(JSON.stringify(value));
  const batchHeader = Buffer.alloc(12);
  batchHeader.writeUInt32LE(1, 8);
  const batch = Buffer.concat([
    batchHeader, Buffer.from([1, keyBytes.length]), keyBytes,
    Buffer.from([valueBytes.length]), valueBytes,
  ]);
  const logHeader = Buffer.alloc(7);
  logHeader.writeUInt16LE(batch.length, 4);
  logHeader[6] = 1;
  // This scanner inspects markers, not database integrity or CRC values.
  return Buffer.concat([logHeader, batch]);
}

for (const [key, value] of [
  ["skipPermissions", true],
  ["skipPermissions", "true"],
  ["skip_all_permission_checks", true],
  ["lastPermissionModePreference", "skip_all_permission_checks"],
  ["permissionMode", "skip_all_permission_checks"],
]) {
  assert(scanFile(storagePath, leveldbPut(key, value)).some((f) => f.id === privilegedId));
}
for (const [key, value] of [
  ["skipPermissions", false],
  ["skip_all_permission_checks", false],
  ["unrelated", "skip_all_permission_checks"],
  ["skipPermissions", "true-ish"],
]) {
  assert(!scanFile(storagePath, leveldbPut(key, value)).some((f) => f.id === privilegedId));
}

console.log("39 publisher and permission-setting regression cases passed");
