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

function varint(value) {
  const bytes = [];
  do {
    bytes.push((value & 127) | (value > 127 ? 128 : 0));
    value >>>= 7;
  } while (value);
  return Buffer.from(bytes);
}

function writeBatch(entries) {
  const batchHeader = Buffer.alloc(12);
  batchHeader.writeUInt32LE(entries.length, 8);
  return Buffer.concat([batchHeader, ...entries.flatMap(([key, value]) => {
    const keyBytes = Buffer.from(key);
    const valueBytes = Buffer.from(JSON.stringify(value));
    return [Buffer.from([1]), varint(keyBytes.length), keyBytes,
      varint(valueBytes.length), valueBytes];
  })]);
}

function logRecord(payload, type) {
  const logHeader = Buffer.alloc(7);
  logHeader.writeUInt16LE(payload.length, 4);
  logHeader[6] = type;
  // This scanner inspects markers, not database integrity or CRC values.
  return Buffer.concat([logHeader, payload]);
}

function leveldbPut(key, value) {
  return logRecord(writeBatch([[key, value]]), 1);
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

function fragmentedLog(batch, firstLength) {
  // Fill the first block so the selected key/value byte falls at its edge.
  const parts = [logRecord(Buffer.alloc(32768 - firstLength - 14), 1),
    logRecord(batch.subarray(0, firstLength), 2)];
  for (let offset = firstLength; offset < batch.length; offset += 32761) {
    const end = Math.min(offset + 32761, batch.length);
    parts.push(logRecord(batch.subarray(offset, end), end === batch.length ? 4 : 3));
  }
  return Buffer.concat(parts);
}

const enabledBatch = writeBatch([["lastPermissionModePreference", "skip_all_permission_checks"]]);
for (const split of [15, 40, 42, enabledBatch.length - 2]) {
  assert(scanFile(storagePath, fragmentedLog(enabledBatch, split)).some((f) => f.id === privilegedId));
}
const largeBatch = writeBatch([["skipPermissions", true], ["padding", "x".repeat(70000)]]);
assert(scanFile(storagePath, fragmentedLog(largeBatch, 17)).some((f) => f.id === privilegedId));
assert(!scanFile(storagePath, fragmentedLog(writeBatch([["skipPermissions", false]]), 17))
  .some((f) => f.id === privilegedId));
for (const type of [2, 3, 4]) {
  assert(!scanFile(storagePath, logRecord(enabledBatch, type)).some((f) => f.id === privilegedId));
}
const truncated = fragmentedLog(enabledBatch, 17).subarray(0, -3);
assert(!scanFile(storagePath, truncated).some((f) => f.id === privilegedId));

console.log("49 publisher and permission-setting regression cases passed");
