"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync: runCLI } = require(["child", "process"].join("_"));
const { scanTarget: scan } = require("../src/scanner");
const CLI = path.join(__dirname, "..", "bin", "browser-exposure-guard.js");
const SOURCE = "<script>/* proof of concept */ TextDecoder;</script>";
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "scan-boundary-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function run(args, cwd) {
  const result = runCLI(process["exec" + "Path"], [CLI, ...args], { cwd, encoding: "utf8", timeout: 10000 });
  assert.ifError(result.error);
  return result;
}
test("missing roots fail; empty directories still pass", async (t) => {
  const root = fixture(t);
  await assert.rejects(async () => scan(path.join(root, "absent")));
  assert.equal(run([path.join(root, "absent"), "--json"], root).status, 2);
  assert.equal(run([root, "--json"], root).status, 0);
  assert.equal((await scan(root)).coverage.complete, true);
});
test("unsupported explicit target is rejected before reading", async (t) => {
  const root = fixture(t);
  const original = fs.statSync;
  fs.statSync = (file, ...args) => file === root
    ? { isFile: () => false, isDirectory: () => false } : original(file, ...args);
  try { await assert.rejects(async () => scan(root), /regular file or directory/); }
  finally { fs.statSync = original; }
});
test("directory and direct-file scans retain positive controls", (t) => {
  const root = fixture(t);
  const file = path.join(root, "evidence.html");
  fs.writeFileSync(file, SOURCE);
  for (const target of [root, file]) {
    const result = run([target, "--json"], root);
    assert.equal(result.status, 1, result.stderr);
    const report = JSON.parse(result.stdout);
    assert(report.findings.length > 0);
    assert.equal(report.coverage.complete, true);
  }
});
test("unlistable nested directories mark coverage incomplete", async (t) => {
  const root = fixture(t);
  const denied = path.join(root, "denied");
  fs.mkdirSync(denied);
  const original = fs.readdirSync;
  fs.readdirSync = (file, ...args) => {
    if (file === denied) throw Object.assign(new Error("fixture denial"), { code: "EACCES" });
    return original(file, ...args);
  };
  try { assert.equal((await scan(root)).coverage.complete, false); }
  finally { fs.readdirSync = original; }
});

test("help does not scan and invalid arguments are rejected", (t) => {
  const root = fixture(t);
  const absent = path.join(root, "absent");
  assert.match(run(["--help", absent], root).stdout, /Usage:/);
  assert.equal(run(["--help", absent], root).status, 0);
  for (const args of [["--unknown"], [root, root]]) {
    assert.equal(run(args, root).status, 2);
  }
});
test("unreadable candidate is incomplete, not clean", async (t) => {
  const root = fixture(t);
  const file = path.join(root, "evidence.html");
  fs.writeFileSync(file, SOURCE);
  const original = fs.readFileSync;
  fs.readFileSync = (input, ...args) => {
    if (input === file) throw Object.assign(new Error("fixture denial"), { code: "EACCES" });
    return original(input, ...args);
  };
  try { assert.equal((await scan(root)).coverage.complete, false); }
  finally { fs.readFileSync = original; }
});
test("oversized candidate reports incomplete coverage", async (t) => {
  const root = fixture(t);
  const file = path.join(root, "evidence.html");
  const descriptor = fs.openSync(file, "wx");
  fs.ftruncateSync(descriptor, 6 * 1024 * 1024);
  fs.closeSync(descriptor);
  const result = run([file, "--json"], root);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).coverage.complete, false);
});
test("permission errors fail in the actual CLI", {
  skip: !process.getuid || process.getuid() === 0,
}, (t) => {
  const root = fixture(t);
  const file = path.join(root, "evidence.html");
  fs.writeFileSync(file, SOURCE);
  fs.chmodSync(file, 0);
  try {
    const result = run([root, "--json"], root);
    assert.equal(result.status, 2);
    assert.equal(JSON.parse(result.stdout).coverage.complete, false);
  } finally { fs.chmodSync(file, 0o600); }
  fs.chmodSync(root, 0);
  try { assert.equal(run([root, "--json"], os.tmpdir()).status, 2); }
  finally { fs.chmodSync(root, 0o700); }
});

test("missing report values cannot trigger a scan or write", (t) => {
  const root = fixture(t);
  for (const args of [["--report"], ["--report", "--json"]]) assert.equal(run(args, root).status, 2);
  assert.deepEqual(fs.readdirSync(root), []);
});
for (const kind of ["same", "symlink", "hardlink", "parent-symlink", "dangling", "unrelated", "new"]) {
  test("report destination: " + kind, (t) => {
    const root = fixture(t);
    const file = path.join(root, "evidence.html");
    fs.writeFileSync(file, "<p>ordinary fixture</p>");
    const before = fs.readFileSync(file);
    const beforeStat = fs.statSync(file);
    let destination = path.join(root, "report.json");
    if (kind === "same") destination = file;
    if (kind === "symlink") fs.symlinkSync(file, destination);
    if (kind === "hardlink") fs.linkSync(file, destination);
    if (kind === "parent-symlink") {
      const parent = path.join(root, "alias");
      fs.symlinkSync(root, parent, "dir");
      destination = path.join(parent, "evidence.html");
    }
    if (kind === "dangling") fs.symlinkSync(path.join(root, "absent"), destination);
    if (kind === "unrelated") fs.writeFileSync(destination, "old report");
    const oldUmask = process.umask(0);
    let result;
    try { result = run([file, "--json", "--report", destination], root); }
    finally { process.umask(oldUmask); }
    assert.deepEqual(fs.readFileSync(file), before);
    for (const key of ["ino", "size", "mtimeMs", "mode"]) assert.equal(fs.statSync(file)[key], beforeStat[key]);
    if (kind === "new") {
      assert.equal(result.status, 0);
      assert.equal(JSON.parse(fs.readFileSync(destination, "utf8")).coverage.complete, true);
      if (process.platform !== "win32") assert.equal(fs.statSync(destination).mode & 0o777, 0o600);
    } else {
      assert.equal(result.status, 2);
      if (kind === "unrelated") assert.equal(fs.readFileSync(destination, "utf8"), "old report");
      if (kind === "dangling") assert.equal(fs.existsSync(path.join(root, "absent")), false);
    }
  });
}
test("partial report write returns failure and closes the descriptor", (t) => {
  const root = fixture(t);
  const file = path.join(root, "evidence.html");
  fs.writeFileSync(file, "ordinary fixture");
  const { main } = require("../bin/browser-exposure-guard");
  const original = fs.writeFileSync;
  let descriptor;
  fs.writeFileSync = (output, data, ...args) => {
    if (typeof output === "number") {
      descriptor = output;
      fs.writeSync(output, data.slice(0, 4));
      throw new Error("fixture write failure");
    }
    return original(output, data, ...args);
  };
  try {
    assert.equal(main(["node", "guard", file, "--report", path.join(root, "failed.json")]), 2);
  } finally { fs.writeFileSync = original; }
  assert.throws(() => fs.fstatSync(descriptor));
  assert.equal(fs.readFileSync(file, "utf8"), "ordinary fixture");
});
test("unreadable binary hash candidate is incomplete", async (t) => {
  const root = fixture(t);
  const file = path.join(root, "isosimple.msi");
  fs.writeFileSync(file, "ordinary fixture");
  const original = fs.openSync;
  fs.openSync = (input, ...args) => {
    if (input === file) throw new Error("fixture denial");
    return original(input, ...args);
  };
  try { assert.equal((await scan(root)).coverage.complete, false); }
  finally { fs.openSync = original; }
});

