#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { scanTarget } = require("../src/scanner");

function main(argv) {
  try {
    const args = argv.slice(2);
    let json = false;
    let help = false;
    let reportPath;
    let target;
    for (let i = 0; i < args.length; i += 1) {
      const arg = args[i];
      if (arg === "--json") json = true;
      else if (arg === "--help" || arg === "-h") help = true;
      else if (arg === "--report") {
        reportPath = args[++i];
        if (!reportPath || reportPath.startsWith("-")) throw new Error("--report requires a file path");
      } else if (arg.startsWith("-")) throw new Error(`Unknown argument: ${arg}`);
      else if (target !== undefined) throw new Error("Only one target path may be specified");
      else target = arg;
    }
    if (help) {
      process.stdout.write("Usage: browser-exposure-guard [target] [--json] [--report NEW_FILE]\n" +
        "Read-only scan. Reports create new private files; existing paths are refused.\n" +
        "Exit codes: 0 no high findings; 1 high findings; 2 usage/runtime error or incomplete scan.\n");
      return 0;
    }
    const result = scanTarget(target || ".");
    const output = json ? JSON.stringify(result, null, 2) + "\n" : renderText(result);
    if (reportPath) {
      const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0);
      const descriptor = fs.openSync(path.resolve(reportPath), flags, 0o600);
      try { fs.writeFileSync(descriptor, output, "utf8"); }
      finally { fs.closeSync(descriptor); }
    } else process.stdout.write(output);
    if (!result.coverage.complete) return 2;
    return result.summary.high > 0 ? 1 : 0;
  } catch (error) {
    process.stderr.write(`Error: ${error.message}\n`);
    return 2;
  }
}

function renderText(result) {
  const lines = [
    "Browser Exposure Guard Report",
    `Target: ${result.target}`,
    `Files scanned: ${result.summary.filesScanned}`,
    `Findings: ${result.findings.length}`,
    "",
  ];

  if (!result.coverage.complete) {
    lines.push("INCOMPLETE: some inputs could not be inspected; this is not a passed scan.");
    for (const error of result.coverage.errors) lines.push(`  ${error.reason}: ${error.path}`);
    lines.push("");
  }

  if (result.findings.length === 0) {
    lines.push("No browser exposure findings matched this rule set. This is not an all-clear.");
    return `${lines.join("\n")}\n`;
  }

  for (const finding of result.findings) {
    lines.push(`[${finding.severity}] ${finding.id}`);
    lines.push(`  Path: ${finding.path}`);
    lines.push(`  Reason: ${finding.reason}`);
    lines.push(`  Evidence: ${finding.evidence}`);
    lines.push(`  Guidance: ${finding.guidance}`);
    lines.push("");
  }
  return lines.join("\n");
}

if (require.main === module) {
  process.exitCode = main(process.argv);
}

module.exports = { main, renderText };
