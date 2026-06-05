#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { scanTarget } = require("../src/scanner");

function main(argv) {
  const args = argv.slice(2);
  const json = args.includes("--json");
  const reportIndex = args.indexOf("--report");
  const reportPath = reportIndex >= 0 ? args[reportIndex + 1] : "";
  const target = args.find((arg, index) => {
    if (arg === "--json" || arg === "--report") return false;
    if (index > 0 && args[index - 1] === "--report") return false;
    return !arg.startsWith("--");
  }) || ".";

  const result = scanTarget(target);
  const output = json ? JSON.stringify(result, null, 2) : renderText(result);

  if (reportPath) {
    fs.writeFileSync(path.resolve(reportPath), output, "utf8");
  } else {
    process.stdout.write(output);
  }

  return result.summary.high > 0 ? 1 : 0;
}

function renderText(result) {
  const lines = [
    "Browser Exposure Guard Report",
    `Target: ${result.target}`,
    `Files scanned: ${result.summary.filesScanned}`,
    `Findings: ${result.findings.length}`,
    "",
  ];

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
