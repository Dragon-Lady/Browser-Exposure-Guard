# Browser Exposure Guard

Read-only browser/client exposure scanner for unsafe local artifacts and
browser advisory watch signals.

This project is for the browser/client lane: Chrome/Chromium/WebView/Firefox/
Safari-style exposure notes, local repro artifacts, suspicious HTML/SVG/MHTML/
HAR files, experimental flag reminders, and “do not open this in your daily
browser” guidance.

## Safety

- No network calls.
- No browser launching.
- No PoC execution.
- No exploit testing.
- No package installs.
- No cleanup, deletion, quarantine, or credential rotation.
- No claim that a host or browser profile is clean.
- No telemetry, maintainer alerting, or remote reporting.

The scanner reads local text-like files and reports review signals to the
person running the tool.

## What It Checks

- Local browser-rendered artifacts such as `.html`, `.svg`, `.mhtml`, and `.har`
  files that combine script, browser attack-surface APIs, and exploit/repro
  language.
- Chromium advisory notes mentioning signals such as `CVE-2026-3921`,
  `TextEncoding`, `Canvas2D`, `beginLayer`, and related public Chromium issue
  IDs.
- Experimental flag notes such as `chrome://flags`,
  `--enable-blink-features`, or
  `--enable-experimental-web-platform-features`.
- Phishing attachment patterns in local `.html` and `.svg` artifacts,
  including SVG content disguised as HTML, invisible SVG business-dashboard
  camouflage, business-term encoded payload attributes, and dynamic JavaScript
  execution chains.

## Run

```powershell
node .\bin\browser-exposure-guard.js C:\path\to\scan
```

JSON output:

```powershell
node .\bin\browser-exposure-guard.js --json C:\path\to\scan
```

## Interpreting Findings

High findings mean “do not open this file in a normal browser profile.” Review
with a safe text viewer, disposable VM, or isolated analysis environment.

Medium findings are advisory or posture reminders. They usually mean “check
browser patch state” or “avoid enabling experimental browser flags around
untrusted repros.”

## Sources

See [docs/sources.md](docs/sources.md).
