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
- Installed Chrome/Chromium/Edge extension profile manifests matching known
  high-risk AI side-panel extension IDs from the Rebora Spyder/MaXSS research:
  SiderAI (`difoiogjjojoaoomphldepapgpbgkhkb`) and MaxAI
  (`mhnlakgilnojmhinhkckjpncpbhabphi`).
- Microsoft Copilot / AI-assistant URLs in local browser/client artifacts where
  a `q=` query parameter combines private-context requests with external
  exfiltration terms, matching Reprompt-style one-click data-theft behavior.
- Huntress-reported fake “Plus 5.6” Custom GPT IDs and Google Sites ClickFix
  lures in saved HTML/MHTML/HAR artifacts. Exported Windows text, JSON, and XML
  evidence is checked for the reported PowerShell staging and MSI/persistence
  combinations. Exact SHA-256 matches on five reported malicious MSI/DLL files
  are checked when those files appear in the target folder. The legitimate
  signed Canon and Stardock host executables are not flagged. A saved URL is a
  visit lead, not proof of execution.
- Official Anthropic Claude for Chrome / Claude in Chrome in local
  Chrome/Chromium/Edge profiles (published extension id
  `fcoeoabgfenejglbffodgkkbkcdhcgfn`, or manifest name plus Anthropic
  publisher), including local “Act without asking” /
  `skip_all_permission_checks` settings when those strings appear in profile
  Preferences or extension-settings files. High/exposed only when Preferences
  show the extension enabled (`state: 1`). Installed-but-disabled leftovers
  are Medium/advisory. This is a local alert for the public LayerX ClaudeBleed
  / Manifold Security synthetic-click research, not original vulnerability
  research.
- Published fake-Claude Chrome Web Store impersonation extension ids/names and
  local lure artifacts matching Huntress FakeAgent or Sophos fake-Claude
  install indicators. No invented hashes or ids.

## Run

```powershell
node .\bin\browser-exposure-guard.js C:\path\to\scan
```

JSON output:

```powershell
node .\bin\browser-exposure-guard.js --json C:\path\to\scan
```

For the Huntress campaign, scan a folder of **saved browser pages/HAR files or
exported Windows process, task, and registry evidence**. The scanner does not
read live browser history, Windows Event Logs, the registry, or scheduled tasks
by itself. Name exported Windows evidence files with `windows`, `event`,
`sysmon`, `process`, `powershell`, `task`, `registry`, `autoruns`, `triage`, or
`export` so the campaign check can distinguish them from research notes. It
does not execute a pasted command or inspect malware behavior; matching candidate
files are only hashed.

## Interpreting Findings

High browser-artifact findings mean “do not open this file in a normal browser
profile.” Review with a safe text viewer, disposable VM, or isolated analysis
environment. High Windows evidence or file-hash findings call for incident
triage; they do not by themselves establish that the final RAT ran.
For installed extension findings, high means “disable or remove until vendor
remediation is independently verified.”
For Claude for Chrome findings, high means you may be exposed: the official
extension is present **and enabled**, Act without asking appears to be on
while it is enabled, a published fake-Claude impersonation extension is
installed, or a local file matches a published install lure. Follow the
finding’s guidance links. This tool does not claim the host is clean.

Medium findings are advisory or posture reminders. They usually mean “check
browser patch state” or “avoid enabling experimental browser flags around
untrusted repros.” A Medium Claude finding means the official extension is
still on disk but turned off, or this scan could not confirm it is enabled.
Leave it disabled until Anthropic ships an independently verified
isTrusted-style fix. Same credited writeups as the High finding.

## Sources

See [docs/sources.md](docs/sources.md).
