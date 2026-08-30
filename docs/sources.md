# Sources

- Chromium issue `484946544`: https://issues.chromium.org/issues/484946544
- Chromium issue `485677960`: https://issues.chromium.org/issues/485677960
- NVD CVE-2026-3921: https://nvd.nist.gov/vuln/detail/CVE-2026-3921
- Chrome Releases, Long Term Support Channel Update for ChromeOS:
  https://chromereleases.googleblog.com/2026/05/long-term-support-channel-update-for.html
- Sublime Security, Kratos phishing attack hidden in business term encoding and
  sophisticated obfuscation:
  https://sublime.security/blog/kratos-phishing-attack-hidden-in-business-term-encoding-and-sophisticated-obfuscation/
- Rebora, MaXSS & Spyder: How two Chrome extensions allow websites to
  compromise over 10 million browsers:
  https://rebora.io/blog/spyder-and-maxss-chrome-extension-vulnerabilities-put-millions-at-risk
- Rebora, MaXSS: Chrome Extension MaxAI Vulnerable to UXSS Puts 1,000,000
  Users at Risk:
  https://rebora.io/blog/maxss-vulnerability-in-chrome-extension-leads-to-uxss
- Rebora, Spyder: Chrome Extension SiderAI Vulnerable to UXSG Puts 10,000,000
  Users at Risk:
  https://rebora.io/blog/spyder-vulnerability-in-chrome-extension-leads-to-uxsg
- BleepingComputer, Microsoft 365 Copilot Reprompt / one-click data-theft
  coverage:
  https://www.bleepingcomputer.com/news/security/new-attack-turned-microsoft-365-copilot-into-1-click-data-theft-tool/
- Windows Central summary of Varonis Reprompt details:
  https://www.windowscentral.com/artificial-intelligence/microsoft-copilot/copilot-ai-reprompt-exploit-detailed-2026

## Claude for Chrome / fake-Claude install (public research, not this repo)

This repo only implements local detection and alerting. It does not claim
original vulnerability research. CoinBureau's public post
https://x.com/coinbureau/status/2093999668464427227 is credited as the
signal that surfaced the Manifold writeup for operators using this tool;
wording below is from the researcher blogs, not that post.

### Official Claude in Chrome extension id

- Chrome Web Store listing “Claude” published by Anthropic:
  https://chromewebstore.google.com/detail/claude/fcoeoabgfenejglbffodgkkbkcdhcgfn
- Anthropic, Use Claude Code with Chrome, documents that same listing:
  https://code.claude.com/docs/en/chrome
- Anthropic Help Center, Claude in Chrome permissions guide:
  https://support.claude.com/en/articles/12902446-claude-in-chrome-permissions-guide

If a profile has no id in the path, the scanner also matches a `manifest.json`
whose name is `Claude` or `Claude in Chrome` and whose author/homepage is
Anthropic. The id is not invented.

### LayerX — ClaudeBleed (April–May 2026)

- Aviad Gispan / LayerX, “ClaudeBleed: A Flaw In Claude’s Browser Extension
  Allows Any Extension to Hijack It,” reported 27 April 2026, public writeup
  around 5–8 May 2026. The live LayerX URL
  https://layerxsecurity.com/blog/a-flaw-in-claudes-browser-extension-allows-any-extension-to-hijack-it/
  returned 404 at implementation time. Archived original:
  https://web.archive.org/web/20260508132614/https://layerxsecurity.com/blog/a-flaw-in-claudes-browser-extension-allows-any-extension-to-hijack-it/

LayerX described origin-based trust on `claude.ai` via
`externally_connectable`, a partial Anthropic change in v1.0.70 (6 May 2026),
and residual risk when “Act without asking” / privileged mode is on.

### Manifold Security — residual synthetic-click / skipPermissions (May–July 2026)

- Ax Sharma / Manifold Security, “ClaudeBleed Reopened: Browser Extensions Can
  Still Push Claude for Chrome to Read Your Gmail,” 14 July 2026:
  https://www.manifold.security/blog/claude-for-chrome-extension-bypass

Manifold reported that the click handler still does not check
`event.isTrusted`, so any co-installed extension with a content script on
`claude.ai` can forge an approval click. They verified this still in v1.0.80
(7 July 2026). Severity is higher if the user enabled “Act without asking.”
They also described a side-panel `skipPermissions=true` initialization that
sets `skip_all_permission_checks`. Anthropic narrowed outside callers to a
fixed task set after ClaudeBleed; Manifold’s position is that the trust
boundary did not move.

This scanner does **not** include a reproduction, forged-click sample, or
side-panel URL construction. It only looks at local manifests, Preferences,
and published setting-key strings.

### Coverage that shares the Manifold findings

- Cloud Security Alliance research note, “Claude for Chrome: Synthetic Click
  Flaw Lets Extensions Hijack AI Actions,” 18 July 2026:
  https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/07/CSA_research_note_claude_chrome_extension_click_simulation_flaw_20260718-csa-styled.pdf
- Pieter Arntz / Malwarebytes, “Claude for Chrome flaw could let rogue
  extensions access your Gmail,” 15 July 2026:
  https://www.malwarebytes.com/blog/news/2026/07/claude-for-chrome-flaw-could-let-rogue-extensions-access-your-gmail
- Suriq, “A rogue extension can still make Claude in Chrome read your Gmail”:
  https://suriq.io/blog/claude-chrome-extension-forged-click-gmail
- CSO Online, “New bugs in Claude for Chrome allow extensions to abuse AI
  privileges,” 15 July 2026:
  https://www.csoonline.com/article/4197325/new-bugs-in-claude-for-chrome-allow-extensions-to-abuse-ai-privileges.html
- The Hacker News, “Researchers Say Claude for Chrome Flaw Lets Rogue
  Extensions Trigger Gmail Reads,” July 2026 (independent unpack of v1.0.80):
  https://thehackernews.com/2026/07/claude-for-chrome-flaw-lets-other.html
- BleepingComputer, “Claude Chrome extension flaw lets malicious extensions
  trigger AI actions”:
  https://www.bleepingcomputer.com/news/security/claude-chrome-extension-flaw-lets-malicious-extensions-trigger-ai-actions/

Malwarebytes’ user steps are the ones this alert repeats: turn off Act
without asking, review/remove untrusted extensions that can run on
`claude.ai`, and consider disabling Claude for Chrome until a real
`isTrusted` fix ships.

### Local “Act without asking” settings

Published local key names (not invented): `skip_all_permission_checks`,
`skipPermissions=true`, `lastPermissionModePreference`,
`CLAUDE_CHROME_PERMISSION_MODE`, and the UI strings “Act without asking” /
“Skip all approvals,” as discussed by Manifold and in public Claude Code
extension-storage notes. Chrome stores these in profile Preferences or
LevelDB under `Local Extension Settings/<official-id>/`. This scanner is
text-only and does not open LevelDB or launch a browser, so it only fires
when those strings are visible in readable profile files (including `.log`
files under that path).

### Huntress FakeAgent (July 2026)

- Huntress, “Inside FakeAgent: How a Claude Desktop Malvertising Campaign Hit
  29 Organizations with SectopRAT”:
  https://www.huntress.com/blog/fakeagent-claude-desktop-malvertising-ends-in-dotnet-rat

This is a desktop-installer malvertising chain (malicious public Claude
Artifact → redirect domains → `ClaudeDesktop.exe` / SectopRAT), not a
Chrome-extension click bug. It still fits this scanner as **local text
artifact matching** of Huntress-published IOCs (artifact UUID, redirect
hosts, malicious SHA-256s). The scanner does not read PE/DLL binaries, so
on-disk installers are not hashed here.

Huntress marked SHA-256
`f8acb8f5cf88b77a4c27d7fd6856aa299bb178e85f9963c2fbd447d818da3ed0`
(`ClaudeDesktop.exe` / `DockerDesktop.exe`) and
`fd826215add30c1319eefa291b6eaf8ddfa7720cfe816c49aef6fe8a88de7939`
(`SSLConf.exe`) as **benign** signed hosts. Those hashes are not alerted.

Huntress published no fake official-Claude-for-Chrome extension id.

### Sophos fake-Claude / AI-brand impersonation (August 2026)

- Colin Cowie, Rafe Pilling, Ryan Westman / Sophos, “Fake AI, real malware:
  Attackers impersonating AI brands”:
  https://www.sophos.com/en-us/blog/fake-ai-real-malware-attackers-impersonating-ai-brands
- SophosLabs IOC table for that article:
  https://github.com/sophoslabs/IoCs/blob/master/AI_2025-2026_IOCs.csv
- Cybersecuritynews recap of the same Sophos research:
  https://cybersecuritynews.com/hackers-are-turning-claude-chatgpt/

Sophos described fake Claude, ChatGPT, and Copilot pages plus AI-themed
Chrome Web Store extensions, including one marketed as “AI Sidebar with
DeepSeek, ChatGPT, Claude.” The Sophos blog did not print that listing’s
extension id. Matching ids and sample hashes were published by:

- OX Security, “900K Users Compromised: Chrome Extensions Steal ChatGPT and
  DeepSeek Conversations”:
  https://www.ox.security/blog/malicious-chrome-extensions-steal-chatgpt-deepseek-conversations/
  (`fnmihdojmnkclgjpcoonokmkhjpjechg`, `inhcgfpbfdjbjogdfjbclgolkmhnooop`)
- Microsoft Defender Security Research, “Malicious AI Assistant Extensions
  Harvest LLM Chat Histories,” 5 March 2026:
  https://www.microsoft.com/en-us/security/blog/2026/03/05/malicious-ai-assistant-extensions-harvest-llm-chat-histories/

SophosLabs later listed those same two SHA-256 values as “DeepSeek/AI
extension campaign sample.” No ids were invented here.

Sophos InstallFix / fake-Claude host and filename IOCs used for local
artifact matching are only the published ones (for example
`download-version.1-9-18.com`, `claude.msixbundle`, `Claude Setup.zip`,
`claude-setup.com`, `code.verification-claude-cdn.beer`). Generic names such
as `claude.exe` are not used as standalone alerts.

Sources are retained for defensive patch posture and local artifact review.
This project intentionally avoids exploit reproduction steps.
