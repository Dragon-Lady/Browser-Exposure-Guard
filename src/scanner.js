"use strict";

const fs = require("fs");
const path = require("path");

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "coverage", ".next"]);
const TEXT_EXTENSIONS = new Set([
  "",
  ".css",
  ".har",
  ".htm",
  ".html",
  ".json",
  ".log",
  ".md",
  ".mhtml",
  ".svg",
  ".txt",
  ".xml",
]);

const BROWSER_ARTIFACT_EXTENSIONS = new Set([".html", ".htm", ".svg", ".mhtml", ".har"]);

const BUSINESS_TERM_STEGO_TERMS = [
  "quarterly",
  "annual",
  "monthly",
  "revenue",
  "profit",
  "growth",
  "market",
  "sales",
  "customer",
  "analytics",
  "metrics",
  "forecast",
  "performance",
  "strategy",
  "operations",
  "budget",
  "finance",
  "report",
  "dashboard",
  "insight",
  "data",
  "trends",
  "analysis",
  "business",
  "overview",
  "summary",
  "review",
  "target",
  "goal",
  "objective",
  "kpi",
  "roi",
  "segment",
  "portfolio",
  "investment",
  "return",
  "cost",
  "expense",
  "value",
  "margin",
  "earnings",
  "income",
  "assets",
  "equity",
  "debt",
  "cash",
  "flow",
  "capital",
  "shares",
  "stock",
  "dividend",
  "yield",
  "risk",
  "beta",
  "alpha",
  "ratio",
  "balance",
  "sheet",
  "statement",
  "audit",
  "tax",
  "fiscal",
  "quarter",
  "year",
];

const CHROMIUM_ADVISORY_TERMS = [
  "CVE-2026-3921",
  "TextEncoding",
  "use-after-free",
  "Canvas2D",
  "beginLayer",
  "issues.chromium.org/issues/484946544",
  "issues.chromium.org/issues/485677960",
];

const AI_EXTENSION_WATCHLIST = new Map([
  [
    "difoiogjjojoaoomphldepapgpbgkhkb",
    {
      name: "SiderAI / Sider: Chat with all AI",
      issue: "Spyder UXSG exposure",
      impact: "arbitrary website-driven clicking and typing through extension-controlled embedded pages",
    },
  ],
  [
    "mhnlakgilnojmhinhkckjpncpbhabphi",
    {
      name: "MaxAI / MaxAI.me",
      issue: "MaXSS UXSS exposure",
      impact: "arbitrary website access to extension-level browser permissions",
    },
  ],
]);

const COPILOT_REPROMPT_HOSTS = [
  "copilot.microsoft.com",
  "m365.cloud.microsoft/chat",
  "microsoft365.com/chat",
];

// Official Anthropic "Claude" / "Claude in Chrome" listing. ID taken from the
// Chrome Web Store URL and Anthropic's Claude Code Chrome docs, not guessed.
const OFFICIAL_CLAUDE_CHROME_EXTENSION_ID = "fcoeoabgfenejglbffodgkkbkcdhcgfn";

const CLAUDE_FOR_CHROME_FIX_GUIDANCE = [
  "You may be exposed.",
  "Audit and remove untrusted extensions that can run scripts on claude.ai.",
  "Turn off Act without asking / Skip all approvals.",
  "Consider disabling Claude for Chrome until Anthropic ships an independently verified isTrusted check.",
  "Read the public writeups: Manifold Security https://www.manifold.security/blog/claude-for-chrome-extension-bypass ; Malwarebytes https://www.malwarebytes.com/blog/news/2026/07/claude-for-chrome-flaw-could-let-rogue-extensions-access-your-gmail ; LayerX ClaudeBleed (archived original) https://web.archive.org/web/20260508132614/https://layerxsecurity.com/blog/a-flaw-in-claudes-browser-extension-allows-any-extension-to-hijack-it/ ; CSA research note https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/07/CSA_research_note_claude_chrome_extension_click_simulation_flaw_20260718-csa-styled.pdf",
  "Download Claude only from official Anthropic channels, not ads or third-party artifacts.",
].join(" ");

const CLAUDE_FOR_CHROME_DISABLED_GUIDANCE = [
  "Official Claude for Chrome is still on disk but this profile shows it is turned off.",
  "Leave it disabled until Anthropic ships an independently verified isTrusted-style fix.",
  "Do not turn it back on for convenience.",
  "Read the public writeups: Manifold Security https://www.manifold.security/blog/claude-for-chrome-extension-bypass ; Malwarebytes https://www.malwarebytes.com/blog/news/2026/07/claude-for-chrome-flaw-could-let-rogue-extensions-access-your-gmail ; LayerX ClaudeBleed (archived original) https://web.archive.org/web/20260508132614/https://layerxsecurity.com/blog/a-flaw-in-claudes-browser-extension-allows-any-extension-to-hijack-it/ ; CSA research note https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/07/CSA_research_note_claude_chrome_extension_click_simulation_flaw_20260718-csa-styled.pdf",
].join(" ");

const CLAUDE_FOR_CHROME_UNKNOWN_ENABLEMENT_GUIDANCE = [
  "Official Claude for Chrome files are still on disk. This scan could not confirm from Preferences that the extension is enabled.",
  "Check chrome://extensions or edge://extensions and keep it off until Anthropic ships an independently verified isTrusted-style fix.",
  "Read the public writeups: Manifold Security https://www.manifold.security/blog/claude-for-chrome-extension-bypass ; Malwarebytes https://www.malwarebytes.com/blog/news/2026/07/claude-for-chrome-flaw-could-let-rogue-extensions-access-your-gmail ; LayerX ClaudeBleed (archived original) https://web.archive.org/web/20260508132614/https://layerxsecurity.com/blog/a-flaw-in-claudes-browser-extension-allows-any-extension-to-hijack-it/ ; CSA research note https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/07/CSA_research_note_claude_chrome_extension_click_simulation_flaw_20260718-csa-styled.pdf",
].join(" ");

const FAKE_CLAUDE_EXTENSION_GUIDANCE = [
  "You may be exposed.",
  "This is not Anthropic's official Claude in Chrome listing.",
  "Remove the extension in chrome://extensions or edge://extensions.",
  "Official Claude in Chrome is only extension id fcoeoabgfenejglbffodgkkbkcdhcgfn from Anthropic.",
  "Published impersonation IDs/hashes: OX Security https://www.ox.security/blog/malicious-chrome-extensions-steal-chatgpt-deepseek-conversations/ ; Microsoft https://www.microsoft.com/en-us/security/blog/2026/03/05/malicious-ai-assistant-extensions-harvest-llm-chat-histories/ ; Sophos https://www.sophos.com/en-us/blog/fake-ai-real-malware-attackers-impersonating-ai-brands",
].join(" ");

const FAKE_CLAUDE_LURE_GUIDANCE = [
  "You may be exposed.",
  "This local file matches a published fake-Claude install lure.",
  "Do not run advertised installers or ad-linked downloads.",
  "Get Claude only from official Anthropic channels (claude.ai or the Anthropic Chrome Web Store listing).",
  "Read Huntress FakeAgent https://www.huntress.com/blog/fakeagent-claude-desktop-malvertising-ends-in-dotnet-rat and Sophos https://www.sophos.com/en-us/blog/fake-ai-real-malware-attackers-impersonating-ai-brands",
].join(" ");

const FAKE_CLAUDE_EXTENSION_WATCHLIST = new Map([
  [
    "fnmihdojmnkclgjpcoonokmkhjpjechg",
    {
      name: "Chat GPT for Chrome with GPT-5, Claude Sonnet & DeepSeek AI",
      sources: "OX Security, Microsoft, Sophos IOC hashes",
    },
  ],
  [
    "inhcgfpbfdjbjogdfjbclgolkmhnooop",
    {
      name: "AI Sidebar with Deepseek, ChatGPT, Claude and more",
      sources: "OX Security, Microsoft, Sophos (named this listing; hashes match)",
    },
  ],
]);

const FAKE_CLAUDE_EXTENSION_NAMES = new Set([
  "chat gpt for chrome with gpt-5, claude sonnet & deepseek ai",
  "ai sidebar with deepseek, chatgpt, claude and more",
  "ai sidebar with deepseek, chatgpt, claude",
]);

const CLAUDE_PRIVILEGED_MODE_PATTERNS = [
  { label: "skip_all_permission_checks", pattern: /skip_all_permission_checks/i },
  { label: "skipPermissions=true", pattern: /skipPermissions\s*=\s*["']?true/i },
  { label: "skipPermissions true", pattern: /["']skipPermissions["']\s*:\s*["']true["']/i },
  { label: "Act without asking", pattern: /Act without asking/i },
  { label: "Skip all approvals", pattern: /Skip all approvals/i },
  { label: "CLAUDE_CHROME_PERMISSION_MODE", pattern: /CLAUDE_CHROME_PERMISSION_MODE\s*=\s*skip_all_permission_checks/i },
  { label: "lastPermissionModePreference skip", pattern: /lastPermissionModePreference["']?\s*[:=]\s*["']?skip_all_permission_checks/i },
];

const FAKE_CLAUDE_LURE_MARKERS = [
  { id: "huntress-fakeagent-artifact", value: "ca456f1f-44c0-42af-b329-4f1c7534a877" },
  { id: "huntress-download-app-us", value: "download-app.us" },
  { id: "huntress-downloading-api", value: "downloading-api.it.com" },
  { id: "huntress-sectoprat-backup-domain", value: "5ca8758c-02d0-4a72-89c8-d468b66dda41.com" },
  { id: "huntress-tempdir-dll", value: "1cd58cfba596da296ab1878d74023e00c399345a1b6c2a0e5446c53563f4e3bb" },
  { id: "huntress-libcef-dll", value: "26bae4d7012bf59847ab4036a065419c3d4ca47e020479f55b3b2c6d0d21394a" },
  { id: "huntress-sectoprat-payload", value: "1fe3646d27d286db8123297e06ae7badf3e26f352a04f91b6d82c28869a91664" },
  { id: "sophos-download-version-1-9-18", value: "download-version.1-9-18.com" },
  { id: "sophos-download-version-1-5-8", value: "download-version.1-5-8.com" },
  { id: "sophos-download-version-1-8-3", value: "download-version.1-8-3.com" },
  { id: "sophos-download-version-2-1-9", value: "download-version.2-1-9.com" },
  { id: "sophos-download-active-version", value: "download.active-version.com" },
  { id: "sophos-events-ms709", value: "events.ms709.com" },
  { id: "sophos-claude-setup-domain", value: "claude-setup.com" },
  { id: "sophos-verification-cdn", value: "code.verification-claude-cdn.beer" },
  { id: "sophos-claudemo", value: "finger.claudemo.net" },
  { id: "sophos-claudefos", value: "claudefos.com" },
  { id: "sophos-claudverification", value: "claudverification-id.beer" },
  { id: "sophos-claude-pro", value: "claude-pro.com" },
  { id: "sophos-msixbundle", value: "claude.msixbundle" },
  { id: "sophos-setup-zip", value: "claude setup.zip" },
  { id: "sophos-ox-extension-hash-1", value: "98d1f151872c27d0abae3887f7d6cb6e4ce29e99ad827cb077e1232bc4a69c00" },
  { id: "sophos-ox-extension-hash-2", value: "20ba72e91d7685926c8c1c5b4646616fa9d769e32c1bc4e9f15dddaf3429cea7" },
];

function scanTarget(targetPath) {
  const root = path.resolve(targetPath || ".");
  const findings = [];
  const claudeWatch = createClaudeWatch();
  let filesScanned = 0;

  walk(root, (filePath) => {
    filesScanned += 1;
    const text = readTextFile(filePath);
    if (text === null) return;
    inspectFile(filePath, root, text, findings, claudeWatch);
  });
  emitClaudeWatchFindings(findings, claudeWatch);

  return {
    tool: "browser-exposure-guard",
    version: "0.1.3",
    scannedAt: new Date().toISOString(),
    target: root,
    summary: summarize(filesScanned, findings),
    findings,
  };
}

function inspectFile(filePath, root, text, findings, claudeWatch) {
  const relative = path.relative(root, filePath).replace(/\\/g, "/") || path.basename(filePath);
  const extension = browserArtifactExtension(filePath);

  if (BROWSER_ARTIFACT_EXTENSIONS.has(extension)) {
    scanBrowserArtifact(relative, text, findings);
  }

  scanChromiumAdvisoryNotes(relative, text, findings);
  scanKnownAiExtensionManifest(relative, text, findings);
  scanOfficialClaudeForChrome(relative, text, claudeWatch);
  scanClaudePrivilegedModeSettings(relative, text, claudeWatch);
  scanFakeClaudeImpersonationExtension(relative, text, findings);
  scanFakeClaudeLureArtifact(relative, text, findings);
  scanCopilotRepromptLinks(relative, text, findings);
}

function createClaudeWatch() {
  return {
    presence: [],
    enablement: new Map(),
    privileged: [],
  };
}

function scanBrowserArtifact(relative, text, findings) {
  const hasScript = /<script\b|javascript:/i.test(text);
  const hasBrowserRiskApi = /\b(CanvasRenderingContext2D|beginLayer|TextDecoder|TextEncoder|OffscreenCanvas|createImageBitmap|WebGL2RenderingContext|AudioWorklet|SharedArrayBuffer)\b/i.test(text);
  const hasExploitLanguage = /\b(CVE-\d{4}-\d+|use-after-free|type confusion|heap corruption|renderer rce|sandbox escape|poc|proof.of.concept|crash repro)\b/i.test(text);

  if (hasScript && hasBrowserRiskApi && hasExploitLanguage) {
    addFinding(
      findings,
      "high",
      "browser-poc-artifact",
      relative,
      "Local browser-rendered artifact combines script, browser attack-surface APIs, and exploit/repro language.",
      "script + browser API + exploit language",
      "Do not open this file in a normal browser profile. Review in an isolated text viewer or disposable VM."
    );
  }

  if (/--enable-blink-features|--enable-experimental-web-platform-features|chrome:\/\/flags|about:flags/i.test(text)) {
    addFinding(
      findings,
      "medium",
      "browser-experimental-flag-note",
      relative,
      "File references experimental browser flags or feature toggles.",
      "experimental browser flags",
      "Avoid enabling experimental flags on daily-driver browsers when reviewing untrusted repro artifacts."
    );
  }

  scanPhishingAttachmentArtifact(relative, text, findings);
}

function scanPhishingAttachmentArtifact(relative, text, findings) {
  const extension = browserArtifactExtension(relative);
  const hasSvg = /<svg\b/i.test(text);
  const hasScript = /<script\b|javascript:|new\s+Function\s*\(|eval\s*\(/i.test(text);
  const htmlNamedSvg = (extension === ".html" || extension === ".htm") && hasSvg && !/<html\b/i.test(text.slice(0, 1000));
  const hiddenRenderMarkers = countMatches(text, /\b(?:opacity\s*=\s*["']?0["']?|visibility\s*:\s*hidden|visibility\s*=\s*["']hidden["']|fill\s*=\s*["']transparent["']|fill\s*:\s*transparent)\b/gi);
  const hasInvisibleSvgDashboard = hasSvg && hiddenRenderMarkers >= 3 && /\b(?:Business|Analytics|Dashboard|Performance|Revenue|Report)\b/i.test(text);
  const hasBusinessTermPayload = hasBusinessTermStegoPayload(text);
  const hasDynamicExecutionChain = /String\.fromCharCode\s*\(/i.test(text)
    && /(?:new\s+Function\s*\(|eval\s*\(|window\.location|location\.href)/i.test(text)
    && /(?:setTimeout\s*\(|charCodeAt\s*\(|\^\s*[^=]|%\s*256)/i.test(text);
  const hasKratosCampaignHash = /fb2a4eddd2e063dc/i.test(text);

  if (htmlNamedSvg && (hasScript || hasInvisibleSvgDashboard)) {
    addFinding(
      findings,
      "high",
      "phishing-svg-disguised-as-html",
      relative,
      "HTML-named browser artifact appears to contain SVG content, a common phishing attachment smuggling pattern.",
      "html extension + svg content",
      "Do not open this attachment in a normal browser profile. Review as text or in an isolated analysis environment."
    );
  }

  if (hasSvg && hasScript && hasInvisibleSvgDashboard) {
    addFinding(
      findings,
      "high",
      "phishing-invisible-svg-script",
      relative,
      "SVG artifact combines embedded script with invisible business-dashboard rendering camouflage.",
      "svg script + hidden visual elements",
      "Treat this as an active browser-executed attachment until proven benign."
    );
  }

  if (hasBusinessTermPayload && hasDynamicExecutionChain) {
    addFinding(
      findings,
      "high",
      "phishing-business-term-steganography",
      relative,
      "Browser artifact appears to combine business-term encoded payload data with dynamic JavaScript execution.",
      "business-term payload + dynamic execution",
      "Do not decode or execute the payload on a daily-driver host. Preserve the file and review in isolation."
    );
  }

  if (hasKratosCampaignHash || (hasBusinessTermPayload && hasInvisibleSvgDashboard && hasDynamicExecutionChain)) {
    addFinding(
      findings,
      "medium",
      "kratos-phishing-campaign-watch",
      relative,
      "File matches Kratos-style SVG phishing attachment watch signals reported by Sublime Security.",
      hasKratosCampaignHash ? "campaign hash marker" : "svg + business-term encoding + dynamic execution",
      "Correlate with sender reputation, authentication results, and attachment metadata before user exposure."
    );
  }
}

function hasBusinessTermStegoPayload(text) {
  const attributeMatches = text.match(/\bdata-[a-z0-9_-]+\s*=\s*["'][^"']{250,}["']/gi) || [];
  const candidateText = attributeMatches.length > 0 ? attributeMatches.join("\n") : text;
  const termMatches = BUSINESS_TERM_STEGO_TERMS.reduce((count, term) => {
    const pattern = new RegExp(`\\b${escapeRegExp(term)}\\b`, "gi");
    return count + countMatches(candidateText, pattern);
  }, 0);
  const concatenatedPairHits = countMatches(
    candidateText,
    /(?:earningsannual|riskannual|sharesannual|yieldannual|statementquarterly|capitalquarterly|budgetquarterly|reportannual|summaryquarterly|investmentannual)/gi
  );

  return termMatches >= 24 || concatenatedPairHits >= 3;
}

function countMatches(text, pattern) {
  return Array.from(text.matchAll(pattern)).length;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function browserArtifactExtension(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  if (extension) return extension;
  const base = path.basename(filePath).toLowerCase();
  return BROWSER_ARTIFACT_EXTENSIONS.has(base) ? base : "";
}

function scanChromiumAdvisoryNotes(relative, text, findings) {
  const matched = CHROMIUM_ADVISORY_TERMS.filter((term) => text.includes(term));
  if (matched.length < 2) return;

  addFinding(
    findings,
    "medium",
    "chromium-advisory-watch-note",
    relative,
    "File references Chromium browser vulnerability watch terms.",
    matched.slice(0, 4).join(", "),
    "Verify browser patch state and avoid running linked PoCs or repro artifacts outside isolation."
  );
}

function scanKnownAiExtensionManifest(relative, text, findings) {
  if (path.basename(relative).toLowerCase() !== "manifest.json") return;

  const normalized = relative.replace(/\\/g, "/").toLowerCase();
  for (const [extensionId, metadata] of AI_EXTENSION_WATCHLIST.entries()) {
    if (!normalized.split("/").includes(extensionId)) continue;

    const version = manifestVersion(text) || versionFromExtensionPath(normalized, extensionId) || "unknown";
    addFinding(
      findings,
      "high",
      "known-vulnerable-ai-browser-extension",
      relative,
      `${metadata.name} is installed in the scanned browser profile and matches Rebora's ${metadata.issue} watchlist.`,
      `extension id ${extensionId}; manifest version ${version}; risk: ${metadata.impact}`,
      "Disable or remove the extension until vendor remediation is independently verified. Review recently visited sites and browser account activity if exposure is suspected."
    );
  }
}

function scanOfficialClaudeForChrome(relative, text, claudeWatch) {
  const basename = path.basename(relative).toLowerCase();
  const normalized = relative.replace(/\\/g, "/").toLowerCase();
  const isManifest = basename === "manifest.json";
  const isPrefs = isChromiumPreferencesFile(relative);
  const profileKey = chromiumProfileKey(relative);
  const pathHasOfficialId = pathContainsExtensionId(normalized, OFFICIAL_CLAUDE_CHROME_EXTENSION_ID);

  if (isPrefs) recordClaudeEnablementFromPrefs(claudeWatch, profileKey, text);

  let matched = "";
  let version = "unknown";
  let extensionId = "";

  if (isManifest && pathHasOfficialId) {
    matched = `official extension id ${OFFICIAL_CLAUDE_CHROME_EXTENSION_ID}`;
    version = manifestVersion(text) || versionFromExtensionPath(normalized, OFFICIAL_CLAUDE_CHROME_EXTENSION_ID) || "unknown";
    extensionId = OFFICIAL_CLAUDE_CHROME_EXTENSION_ID;
  } else if (isManifest) {
    const identity = officialClaudeManifestIdentity(text);
    if (identity) {
      matched = identity;
      version = manifestVersion(text) || "unknown";
    }
  } else if (isPrefs && text.includes(OFFICIAL_CLAUDE_CHROME_EXTENSION_ID)) {
    matched = `browser Preferences lists official extension id ${OFFICIAL_CLAUDE_CHROME_EXTENSION_ID}`;
    version = prefsListedExtensionVersion(text, OFFICIAL_CLAUDE_CHROME_EXTENSION_ID) || "unknown";
    extensionId = OFFICIAL_CLAUDE_CHROME_EXTENSION_ID;
  }

  if (!matched) return;

  claudeWatch.presence.push({ relative, matched, version, profileKey, extensionId });
}

function scanClaudePrivilegedModeSettings(relative, text, claudeWatch) {
  if (!isClaudePrivilegedModeSettingsFile(relative)) return;

  const matched = CLAUDE_PRIVILEGED_MODE_PATTERNS.filter((entry) => entry.pattern.test(text)).map((entry) => entry.label);
  if (matched.length === 0) return;

  claudeWatch.privileged.push({
    relative,
    markers: matched,
    profileKey: chromiumProfileKey(relative),
    extensionId: OFFICIAL_CLAUDE_CHROME_EXTENSION_ID,
  });
}

function emitClaudeWatchFindings(findings, claudeWatch) {
  for (const item of claudeWatch.presence) {
    const enablement = lookupClaudeEnablement(claudeWatch, item.profileKey, item.extensionId);
    if (enablement === "enabled") {
      addFinding(
        findings,
        "high",
        "claude-for-chrome-unpatched-trust-boundary",
        item.relative,
        "Official Claude for Chrome / Claude in Chrome is present and enabled in the scanned local browser profile. Public research (LayerX ClaudeBleed, April–May 2026; Manifold Security, July 2026) reports that co-installed extensions able to run on claude.ai can still trigger Claude tasks because the click handler does not check event.isTrusted, including in v1.0.80.",
        `${item.matched}; manifest version ${item.version}; Preferences state enabled`,
        CLAUDE_FOR_CHROME_FIX_GUIDANCE
      );
      continue;
    }
    if (enablement === "disabled") {
      addFinding(
        findings,
        "medium",
        "claude-for-chrome-disabled-on-disk",
        item.relative,
        "Official Claude for Chrome / Claude in Chrome is still on disk but this profile shows it is turned off. Public LayerX / Manifold research is why it should stay off until Anthropic ships an independently verified isTrusted-style fix.",
        `${item.matched}; manifest version ${item.version}; Preferences state disabled`,
        CLAUDE_FOR_CHROME_DISABLED_GUIDANCE
      );
      continue;
    }
    addFinding(
      findings,
      "medium",
      "claude-for-chrome-on-disk-enablement-unknown",
      item.relative,
      "Official Claude for Chrome / Claude in Chrome files are on disk, but this scan could not confirm from Preferences that the extension is enabled. High/exposed is reserved for an enabled install.",
      `${item.matched}; manifest version ${item.version}; Preferences state not confirmed`,
      CLAUDE_FOR_CHROME_UNKNOWN_ENABLEMENT_GUIDANCE
    );
  }

  for (const item of claudeWatch.privileged) {
    const enablement = lookupClaudeEnablement(claudeWatch, item.profileKey, item.extensionId);
    const markers = `privileged-mode markers: ${item.markers.slice(0, 3).join("; ")}`;
    if (enablement === "enabled") {
      addFinding(
        findings,
        "high",
        "claude-for-chrome-act-without-asking",
        item.relative,
        "Local Claude for Chrome settings look like Act without asking / skip-all-permission-checks, and the official extension is enabled in this profile. Manifold Security rates the forged-click exposure Critical (9.6) in this mode versus High (7.7) in default ask-before-acting mode.",
        `${markers}; Preferences state enabled`,
        CLAUDE_FOR_CHROME_FIX_GUIDANCE
      );
      continue;
    }
    if (enablement === "disabled") {
      addFinding(
        findings,
        "medium",
        "claude-for-chrome-act-without-asking",
        item.relative,
        "Act without asking / skip-all-permission-checks strings remain on disk, but this profile shows Claude for Chrome is turned off. Leave it disabled until Anthropic ships an independently verified isTrusted-style fix.",
        `${markers}; Preferences state disabled`,
        CLAUDE_FOR_CHROME_DISABLED_GUIDANCE
      );
      continue;
    }
    addFinding(
      findings,
      "medium",
      "claude-for-chrome-act-without-asking",
      item.relative,
      "Act without asking / skip-all-permission-checks strings are on disk, but this scan could not confirm the official extension is enabled. High/exposed is reserved for an enabled install.",
      `${markers}; Preferences state not confirmed`,
      CLAUDE_FOR_CHROME_UNKNOWN_ENABLEMENT_GUIDANCE
    );
  }
}

function recordClaudeEnablementFromPrefs(claudeWatch, profileKey, text) {
  const parsed = parsedManifest(text);
  const settings = parsed && parsed.extensions && parsed.extensions.settings && typeof parsed.extensions.settings === "object"
    ? parsed.extensions.settings
    : null;

  if (settings) {
    if (settings[OFFICIAL_CLAUDE_CHROME_EXTENSION_ID]) {
      recordClaudeEnablement(
        claudeWatch,
        profileKey,
        OFFICIAL_CLAUDE_CHROME_EXTENSION_ID,
        interpretChromiumExtensionState(settings[OFFICIAL_CLAUDE_CHROME_EXTENSION_ID])
      );
    }
    for (const [extensionId, entry] of Object.entries(settings)) {
      if (!entry || typeof entry !== "object") continue;
      const name = String((entry.manifest && entry.manifest.name) || "").trim().toLowerCase();
      if (name !== "claude" && name !== "claude in chrome") continue;
      recordClaudeEnablement(claudeWatch, profileKey, extensionId, interpretChromiumExtensionState(entry));
    }
    return;
  }

  if (text.includes(OFFICIAL_CLAUDE_CHROME_EXTENSION_ID)) {
    recordClaudeEnablement(
      claudeWatch,
      profileKey,
      OFFICIAL_CLAUDE_CHROME_EXTENSION_ID,
      interpretChromiumExtensionStateFromText(text, OFFICIAL_CLAUDE_CHROME_EXTENSION_ID)
    );
  }
}

function recordClaudeEnablement(claudeWatch, profileKey, extensionId, enablement) {
  if (!profileKey || !extensionId || !enablement) return;
  const key = `${profileKey}::${extensionId}`;
  const existing = claudeWatch.enablement.get(key);
  if (existing === "disabled" || enablement === "disabled") {
    claudeWatch.enablement.set(key, "disabled");
    return;
  }
  claudeWatch.enablement.set(key, enablement);
}

function lookupClaudeEnablement(claudeWatch, profileKey, extensionId) {
  if (profileKey && extensionId) {
    const exact = claudeWatch.enablement.get(`${profileKey}::${extensionId}`);
    if (exact) return exact;
  }
  return "";
}

function interpretChromiumExtensionState(settings) {
  if (!settings || typeof settings !== "object") return "";
  if (settings.state === 1 || settings.state === "1" || settings.enabled === true) return "enabled";
  if (settings.state === 0 || settings.state === "0" || settings.enabled === false) return "disabled";
  const reasons = settings.disable_reasons;
  if (reasons !== undefined && reasons !== null && reasons !== 0 && reasons !== "0" && reasons !== "") {
    return "disabled";
  }
  return "";
}

function interpretChromiumExtensionStateFromText(text, extensionId) {
  const block = text.match(new RegExp(`"${escapeRegExp(extensionId)}"\\s*:\\s*\\{([\\s\\S]{0,4000}?)\\n\\s*\\}`));
  const haystack = block ? block[1] : text;
  if (/"state"\s*:\s*"?1"?/.test(haystack) || /"enabled"\s*:\s*true/.test(haystack)) return "enabled";
  if (/"state"\s*:\s*"?0"?/.test(haystack) || /"enabled"\s*:\s*false/.test(haystack)) return "disabled";
  if (/"disable_reasons"\s*:\s*(?:[1-9]\d*|"[1-9]\d*")/.test(haystack)) return "disabled";
  return "";
}

function chromiumProfileKey(relative) {
  const parts = relative.replace(/\\/g, "/").split("/");
  const markers = new Set(["extensions", "local extension settings", "sync extension settings"]);
  for (let index = 0; index < parts.length; index += 1) {
    if (markers.has(parts[index].toLowerCase()) && index > 0) {
      return parts.slice(0, index).join("/").toLowerCase();
    }
  }
  if (isChromiumPreferencesFile(relative) && parts.length > 1) {
    return parts.slice(0, -1).join("/").toLowerCase();
  }
  return "";
}

function scanFakeClaudeImpersonationExtension(relative, text, findings) {
  if (path.basename(relative).toLowerCase() !== "manifest.json") return;

  const normalized = relative.replace(/\\/g, "/").toLowerCase();
  for (const [extensionId, metadata] of FAKE_CLAUDE_EXTENSION_WATCHLIST.entries()) {
    if (!pathContainsExtensionId(normalized, extensionId)) continue;
    const version = manifestVersion(text) || versionFromExtensionPath(normalized, extensionId) || "unknown";
    addFinding(
      findings,
      "high",
      "fake-claude-impersonation-extension",
      relative,
      `Installed extension matches a published Claude-themed impersonation listing (${metadata.name}).`,
      `extension id ${extensionId}; manifest version ${version}; sources: ${metadata.sources}`,
      FAKE_CLAUDE_EXTENSION_GUIDANCE
    );
    return;
  }

  const identity = parsedManifest(text);
  if (!identity) return;
  const normalizedName = normalizeExtensionName(identity.name);
  if (!FAKE_CLAUDE_EXTENSION_NAMES.has(normalizedName)) return;

  addFinding(
    findings,
    "high",
    "fake-claude-impersonation-extension",
    relative,
    `Installed extension name matches a published Claude-themed impersonation listing (${identity.name}).`,
    `manifest name ${identity.name}; version ${identity.version || "unknown"}`,
    FAKE_CLAUDE_EXTENSION_GUIDANCE
  );
}

function scanFakeClaudeLureArtifact(relative, text, findings) {
  if (!isFakeClaudeLureScanTarget(relative)) return;

  const haystack = text.toLowerCase();
  const matched = FAKE_CLAUDE_LURE_MARKERS.filter((marker) => haystack.includes(marker.value.toLowerCase()));
  if (matched.length === 0) return;

  addFinding(
    findings,
    "high",
    "fake-claude-install-lure-artifact",
    relative,
    "Local artifact matches published Huntress FakeAgent or Sophos fake-Claude install lure indicators.",
    matched.map((marker) => marker.id).join(", "),
    FAKE_CLAUDE_LURE_GUIDANCE
  );
}

function officialClaudeManifestIdentity(text) {
  const manifest = parsedManifest(text);
  if (!manifest) return "";
  const name = String(manifest.name || "").trim().toLowerCase();
  const officialName = name === "claude" || name === "claude in chrome";
  if (!officialName) return "";

  const author = String(manifest.author || "").toLowerCase();
  const homepage = String(manifest.homepage_url || manifest.homepage || "").toLowerCase();
  const officialPublisher = author.includes("anthropic")
    || homepage.includes("anthropic.com")
    || homepage.includes("claude.ai");
  if (!officialPublisher) return "";

  return `manifest name ${manifest.name}; publisher ${manifest.author || manifest.homepage_url || "Anthropic"}`;
}

function isChromiumPreferencesFile(relative) {
  const base = path.basename(relative);
  return base === "Preferences" || base === "Secure Preferences";
}

function isClaudePrivilegedModeSettingsFile(relative) {
  const normalized = relative.replace(/\\/g, "/").toLowerCase();
  if (isChromiumPreferencesFile(relative)) return true;
  return normalized.includes(`/local extension settings/${OFFICIAL_CLAUDE_CHROME_EXTENSION_ID}/`)
    || normalized.includes(`/sync extension settings/${OFFICIAL_CLAUDE_CHROME_EXTENSION_ID}/`);
}

function isFakeClaudeLureScanTarget(relative) {
  const extension = path.extname(relative).toLowerCase();
  if (BROWSER_ARTIFACT_EXTENSIONS.has(extension) || extension === ".log" || extension === ".txt" || extension === ".json") {
    return true;
  }
  return isChromiumPreferencesFile(relative);
}

function pathContainsExtensionId(normalizedRelative, extensionId) {
  return normalizedRelative.split("/").includes(extensionId);
}

function normalizeExtensionName(name) {
  return String(name || "").toLowerCase().replace(/[.]/g, "").replace(/\s+/g, " ").trim();
}

function parsedManifest(text) {
  try {
    const manifest = JSON.parse(text);
    return manifest && typeof manifest === "object" ? manifest : null;
  } catch (_error) {
    return null;
  }
}

function prefsListedExtensionVersion(text, extensionId) {
  const pattern = new RegExp(`"${escapeRegExp(extensionId)}"\\s*:\\s*\\{[\\s\\S]{0,4000}?"version"\\s*:\\s*"([^"]+)"`);
  const match = text.match(pattern);
  return match ? match[1] : "";
}

function scanCopilotRepromptLinks(relative, text, findings) {
  const candidateUrls = extractUrls(text);
  for (const url of candidateUrls) {
    const decoded = safeDecode(url);
    const normalized = decoded.toLowerCase();
    if (!COPILOT_REPROMPT_HOSTS.some((host) => normalized.includes(host))) continue;
    if (!/[?&]q=|%3fq%3d|%26q%3d/i.test(url) && !/[?&]q=/i.test(decoded)) continue;

    const queryText = copilotQueryText(decoded);
    if (!queryText) continue;
    const hasPrivateContextRequest = /\b(?:recent files?|looked at today|where is the user|user location|sharepoint|onedrive|calendar|email|mailbox)\b/i.test(queryText);
    const hasExternalExfil = /\b(?:send to|fetch|post to|exfiltrate|upload to|attacker server)\b[\s\S]{0,120}https?:\/\//i.test(queryText)
      || /\b(?:webhook|collect|callback|exfil)\b/i.test(queryText);

    if (hasPrivateContextRequest && hasExternalExfil) {
      addFinding(
        findings,
        "high",
        "copilot-reprompt-qparam-exfil-link",
        relative,
        "Local browser/client artifact contains a Microsoft Copilot q-parameter link shaped like Reprompt-style data exfiltration.",
        "Copilot URL + q parameter + private-context request + external exfiltration terms",
        "Do not click the link. Preserve the artifact and review the source, sender, referrer, and any Microsoft 365/Copilot activity around exposure."
      );
      return;
    }
  }
}

function extractUrls(text) {
  const urls = [];
  const pattern = /https?:\/\/[^\s"'<>]+/gi;
  for (const match of text.matchAll(pattern)) {
    urls.push(match[0]);
  }
  return urls;
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch (_error) {
    return value;
  }
}

function copilotQueryText(url) {
  const match = url.match(/[?&]q=([^#&]+)/i);
  if (!match) return "";
  return match[1].replace(/\+/g, " ");
}

function manifestVersion(text) {
  try {
    const manifest = JSON.parse(text);
    return typeof manifest.version === "string" && manifest.version.trim() ? manifest.version.trim() : "";
  } catch (_error) {
    return "";
  }
}

function versionFromExtensionPath(normalizedRelative, extensionId) {
  const parts = normalizedRelative.split("/");
  const idIndex = parts.indexOf(extensionId);
  if (idIndex < 0 || idIndex + 1 >= parts.length) return "";
  return parts[idIndex + 1] || "";
}

function walk(root, onFile) {
  let stat;
  try {
    stat = fs.statSync(root);
  } catch (_error) {
    return;
  }

  if (stat.isFile()) {
    onFile(root);
    return;
  }

  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && shouldReadFile(fullPath)) {
        onFile(fullPath);
      }
    }
  }
}

function shouldReadFile(filePath) {
  if (!TEXT_EXTENSIONS.has(path.extname(filePath).toLowerCase())) return false;
  try {
    return fs.statSync(filePath).size <= MAX_FILE_BYTES;
  } catch (_error) {
    return false;
  }
}

function readTextFile(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (_error) {
    return null;
  }
}

function addFinding(findings, severity, id, filePath, reason, evidence, guidance) {
  findings.push({ severity, id, path: filePath, reason, evidence, guidance });
}

function summarize(filesScanned, findings) {
  const summary = { filesScanned, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    summary[finding.severity] = (summary[finding.severity] || 0) + 1;
  }
  return summary;
}

module.exports = { scanTarget };
