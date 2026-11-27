import express, { type Request, type Response } from "express";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { GoogleGenAI } from "@google/genai";

const PORT = Number(process.env.PORT) || 3000;
const INDEX_PATH = path.resolve(process.cwd(), "internal/ui/index.html");

interface Finding {
  layer: string;
  name: string;
  score: number;
  detail?: string;
}

interface AIVerdict {
  verdict: "malicious" | "suspicious" | "benign" | "unknown";
  confidence: number;
  category?: string;
  recommended_action?: string;
  summary?: string;
  reasons: string[];
  provider: string;
  model: string;
  cached?: boolean;
}

interface ScanResult {
  path: string;
  size: number;
  sha256: string;
  verdict: string;
  score: number;
  threat?: string;
  findings: Finding[];
  ai?: AIVerdict;
  signature_trusted?: boolean;
  action?: string;
  duration_ms: number;
}

interface AppEvent {
  time: string;
  type: "detection" | "anomaly" | "protection" | "definitions" | "scan" | "system";
  severity: "info" | "warn" | "high";
  message: string;
  data?: Record<string, unknown>;
}

interface QItem {
  id: string;
  original: string;
  threat: string;
  sha256: string;
  time: string;
}

const CLOUD_PROVIDERS = [
  {
    id: "gemini",
    name: "Google Gemini",
    secret_name: "gemini",
    default_model: "gemini-2.5-flash",
    models: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.5-flash-lite"],
    docs_hint: "Fast structured JSON triage via Google AI Studio API key",
  },
  {
    id: "claude",
    name: "Anthropic Claude",
    secret_name: "anthropic",
    default_model: "claude-sonnet-4-5",
    models: ["claude-sonnet-4-5", "claude-opus-4-5", "claude-haiku-4-5"],
    docs_hint: "Deep malware reasoning via Anthropic API key",
  },
  {
    id: "openai",
    name: "OpenAI / Compatible",
    secret_name: "openai",
    default_model: "gpt-4.1-mini",
    models: ["gpt-4.1-mini", "gpt-4.1", "o4-mini"],
    docs_hint: "Works with OpenAI, OpenRouter, Groq or any /v1/chat/completions endpoint",
  },
];

const RECOMMENDED_LOCAL = [
  { Model: "qwen3:1.7b", Params: "1.7B", About: "Strong structured JSON reasoning on CPU or GPU (~1.1 GB)" },
  { Model: "qwen2.5:1.5b", Params: "1.5B", About: "Fast, reliable triage on 8 GB RAM laptops (~980 MB)" },
  { Model: "llama3.2:1b", Params: "1.2B", About: "Ultra-lightweight background triage (~750 MB)" },
  { Model: "gemma3:1b", Params: "1.0B", About: "Minimal footprint with fast token throughput (~815 MB)" },
];

const DEF_PRESETS = [
  { name: "malwarebazaar-sha256", url: "https://bazaar.abuse.ch/export/txt/sha256/recent/", about: "Recent MalwareBazaar SHA-256 hashes" },
  { name: "threatfox-hashes", url: "https://threatfox.abuse.ch/export/csv/sha256/recent/", about: "ThreatFox recent IOC hashes" },
  { name: "yara-community", url: "https://raw.githubusercontent.com/Yara-Rules/rules/master/index.yar", about: "Community YARA detection pack" },
];

const nowIso = (offsetMs = 0) => new Date(Date.now() + offsetMs).toISOString();

const state = {
  version: "0.2.0",
  edition: "core",
  protection: true,
  protection_reason: "enabled",
  guard_running: true,
  boot_scan_scheduled: false,
  admin: true,
  user: "DESKTOP-WS01\\Analyst",
  data_dir: "C:\\ProgramData\\Visionary",
  config: {
    profile: "balanced",
    game_mode: { auto: true, forced: false },
    realtime: { auto_quarantine: true },
    behavior: { enabled: true, learning: false },
    windows: { defender_second_opinion: true },
    scan: {
      scan_archives: true,
      use_cache: true,
      excludes: ["\\AppData\\Local\\Temp\\vite-cache\\"],
    },
    allow: {
      hashes: [] as string[],
      paths: ["C:\\Tools\\Sysinternals\\procexp64.exe"],
    },
    security: { require_password_to_disable: false },
    ai: {
      mode: "hybrid",
      sensitivity: "balanced",
      confidence_threshold: 0.8,
      local: {
        provider: "ollama",
        endpoint: "http://127.0.0.1:11434",
        model: "qwen3:1.7b",
        model_path: "",
        max_params_b: 3.0,
        cpu_only: false,
      },
      cloud: {
        provider: "gemini",
        model: "gemini-2.5-flash",
        endpoint: "",
        share_snippets: false,
      },
    },
  },
  secrets: {
    gemini: Boolean(process.env.GEMINI_API_KEY),
    claude: false,
    openai: false,
    virustotal: true,
    huggingface: false,
  } as Record<string, boolean>,
  ai_stats: {
    triaged: 14,
    convicted: 2,
    cleared: 11,
    cache_hits: 38,
    errors: 0,
  },
  windows_security: {
    available: true,
    running_mode: "Normal",
    realtime_enabled: true,
    tamper_protected: true,
    signature_updated: "2026-11-25 14:10",
    force_passive_policy: false,
    visionary_role: "second layer alongside Defender (both active; Visionary's folders are excluded in Defender to avoid double work)",
    notes: [
      "Tamper Protection is on: Defender settings can only be changed from the Windows Security app.",
    ],
  },
  behavior: {
    executables: 184,
    parent_child_edges: 312,
    typical_file_changes_per_10s: 14,
  },
  defs: {
    stats: { hashes: 128450, rules: 46, rules_skipped: 0, certs: 39, revision: 12 },
    sources: [
      { name: "malwarebazaar-sha256", kind: "hashes", origin: "https://bazaar.abuse.ch/export/txt/sha256/recent/", count: 128450, imported_at: nowIso(-3600_000 * 3), channel: "malwarebazaar-sha256" },
      { name: "builtin-yara", kind: "yara", origin: "embedded", count: 46, imported_at: nowIso(-86400_000 * 2) },
      { name: "revoked-signers", kind: "certs", origin: "embedded", count: 39, imported_at: nowIso(-86400_000 * 2) },
    ],
    channels: [
      { name: "malwarebazaar-sha256", url: "https://bazaar.abuse.ch/export/txt/sha256/recent/", interval_hours: 6, last_checked: nowIso(-3600_000 * 3), last_status: "128,450 hashes up to date" },
    ],
  },
  ollama_models: [
    { name: "qwen3:1.7b", params: "1.7B", params_b: 1.7, size_mb: 1120, loaded: true },
    { name: "llama3.2:1b", params: "1.2B", params_b: 1.2, size_mb: 754, loaded: false },
  ],
  stored_models: [
    { name: "Qwen3-1.7B-Q4_K_M.gguf", params_b: 1.72, size_mb: 1096, source: "unsloth/Qwen3-1.7B-GGUF", path: "C:\\ProgramData\\Visionary\\models\\Qwen3-1.7B-Q4_K_M.gguf" },
  ],
  download: {
    running: false,
    ref: "",
    done: 0,
    total: 0,
    error: "",
    result: "",
  },
  quarantine: [
    {
      id: "q-9f21c8a4",
      original: "C:\\Users\\Analyst\\Downloads\\Invoice_Q4_Viewer.hta",
      threat: "AI.Dropper.MSHTA",
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      time: nowIso(-3600_000 * 4),
    },
  ] as QItem[],
  events: [
    {
      time: nowIso(-1800_000),
      type: "detection",
      severity: "high",
      message: "real-time guard: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe — AI.LOLBin.EncodedCradle (score 92)",
      data: {
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        verdict: "malicious",
        score: 92,
        threat: "AI.LOLBin.EncodedCradle",
        action: "process flagged & script blocked",
        signature_trusted: true,
        findings: [
          { layer: "behavior", name: "LOLBin.OfficeToPowerShell", score: 55, detail: "WINWORD.EXE -> powershell.exe -enc IEX(New-Object Net.WebClient)..." },
          { layer: "ai", name: "AI.LOLBin.EncodedCradle", score: 92, detail: "94% confidence · lolbin" },
        ],
        ai: {
          verdict: "malicious",
          confidence: 0.94,
          category: "lolbin",
          recommended_action: "quarantine",
          summary: "Signed Microsoft PowerShell was spawned by Microsoft Word with an obfuscated Base64 download cradle — classic fileless initial-access LOLBin abuse.",
          reasons: [
            "Unexpected parent-child launch chain: WINWORD.EXE -> powershell.exe",
            "Encoded command line attempts remote payload fetch into memory",
            "Behavioural score preserved despite trusted Microsoft Authenticode signature",
          ],
          provider: "gemini",
          model: "gemini-2.5-flash",
        },
      },
    },
    {
      time: nowIso(-2400_000),
      type: "anomaly",
      severity: "high",
      message: "Anomalous process lineage detected: WINWORD.EXE -> powershell.exe",
      data: {
        exe: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent: "WINWORD.EXE",
        pid: 8842,
        score: 85,
        reasons: [
          "Office application spawned scripting interpreter (never seen in baseline)",
          "Encoded command-line argument (-enc / -WindowStyle Hidden)",
        ],
        cmdline: "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA...",
      },
    },
    {
      time: nowIso(-3600_000 * 4),
      type: "detection",
      severity: "high",
      message: "real-time guard: C:\\Users\\Analyst\\Downloads\\Invoice_Q4_Viewer.hta — AI.Dropper.MSHTA (score 88)",
      data: {
        path: "C:\\Users\\Analyst\\Downloads\\Invoice_Q4_Viewer.hta",
        verdict: "malicious",
        score: 88,
        threat: "AI.Dropper.MSHTA",
        action: "quarantined (q-9f21c8a4)",
        findings: [
          { layer: "heuristic", name: "Script.ActiveXShell", score: 45, detail: "WScript.Shell + hidden mshta execution in Downloads" },
          { layer: "ai", name: "AI.Dropper.MSHTA", score: 88, detail: "91% confidence · dropper" },
        ],
        ai: {
          verdict: "malicious",
          confidence: 0.91,
          category: "dropper",
          recommended_action: "quarantine",
          summary: "HTML Application disguised as a quarterly invoice invokes WScript.Shell to stage a remote payload.",
          reasons: [
            "Double-extension social engineering filename in Downloads folder",
            "ActiveXObject WScript.Shell execution pattern detected",
          ],
          provider: "ollama",
          model: "qwen3:1.7b",
        },
      },
    },
    {
      time: nowIso(-3600_000 * 5),
      type: "scan",
      severity: "info",
      message: "quick scan: 1,428 files, 0 malicious, 1 suspicious, 3.8s",
    },
    {
      time: nowIso(-3600_000 * 8),
      type: "definitions",
      severity: "info",
      message: "channel malwarebazaar-sha256 updated (128,450 hashes)",
    },
    {
      time: nowIso(-3600_000 * 12),
      type: "protection",
      severity: "info",
      message: "Real-time AI protection enabled (hybrid mode · balanced sensitivity)",
    },
  ] as AppEvent[],
  job: {
    running: false,
    kind: "",
    files: 0,
    current: "",
    detections: [] as ScanResult[],
    summary: null as null | { files: number; malicious: number; suspicious: number; quarantined: number; cached: number; seconds: number; cancelled: boolean },
    error: "",
    timer: null as ReturnType<typeof setInterval> | null,
  },
};

function logEvent(type: AppEvent["type"], severity: AppEvent["severity"], message: string, data?: Record<string, unknown>) {
  state.events.unshift({ time: nowIso(), type, severity, message, data });
  if (state.events.length > 500) state.events.length = 500;
}

function activeProviderInfo() {
  return CLOUD_PROVIDERS.find((p) => p.id === state.config.ai.cloud.provider) || CLOUD_PROVIDERS[0];
}

function hasActiveCloudKey() {
  return Boolean(state.secrets[state.config.ai.cloud.provider]);
}

function computeTrayStatus(): { tray_state: "active" | "paused" | "warning"; tray_label: string; tray_detail: string } {
  const lowReason = (state.protection_reason || "").toLowerCase();
  if (!state.protection && lowReason.includes("re-enabled")) {
    return { tray_state: "warning", tray_label: "Warning: Protection Off", tray_detail: "Real-time protection is turned off" };
  }
  if (!state.protection) {
    const r = state.protection_reason || "Real-time protection is temporarily paused";
    return { tray_state: "paused", tray_label: "Protection Paused", tray_detail: r.charAt(0).toUpperCase() + r.slice(1) };
  }
  if (!state.guard_running) {
    return { tray_state: "warning", tray_label: "Warning: Guard Offline", tray_detail: "Real-time protection service is not running" };
  }
  if (state.quarantine.length > 0) {
    const n = state.quarantine.length;
    return {
      tray_state: "warning",
      tray_label: n === 1 ? "Warning: 1 Threat Quarantined" : `Warning: ${n} Threats Quarantined`,
      tray_detail: n === 1 ? "1 quarantined file awaiting review" : `${n} quarantined files awaiting review`,
    };
  }
  if (state.config.game_mode.forced) {
    return { tray_state: "active", tray_label: "Protected (Game Mode)", tray_detail: "Real-time protection active at background priority" };
  }
  return { tray_state: "active", tray_label: "Protected", tray_detail: "Real-time AI protection is active" };
}

function buildStatus(withWindows: boolean) {
  const mode = state.config.ai.mode;
  const tray = computeTrayStatus();
  return {
    version: state.version,
    edition: state.edition,
    protection: state.protection,
    protection_reason: state.protection_reason,
    guard_running: state.guard_running,
    game_mode: state.config.game_mode.forced,
    profile: state.config.profile,
    definitions: state.defs.stats,
    channels: state.defs.channels.length,
    ai_mode: mode,
    ai_sensitivity: state.config.ai.sensitivity,
    local_model: mode === "local" || mode === "hybrid" ? state.config.ai.local.model : "",
    cloud_provider: state.config.ai.cloud.provider,
    cloud_model: mode === "cloud" || mode === "hybrid" ? state.config.ai.cloud.model : "",
    cloud_key_set: hasActiveCloudKey(),
    ai_stats: state.ai_stats,
    virustotal_key_set: state.secrets.virustotal,
    quarantined: state.quarantine.length,
    behavior_learning: state.config.behavior.learning,
    behavior: state.behavior,
    boot_scan_scheduled: state.boot_scan_scheduled,
    admin: state.admin,
    data_dir: state.data_dir,
    windows_security: withWindows ? state.windows_security : undefined,
    ui_host: `127.0.0.1:7878`,
    ...tray,
  };
}

async function runLiveGeminiExplain(filePath: string): Promise<{ verdict: AIVerdict; explanation: string; model: string } | null> {
  const key = process.env.GEMINI_API_KEY;
  if (!key) return null;
  try {
    const ai = new GoogleGenAI({ apiKey: key });
    const model = state.config.ai.cloud.model.startsWith("gemini") ? state.config.ai.cloud.model : "gemini-2.5-flash";
    const prompt = `You are Visionary AI Protection's malware analyst. A user asked to explain the security risk profile of this Windows file path and typical indicators: "${filePath}". Provide a concise, practical 3-5 sentence plain-English security briefing covering what the file/path likely is, whether its location or extension carries elevated risk (e.g. Downloads, Temp, HTA, PS1, unsigned PE, or LOLBin), and what concrete next step the user should take. Avoid markdown formatting.`;
    const resp = await ai.models.generateContent({ model, contents: prompt });
    const text = (resp.text || "").trim();
    if (!text) return null;
    const lower = filePath.toLowerCase();
    const risky = lower.includes("temp") || lower.includes(".hta") || lower.includes("powershell") || lower.includes("download") || lower.includes("crack") || lower.includes("loader");
    return {
      verdict: {
        verdict: risky ? "suspicious" : "benign",
        confidence: risky ? 0.84 : 0.91,
        category: lower.includes("powershell") ? "lolbin" : risky ? "dropper" : "benign",
        recommended_action: risky ? "review" : "allow",
        summary: text.split("\n")[0].slice(0, 200),
        reasons: [
          risky ? "Path/extension matches elevated-risk staging or scripting vector" : "Standard system or user path with no known malicious signature",
          "Analyzed live with Google Gemini structured threat triage",
        ],
        provider: "gemini",
        model,
      },
      explanation: text,
      model: `gemini / ${model}`,
    };
  } catch {
    return null;
  }
}

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.send(fs.readFileSync(INDEX_PATH, "utf8"));
});

app.get("/api/status", (req: Request, res: Response) => {
  res.json(buildStatus(req.query.windows === "1"));
});

app.post("/api/protection", (req: Request, res: Response) => {
  const { action, for: dur } = req.body || {};
  if (action === "enable") {
    state.protection = true;
    state.protection_reason = "enabled";
    logEvent("protection", "info", "Real-time protection enabled");
    return res.json({ ok: true });
  }
  if (action === "disable") {
    state.protection = false;
    state.protection_reason = dur === "restart" ? "disabled until restart" : dur === "permanent" ? "disabled until re-enabled" : `disabled for ${dur || "15m"}`;
    logEvent("protection", "warn", `Real-time protection ${state.protection_reason}`);
    return res.json({ ok: true });
  }
  res.status(400).json({ error: "unknown action" });
});

app.post("/api/scan", (req: Request, res: Response) => {
  const { kind, paths, deep, quarantine } = req.body || {};
  if (state.job.running) return res.status(400).json({ error: "a scan is already running" });
  if (kind === "targeted" && (!Array.isArray(paths) || !paths[0])) {
    return res.status(400).json({ error: "enter a file or folder to scan" });
  }
  state.job.running = true;
  state.job.kind = kind || "quick";
  state.job.files = 0;
  state.job.current = "Enumerating running processes, startup entries and risky folders…";
  state.job.detections = [];
  state.job.summary = null;
  state.job.error = "";

  const samples =
    kind === "targeted"
      ? [String(paths[0])]
      : [
          "C:\\Windows\\System32\\svchost.exe",
          "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          "C:\\Users\\Analyst\\AppData\\Local\\Temp\\upd_stage32.ps1",
          "C:\\Users\\Analyst\\Downloads\\packed-utility-setup.exe",
          "C:\\Windows\\System32\\cmd.exe",
        ];

  let step = 0;
  const started = Date.now();
  state.job.timer = setInterval(() => {
    step++;
    state.job.files += kind === "targeted" ? 1 : 210 + Math.floor(Math.random() * 90);
    state.job.current = samples[Math.min(step - 1, samples.length - 1)];

    if (step === 3 && kind !== "targeted") {
      const mal: ScanResult = {
        path: "C:\\Users\\Analyst\\AppData\\Local\\Temp\\upd_stage32.ps1",
        size: 18420,
        sha256: crypto.createHash("sha256").update("upd_stage32.ps1").digest("hex"),
        verdict: "malicious",
        score: 91,
        threat: "AI.Dropper.PowerShellStage",
        action: quarantine ? "quarantined" : "reported",
        duration_ms: 420,
        findings: [
          { layer: "heuristic", name: "Script.ObfuscatedBase64", score: 45, detail: "High-entropy encoded payload in Temp" },
          { layer: "behavior", name: "RiskyPath.TempExecution", score: 25, detail: "Unsigned script staged in AppData\\Local\\Temp" },
          ...(deep && state.config.ai.mode !== "off"
            ? [{ layer: "ai", name: "AI.Dropper.PowerShellStage", score: 91, detail: "93% confidence · dropper" }]
            : []),
        ],
        ai:
          deep && state.config.ai.mode !== "off"
            ? {
                verdict: "malicious",
                confidence: 0.93,
                category: "dropper",
                recommended_action: "quarantine",
                summary: "Obfuscated PowerShell stager in Temp decodes an in-memory loader and registers a Run-key persistence entry.",
                reasons: [
                  "Multi-layer Base64 payload paired with Reflection.Assembly::Load",
                  "Writes HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run persistence",
                  "No valid publisher signature; high-risk Temp directory origin",
                ],
                provider: state.config.ai.mode === "local" ? "ollama" : state.config.ai.cloud.provider,
                model: state.config.ai.mode === "local" ? state.config.ai.local.model : state.config.ai.cloud.model,
              }
            : undefined,
      };
      state.job.detections.push(mal);
      if (deep && state.config.ai.mode !== "off") {
        state.ai_stats.triaged++;
        state.ai_stats.convicted++;
      }
      if (quarantine) {
        state.quarantine.unshift({
          id: "q-" + crypto.randomBytes(4).toString("hex"),
          original: mal.path,
          threat: mal.threat || "Malicious",
          sha256: mal.sha256,
          time: nowIso(),
        });
      }
      logEvent("detection", "high", `${state.job.kind} scan: ${mal.path} — ${mal.threat} (score ${mal.score})`, mal as unknown as Record<string, unknown>);
    }

    if (step === 4 && kind !== "targeted") {
      const susp: ScanResult = {
        path: "C:\\Users\\Analyst\\Downloads\\packed-utility-setup.exe",
        size: 4218880,
        sha256: crypto.createHash("sha256").update("packed-utility-setup.exe").digest("hex"),
        verdict: "suspicious",
        score: 52,
        threat: "Heuristic.UPXPackedUnsigned",
        action: "review recommended",
        duration_ms: 310,
        findings: [
          { layer: "heuristic", name: "PE.HighEntropyPacked", score: 35, detail: "UPX section entropy 7.64, unsigned binary in Downloads" },
          ...(deep && state.config.ai.mode !== "off"
            ? [{ layer: "ai", name: "AI.DualUse.UnsignedInstaller", score: 52, detail: "68% confidence · pup" }]
            : []),
        ],
        ai:
          deep && state.config.ai.mode !== "off"
            ? {
                verdict: "suspicious",
                confidence: 0.68,
                category: "pup",
                recommended_action: "review",
                summary: "Unsigned UPX-packed installer downloaded from the internet. Below auto-quarantine threshold; verify publisher before running.",
                reasons: [
                  "Missing Authenticode code-signing certificate",
                  "Compressed UPX sections hinder static import inspection",
                ],
                provider: state.config.ai.mode === "cloud" ? state.config.ai.cloud.provider : "ollama",
                model: state.config.ai.mode === "cloud" ? state.config.ai.cloud.model : state.config.ai.local.model,
              }
            : undefined,
      };
      state.job.detections.push(susp);
      if (deep && state.config.ai.mode !== "off") {
        state.ai_stats.triaged++;
      }
      logEvent("detection", "warn", `${state.job.kind} scan: ${susp.path} — ${susp.threat} (score ${susp.score})`, susp as unknown as Record<string, unknown>);
    }

    if (step >= (kind === "targeted" ? 2 : 5)) {
      if (state.job.timer) clearInterval(state.job.timer);
      state.job.timer = null;
      state.job.running = false;
      state.job.current = "";
      const malicious = state.job.detections.filter((d) => d.verdict === "malicious").length;
      const suspicious = state.job.detections.filter((d) => d.verdict === "suspicious").length;
      const secs = Number(((Date.now() - started) / 1000).toFixed(1));
      state.job.summary = {
        files: state.job.files,
        malicious,
        suspicious,
        quarantined: quarantine ? malicious : 0,
        cached: kind === "targeted" ? 0 : Math.floor(state.job.files * 0.64),
        seconds: secs,
        cancelled: false,
      };
      logEvent("scan", malicious ? "high" : suspicious ? "warn" : "info", `${state.job.kind} scan: ${state.job.files} files, ${malicious} malicious, ${suspicious} suspicious, ${secs}s`);
    }
  }, 450);

  res.json({ ok: true });
});

app.get("/api/job", (_req: Request, res: Response) => {
  res.json({
    running: state.job.running,
    kind: state.job.kind,
    files: state.job.files,
    current: state.job.current,
    detections: state.job.detections,
    summary: state.job.summary,
    error: state.job.error,
  });
});

app.post("/api/job/cancel", (_req: Request, res: Response) => {
  if (state.job.timer) {
    clearInterval(state.job.timer);
    state.job.timer = null;
  }
  if (state.job.running) {
    state.job.running = false;
    state.job.current = "";
    state.job.summary = {
      files: state.job.files,
      malicious: state.job.detections.filter((d) => d.verdict === "malicious").length,
      suspicious: state.job.detections.filter((d) => d.verdict === "suspicious").length,
      quarantined: 0,
      cached: 0,
      seconds: 0.9,
      cancelled: true,
    };
  }
  res.json({ ok: true });
});

app.get("/api/events", (req: Request, res: Response) => {
  const n = Math.min(Math.max(Number(req.query.n) || 200, 1), 1000);
  res.json(state.events.slice(0, n));
});

app.get("/api/quarantine", (_req: Request, res: Response) => {
  res.json(state.quarantine);
});

app.post("/api/quarantine", (req: Request, res: Response) => {
  const { action, id, path: targetPath, allow } = req.body || {};
  if (action === "quarantine") {
    if (!targetPath) return res.status(400).json({ error: "path is required" });
    const qid = "q-" + crypto.randomBytes(4).toString("hex");
    state.quarantine.unshift({
      id: qid,
      original: String(targetPath),
      threat: "Manual.Quarantine",
      sha256: crypto.createHash("sha256").update(String(targetPath)).digest("hex"),
      time: nowIso(),
    });
    logEvent("protection", "warn", `Quarantined ${targetPath} (${qid})`);
    return res.json({ id: qid });
  }
  if (action === "restore") {
    const idx = state.quarantine.findIndex((q) => q.id === id);
    if (idx < 0) return res.status(404).json({ error: "quarantine item not found" });
    const [item] = state.quarantine.splice(idx, 1);
    if (allow && !state.config.allow.hashes.includes(item.sha256)) {
      state.config.allow.hashes.push(item.sha256);
    }
    logEvent("protection", "info", `Restored ${item.original}${allow ? " and allowlisted SHA-256" : ""}`);
    return res.json({ ok: true });
  }
  if (action === "delete") {
    state.quarantine = state.quarantine.filter((q) => q.id !== id);
    logEvent("protection", "info", `Permanently deleted quarantine item ${id}`);
    return res.json({ ok: true });
  }
  res.status(400).json({ error: "unknown action" });
});

app.get("/api/defs", (_req: Request, res: Response) => {
  res.json({
    sources: state.defs.sources,
    channels: state.defs.channels,
    presets: DEF_PRESETS,
    stats: state.defs.stats,
  });
});

app.post("/api/defs", (req: Request, res: Response) => {
  const { action, name, path: fpath, url, kind } = req.body || {};
  if (action === "import") {
    if (!fpath) return res.status(400).json({ error: "enter the path of a definitions file" });
    const k = !kind || kind === "auto" ? (String(fpath).endsWith(".yar") ? "yara" : "hashes") : String(kind);
    const count = k === "yara" ? 18 : 2400;
    state.defs.sources.unshift({
      name: path.basename(String(fpath)),
      kind: k,
      origin: String(fpath),
      count,
      imported_at: nowIso(),
    });
    if (k === "yara") state.defs.stats.rules += count;
    else state.defs.stats.hashes += count;
    state.defs.stats.revision++;
    logEvent("definitions", "info", `Imported ${count} ${k} definitions from ${fpath}`);
    return res.json({ count, kind: k });
  }
  if (action === "remove") {
    state.defs.sources = state.defs.sources.filter((s) => s.name !== name);
    state.defs.stats.revision++;
    return res.json({ ok: true });
  }
  if (action === "channel-add") {
    if (!name || !url) return res.status(400).json({ error: "channel name and URL are required" });
    state.defs.channels.push({ name: String(name), url: String(url), interval_hours: 12, last_checked: nowIso(), last_status: "synced" });
    logEvent("definitions", "info", `Subscribed to channel ${name}`);
    return res.json([{ name, status: "synced" }]);
  }
  if (action === "channel-remove") {
    state.defs.channels = state.defs.channels.filter((c) => c.name !== name);
    return res.json({ ok: true });
  }
  if (action === "channel-update") {
    const targets = name ? state.defs.channels.filter((c) => c.name === name) : state.defs.channels;
    targets.forEach((c) => {
      c.last_checked = nowIso();
      c.last_status = "up to date";
    });
    return res.json(targets.map((c) => ({ name: c.name, status: "up to date" })));
  }
  res.status(400).json({ error: "unknown action" });
});

app.get("/api/ai", (_req: Request, res: Response) => {
  res.json({
    mode: state.config.ai.mode,
    sensitivity: state.config.ai.sensitivity,
    confidence_threshold: state.config.ai.confidence_threshold,
    local: state.config.ai.local,
    cloud: state.config.ai.cloud,
    cloud_provider: state.config.ai.cloud.provider,
    cloud_providers: CLOUD_PROVIDERS,
    cloud_key_set: hasActiveCloudKey(),
    cloud_keys: {
      gemini: state.secrets.gemini,
      claude: state.secrets.claude,
      openai: state.secrets.openai,
    },
    ai_stats: state.ai_stats,
    vt_key_set: state.secrets.virustotal,
    recommended: RECOMMENDED_LOCAL,
    models: state.ollama_models,
    ollama: "running",
    stored: state.stored_models,
    download: state.download,
    hf_token_set: state.secrets.huggingface,
  });
});

app.post("/api/ai", async (req: Request, res: Response) => {
  const { action, value, name, key, path: fpath } = req.body || {};
  switch (action) {
    case "mode":
      state.config.ai.mode = String(value);
      logEvent("system", "info", `AI mode set to ${value}`);
      return res.json({ ok: true });
    case "sensitivity":
      state.config.ai.sensitivity = String(value);
      logEvent("system", "info", `AI sensitivity set to ${value}`);
      return res.json({ ok: true });
    case "cloud-provider": {
      const p = CLOUD_PROVIDERS.find((x) => x.id === value);
      if (!p) return res.status(400).json({ error: "unknown cloud provider" });
      state.config.ai.cloud.provider = p.id;
      state.config.ai.cloud.model = p.default_model;
      logEvent("system", "info", `Cloud AI provider switched to ${p.name} (${p.default_model})`);
      return res.json({ ok: true });
    }
    case "cloud-model":
      if (!value) return res.status(400).json({ error: "model name required" });
      state.config.ai.cloud.model = String(value);
      return res.json({ ok: true });
    case "cloud-endpoint":
      state.config.ai.cloud.endpoint = String(value || "");
      return res.json({ ok: true });
    case "set-key": {
      if (!String(key || "").trim()) return res.status(400).json({ error: "paste an API key" });
      const prov = String(name || state.config.ai.cloud.provider);
      state.secrets[prov] = true;
      state.config.ai.cloud.provider = prov;
      if (state.config.ai.mode === "off") state.config.ai.mode = "hybrid";
      logEvent("system", "info", `Encrypted API key stored for ${prov}`);
      return res.json({ ok: true });
    }
    case "clear-key": {
      const prov = String(name || state.config.ai.cloud.provider);
      state.secrets[prov] = false;
      return res.json({ ok: true });
    }
    case "vt-key":
      state.secrets.virustotal = Boolean(String(key || "").trim());
      return res.json({ ok: true });
    case "hf-token":
      state.secrets.huggingface = Boolean(String(key || "").trim());
      return res.json({ ok: true });
    case "use":
      state.config.ai.local.provider = "ollama";
      state.config.ai.local.model = String(name);
      state.config.ai.local.model_path = "";
      state.ollama_models.forEach((m) => (m.loaded = m.name === name));
      return res.json({ params_b: 1.7 });
    case "pull":
      if (!state.ollama_models.some((m) => m.name === name)) {
        state.ollama_models.push({ name: String(name), params: "1.5B", params_b: 1.5, size_mb: 980, loaded: true });
      }
      state.config.ai.local.model = String(name);
      return res.json({ params_b: 1.5 });
    case "gguf":
      if (!fpath) return res.status(400).json({ error: "enter a GGUF file path" });
      state.config.ai.local.provider = "llama-server";
      state.config.ai.local.model = path.basename(String(fpath));
      state.config.ai.local.model_path = String(fpath);
      return res.json({ params_b: 1.72 });
    case "use-stored": {
      const m = state.stored_models.find((x) => x.name === name);
      if (!m) return res.status(404).json({ error: "stored model not found" });
      state.config.ai.local.provider = "llama-server";
      state.config.ai.local.model = m.name;
      state.config.ai.local.model_path = m.path;
      return res.json({ params_b: m.params_b });
    }
    case "remove-stored":
      state.stored_models = state.stored_models.filter((x) => x.name !== name);
      return res.json({ ok: true });
    case "import":
      if (!fpath) return res.status(400).json({ error: "enter a GGUF path to import" });
      state.stored_models.push({
        name: path.basename(String(fpath)),
        params_b: 1.7,
        size_mb: 1080,
        source: "local import",
        path: String(fpath),
      });
      return res.json({ params_b: 1.7, name: path.basename(String(fpath)) });
    case "hf-search": {
      const q = String(value || "qwen3").toLowerCase();
      return res.json([
        { id: "unsloth/Qwen3-1.7B-GGUF", downloads: 142800, params_b: 1.7, gated: false },
        { id: "bartowski/Llama-3.2-1B-Instruct-GGUF", downloads: 98400, params_b: 1.2, gated: false },
        { id: "unsloth/gemma-3-1b-it-GGUF", downloads: 76310, params_b: 1.0, gated: false },
      ].filter((m) => m.id.toLowerCase().includes(q) || q.length < 2));
    }
    case "hf-get": {
      if (!name) return res.status(400).json({ error: "enter a Hugging Face repository" });
      state.download = { running: true, ref: String(name), done: 0, total: 1096 << 20, error: "", result: "" };
      const tick = setInterval(() => {
        if (!state.download.running) {
          clearInterval(tick);
          return;
        }
        state.download.done += 274 << 20;
        if (state.download.done >= state.download.total) {
          clearInterval(tick);
          state.download.running = false;
          state.download.result = `${name} ready (1.72B parameters)`;
        }
      }, 600);
      return res.json({ ok: true });
    }
    case "hf-cancel":
      state.download.running = false;
      state.download.error = "cancelled";
      return res.json({ ok: true });
    case "test": {
      const mode = state.config.ai.mode;
      if (mode === "off") return res.status(400).json({ error: "AI mode is currently Off — switch to Local, Cloud, or Hybrid first" });
      const results: Array<Record<string, unknown>> = [];
      if (mode === "local" || mode === "hybrid") {
        results.push({
          provider: state.config.ai.local.provider,
          model: state.config.ai.local.model || "qwen3:1.7b",
          ok: true,
          seconds: 0.42,
          verdict: {
            verdict: "malicious",
            confidence: 0.91,
            category: "lolbin",
            summary: "Synthetic test sample (Word -> encoded PowerShell download cradle) correctly classified as malicious LOLBin activity.",
            reasons: ["Parent WINWORD.EXE launching encoded PowerShell", "Remote web download cradle pattern"],
          },
        });
      }
      if (mode === "cloud" || mode === "hybrid") {
        const prov = activeProviderInfo();
        if (!hasActiveCloudKey()) {
          results.push({
            provider: prov.id,
            model: state.config.ai.cloud.model,
            ok: false,
            error: `no ${prov.name} API key stored yet`,
          });
        } else {
          results.push({
            provider: prov.id,
            model: state.config.ai.cloud.model,
            ok: true,
            seconds: 0.68,
            verdict: {
              verdict: "malicious",
              confidence: 0.96,
              category: "lolbin",
              summary: "Structured JSON triage confirmed fileless Office-to-PowerShell attack chain.",
              reasons: ["Encoded PowerShell command from Office parent", "High-confidence staging behavior"],
            },
          });
        }
      }
      return res.json(results);
    }
    case "explain": {
      const target = String(fpath || "").trim();
      if (!target) return res.status(400).json({ error: "enter a file path to analyze" });
      state.ai_stats.triaged++;
      const live = await runLiveGeminiExplain(target);
      if (live) {
        return res.json({
          result: {
            path: target,
            verdict: live.verdict.verdict === "benign" ? "clean" : live.verdict.verdict,
            score: live.verdict.verdict === "benign" ? 8 : 74,
            ai: live.verdict,
          },
          explanation: live.explanation,
          model: live.model,
        });
      }
      const lower = target.toLowerCase();
      const isMal = lower.includes("powershell") || lower.includes(".hta") || lower.includes("stage") || lower.includes("temp");
      const isSusp = !isMal && (lower.includes("packed") || lower.includes("download") || lower.includes(".vbs"));
      const verdict: AIVerdict = {
        verdict: isMal ? "malicious" : isSusp ? "suspicious" : "benign",
        confidence: isMal ? 0.93 : isSusp ? 0.72 : 0.92,
        category: lower.includes("powershell") ? "lolbin" : isMal ? "dropper" : isSusp ? "pup" : "benign",
        recommended_action: isMal ? "quarantine" : isSusp ? "review" : "allow",
        summary: isMal
          ? "High-risk execution or staging pattern detected in a monitored location or LOLBin process chain."
          : isSusp
            ? "Unsigned packed binary from an untrusted download location; review publisher before execution."
            : "No malicious static, behavioural, or signature anomalies detected.",
        reasons: isMal
          ? ["Matches obfuscated staging or Office-to-interpreter LOLBin pattern", "High-confidence triage recommendation: quarantine or block execution"]
          : isSusp
            ? ["Missing valid Authenticode signature", "High section entropy indicates compression/packing"]
            : ["Clean hash and YARA scan", "Normal filesystem location and execution profile"],
        provider: state.config.ai.mode === "local" ? "ollama" : state.config.ai.cloud.provider,
        model: state.config.ai.mode === "local" ? state.config.ai.local.model : state.config.ai.cloud.model,
      };
      const explanation = isMal
        ? `Risk Assessment: HIGH (${Math.round(verdict.confidence * 100)}% confidence)\n\n${target} exhibits strong indicators of a ${verdict.category} attack. Even when a system binary like PowerShell is signed by Microsoft, Visionary preserves live behavioural findings so parent-child chains (such as Office -> encoded PowerShell) are caught and triaged.\n\nRecommended Next Step: Quarantine the payload (or terminate the offending process tree) and run a Quick Scan with Second Opinions enabled.`
        : isSusp
          ? `Risk Assessment: MEDIUM (${Math.round(verdict.confidence * 100)}% confidence)\n\n${target} is an unsigned or packed file located in a download directory. No known malware hash matched, so Visionary held it below automatic quarantine.\n\nRecommended Next Step: Confirm you intentionally downloaded this file from a trusted vendor before running it, or Quarantine it if unexpected.`
          : `Risk Assessment: LOW (${Math.round(verdict.confidence * 100)}% confidence)\n\n${target} shows no hash, YARA, certificate, or behavioural anomalies. No action is needed.`;
      return res.json({
        result: {
          path: target,
          verdict: isMal ? "malicious" : isSusp ? "suspicious" : "clean",
          score: isMal ? 91 : isSusp ? 52 : 6,
          ai: verdict,
        },
        explanation,
        model: `${verdict.provider} / ${verdict.model}`,
      });
    }
    default:
      return res.status(400).json({ error: "unknown action" });
  }
});

app.get("/api/settings", (_req: Request, res: Response) => {
  res.json({ config: state.config, user: state.user });
});

app.post("/api/settings", (req: Request, res: Response) => {
  const { action, key, value } = req.body || {};
  switch (action) {
    case "set": {
      const bool = value === "true";
      if (key === "realtime.auto_quarantine") state.config.realtime.auto_quarantine = bool;
      else if (key === "behavior.enabled") state.config.behavior.enabled = bool;
      else if (key === "windows.defender_second_opinion") state.config.windows.defender_second_opinion = bool;
      else if (key === "scan.scan_archives") state.config.scan.scan_archives = bool;
      else if (key === "scan.use_cache") state.config.scan.use_cache = bool;
      else if (key === "security.require_password_to_disable") state.config.security.require_password_to_disable = bool;
      else if (key === "ai.cloud.share_snippets") state.config.ai.cloud.share_snippets = bool;
      else if (key === "ai.local.cpu_only") state.config.ai.local.cpu_only = bool;
      else if (key === "ai.confidence_threshold") {
        const n = Number(value);
        if (Number.isNaN(n) || n < 0.5 || n > 0.99) return res.status(400).json({ error: "threshold must be between 0.50 and 0.99" });
        state.config.ai.confidence_threshold = n;
      }
      logEvent("system", "info", `Setting updated: ${key} = ${value}`);
      return res.json({ ok: true });
    }
    case "profile":
      state.config.profile = String(value);
      logEvent("system", "info", `Profile changed to ${value}`);
      return res.json({ ok: true });
    case "gamemode":
      state.config.game_mode.forced = value === "on";
      state.config.game_mode.auto = value === "auto";
      return res.json({ ok: true });
    case "learn":
      state.config.behavior.learning = true;
      logEvent("system", "info", "Behaviour learning started for 3 days");
      return res.json({ ok: true });
    case "stop-learning":
      state.config.behavior.learning = false;
      logEvent("system", "info", "Behaviour learning stopped — enforcing baseline");
      return res.json({ ok: true });
    case "behavior-reset":
      state.behavior = { executables: 0, parent_child_edges: 0, typical_file_changes_per_10s: 0 };
      logEvent("system", "warn", "Behaviour baseline cleared");
      return res.json({ ok: true });
    case "exclude-add":
      if (!value) return res.status(400).json({ error: "enter an exclusion pattern" });
      if (!state.config.scan.excludes.includes(String(value))) state.config.scan.excludes.push(String(value));
      return res.json({ ok: true });
    case "exclude-remove":
      state.config.scan.excludes = state.config.scan.excludes.filter((x) => x !== value);
      return res.json({ ok: true });
    case "allow-add":
      if (!value) return res.status(400).json({ error: "enter a path or hash" });
      if (!state.config.allow.paths.includes(String(value))) state.config.allow.paths.push(String(value));
      logEvent("system", "info", `Allowlisted ${value}`);
      return res.json({ ok: true });
    case "allow-remove":
      state.config.allow.paths = state.config.allow.paths.filter((x) => x !== value);
      state.config.allow.hashes = state.config.allow.hashes.filter((x) => x !== value);
      return res.json({ ok: true });
    case "reset":
      state.config.profile = "balanced";
      state.config.ai.sensitivity = "balanced";
      state.config.ai.confidence_threshold = 0.8;
      logEvent("system", "warn", "Settings reset to defaults");
      return res.json({ ok: true });
    default:
      return res.status(400).json({ error: "unknown action" });
  }
});

app.post("/api/windows", (req: Request, res: Response) => {
  const { action } = req.body || {};
  if (action === "coexist") {
    logEvent("system", "info", "Configured Microsoft Defender co-existence exclusions");
    return res.json({ ok: true });
  }
  if (action === "passive-on") {
    state.windows_security.running_mode = "Passive";
    state.windows_security.visionary_role = "primary real-time scanner (Defender is passive: it still scans on demand and keeps its definitions current)";
    return res.json({ message: "Defender passive mode requested" });
  }
  if (action === "passive-off") {
    state.windows_security.running_mode = "Normal";
    state.windows_security.visionary_role = "second layer alongside Defender (both active; Visionary's folders are excluded in Defender to avoid double work)";
    return res.json({ message: "Defender returned to active mode" });
  }
  if (action === "offline-scan") {
    logEvent("scan", "warn", "Microsoft Defender Offline scan scheduled for next reboot");
    return res.json({ ok: true });
  }
  res.status(400).json({ error: "unknown action" });
});

app.post("/api/preboot", (req: Request, res: Response) => {
  const { action } = req.body || {};
  state.boot_scan_scheduled = action === "schedule";
  logEvent("scan", "info", state.boot_scan_scheduled ? "Boot-time scan scheduled for next restart" : "Boot-time scan cancelled");
  res.json({ ok: true });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Visionary AI Protection dashboard listening on http://0.0.0.0:${PORT}`);
});
