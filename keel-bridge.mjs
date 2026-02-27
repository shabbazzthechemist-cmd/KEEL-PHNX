// keel-bridge.mjs (v0.7.0) — adds Inspector UI + Handoff Packet export
import http from "node:http";
import { promises as fsp } from "node:fs";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const HOST = process.env.KEEL_HOST || "127.0.0.1";
const PORT = Number(process.env.KEEL_PORT || "42069");
const KEEL_DIR = process.env.KEEL_DIR || path.join(__dirname, "runs");
const KEEL_TOKEN = process.env.KEEL_TOKEN || "";
const MAX_BODY_BYTES = Number(process.env.KEEL_MAX_BODY_BYTES || 2_000_000);
const VERSION = "v0.7.1";

const LOCK_PATH = path.join(KEEL_DIR, ".bridge.lock");
let LOCK_OWNED = false;

const ALLOWED_EVENT_TYPES = new Set([
  "run_started",
  "user_input",
  "agent_output",
  "decision_recorded",
  "dispute_open",
  "dispute_resolve",
  "state_updated",
  "artifact_added",
  "audit_generated",
  "run_closed",
  "proposal",
  "event_rejected",
  "challenge",
  "test",
  "recognition_event",
  "handoff_packet_exported",
  "handoff_packet_export_failed",
  "handoff_validated",
  "handoff_rejected",
  "run_forked",
]);

const EXPORT_PRESETS = {
  tail200: {
    mode: "tail",
    tail_events: 200,
    kinds: [
      "message",
      "decision",
      "dispute_open",
      "dispute_resolve",
      "hold",
      "release",
      "discharge",
      "recognition_event",
      "session_close",
      "event_rejected",
      "challenge",
    ],
    redact_url: true,
  },
  decisions_disputes: {
    mode: "tail",
    tail_events: 500,
    kinds: [
      "decision",
      "dispute_open",
      "dispute_resolve",
      "commitment_create",
      "commitment_amend",
      "recognition_event",
      "session_close",
      "event_rejected",
    ],
    redact_url: true,
  },
  alarms_only: {
    mode: "tail",
    tail_events: 500,
    kinds: ["discharge", "challenge", "event_rejected", "dispute_open"],
    redact_url: true,
  },
};
const EXPORT_PRESET_NAMES = new Set(["tail200", "decisions_disputes", "alarms_only", "custom"]);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function nowIso() {
  return new Date().toISOString();
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function stableStringify(obj) {
  const seen = new WeakSet();
  const sorter = (v) => {
    if (v && typeof v === "object") {
      if (seen.has(v)) throw new Error("cycle in json");
      seen.add(v);
      if (Array.isArray(v)) return v.map(sorter);
      const out = {};
      for (const k of Object.keys(v).sort()) out[k] = sorter(v[k]);
      return out;
    }
    return v;
  };
  return JSON.stringify(sorter(obj));
}

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function ulid(ts = Date.now()) {
  let t = Number(ts);
  const timeChars = new Array(10);
  for (let i = 9; i >= 0; i--) {
    timeChars[i] = ULID_ALPHABET[t % 32];
    t = Math.floor(t / 32);
  }
  const rand = crypto.randomBytes(16);
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; out.length < 16; i++) {
    value = (value << 8) | rand[i];
    bits += 8;
    while (bits >= 5 && out.length < 16) {
      bits -= 5;
      out += ULID_ALPHABET[(value >> bits) & 31];
    }
  }
  return `${timeChars.join("")}${out}`;
}

function isObject(v) {
  return v && typeof v === "object" && !Array.isArray(v);
}

function isStringArray(v) {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

function normalizeActor(actor_id, actor) {
  if (isObject(actor) && typeof actor.type === "string" && typeof actor.id === "string") {
    return {
      type: actor.type,
      id: actor.id,
      name: typeof actor.name === "string" ? actor.name : actor.id,
    };
  }
  const [maybeType] = String(actor_id || "").split(":");
  const type = ["human", "agent", "system"].includes(maybeType) ? maybeType : "system";
  return { type, id: String(actor_id || "unknown"), name: String(actor_id || "unknown") };
}

async function mkdirp(p) {
  await fsp.mkdir(p, { recursive: true });
}

async function readJson(p) {
  const s = await fsp.readFile(p, "utf-8");
  return JSON.parse(s);
}

async function writeJsonAtomic(p, obj) {
  const dir = path.dirname(p);
  const tmp = path.join(dir, `.tmp.${path.basename(p)}.${crypto.randomBytes(6).toString("hex")}`);
  await fsp.writeFile(tmp, JSON.stringify(obj, null, 2) + "\n", "utf-8");
  await fsp.rename(tmp, p);
}

function sendJson(res, status, obj) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}

function sendText(res, status, text, contentType = "text/plain; charset=utf-8") {
  res.writeHead(status, { "content-type": contentType });
  res.end(text);
}

function assertLocalOnly(req) {
  const ra = req.socket.remoteAddress;
  if (ra && !["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(ra)) {
    throw new HttpError(403, "forbidden");
  }
}

function requireToken(req) {
  if (!KEEL_TOKEN) throw new HttpError(500, "KEEL_TOKEN is not set");
  const tok = req.headers["x-keel-token"];
  if (tok !== KEEL_TOKEN) throw new HttpError(401, "unauthorized");
}

async function readBodyJson(req) {
  const buf = await new Promise((resolve, reject) => {
    let bytes = 0;
    const chunks = [];
    req.on("data", (c) => {
      bytes += c.length;
      if (bytes > MAX_BODY_BYTES) {
        reject(new HttpError(413, `body too large > ${MAX_BODY_BYTES}`));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });

  const s = buf.toString("utf-8").trim();
  if (!s) return {};
  try {
    return JSON.parse(s);
  } catch {
    throw new HttpError(400, "invalid JSON");
  }
}

function validateRunId(run_id) {
  if (typeof run_id !== "string") return false;
  if (run_id.length < 6 || run_id.length > 128) return false;
  if (!/^[a-zA-Z0-9._-]+$/.test(run_id)) return false;
  return true;
}

function validateEventCore(evt) {
  if (!evt || typeof evt !== "object") return "event must be object";
  if (!ALLOWED_EVENT_TYPES.has(evt.type)) return `type not allowed: ${evt.type}`;
  if (typeof evt.actor_id !== "string" || evt.actor_id.length < 1) return "actor_id required";
  if (typeof evt.payload === "undefined") return "payload required";
  if (evt.links && !Array.isArray(evt.links)) return "links must be array";
  if (evt.refs && !Array.isArray(evt.refs)) return "refs must be array";
  if (evt.actor && (!isObject(evt.actor) || typeof evt.actor.type !== "string" || typeof evt.actor.id !== "string")) {
    return "actor must be object with type/id";
  }
  if (evt.source && typeof evt.source !== "string") return "source must be string";
  if (evt.transform && typeof evt.transform !== "object" && evt.transform !== null) return "transform must be object or null";
  if (evt.type === "dispute_open") return validateDisputeOpenPayload(evt.payload);
  if (evt.type === "dispute_resolve") return validateDisputeResolvePayload(evt.payload);
  if (evt.type === "event_rejected") return validateEventRejectedPayload(evt.payload);
  if (evt.type === "recognition_event") return validateRecognitionPayload(evt);
  if (evt.type === "handoff_packet_exported") return validateExportedPayload(evt.payload);
  if (evt.type === "handoff_packet_export_failed") return validateExportFailedPayload(evt.payload);
  if (evt.type === "handoff_validated") return validateHandoffValidationPayload(evt.payload, "VALID");
  if (evt.type === "handoff_rejected") return validateHandoffValidationPayload(evt.payload, "INVALID");
  return null;
}

function validateDisputeOpenPayload(payload) {
  if (!isObject(payload)) return "dispute_open.payload must be object";
  if (typeof payload.dispute_id !== "string" || !payload.dispute_id) return "dispute_open.dispute_id required";
  if (typeof payload.target_key !== "string" || !payload.target_key) return "dispute_open.target_key required";
  if (typeof payload.issue !== "string" || !payload.issue.trim()) return "dispute_open.issue required";
  return null;
}

function validateDisputeResolvePayload(payload) {
  if (!isObject(payload)) return "dispute_resolve.payload must be object";
  if (typeof payload.dispute_id !== "string" || !payload.dispute_id) return "dispute_resolve.dispute_id required";
  if (typeof payload.target_key !== "string" || !payload.target_key) return "dispute_resolve.target_key required";
  if (payload.resolution != null && typeof payload.resolution !== "string") {
    return "dispute_resolve.resolution must be string";
  }
  return null;
}

function validateEventRejectedPayload(payload) {
  if (!isObject(payload)) return "event_rejected.payload must be object";
  if (typeof payload.proposed_kind !== "string" || !payload.proposed_kind) {
    return "event_rejected.proposed_kind required";
  }
  if (typeof payload.reason_code !== "string" || !payload.reason_code) {
    return "event_rejected.reason_code required";
  }
  if (typeof payload.reason !== "string" || !payload.reason) {
    return "event_rejected.reason required";
  }
  if (!isStringArray(payload.violated_commitment_ids || [])) {
    return "event_rejected.violated_commitment_ids must be string[]";
  }
  if (payload.proposed_event_hash != null && typeof payload.proposed_event_hash !== "string") {
    return "event_rejected.proposed_event_hash must be string";
  }
  return null;
}

function validationTargetKeyFromPayload(payload) {
  if (!isObject(payload)) return null;
  if (!isObject(payload.target)) return null;
  const target = payload.target;
  if (typeof target.packet_hash !== "string" || !target.packet_hash) return null;
  if (target.export_id == null) return `hash:${target.packet_hash}`;
  if (typeof target.export_id !== "string" || !target.export_id) return null;
  return `export:${target.export_id}`;
}

function validateHandoffValidationPayload(payload, expectedVerdict) {
  if (!isObject(payload)) return "handoff_validation.payload must be object";
  const prohibited = ["proposals", "next_moves", "recommendations"];
  for (const key of prohibited) {
    if (Object.prototype.hasOwnProperty.call(payload, key)) {
      return `handoff_validation non-procedural field not allowed: ${key}`;
    }
  }

  const targetKey = validationTargetKeyFromPayload(payload);
  if (!targetKey) return "handoff_validation.target invalid";

  if (!isObject(payload.validator)) return "handoff_validation.validator required";
  if (typeof payload.validator.type !== "string" || !payload.validator.type) {
    return "handoff_validation.validator.type required";
  }
  if (typeof payload.validator.id !== "string" || !payload.validator.id) {
    return "handoff_validation.validator.id required";
  }
  if (!isObject(payload.schema_check)) return "handoff_validation.schema_check required";
  if (!isObject(payload.hash_check)) return "handoff_validation.hash_check required";
  if (!isObject(payload.chain_check)) return "handoff_validation.chain_check required";
  if (!isObject(payload.anchor_inventory)) return "handoff_validation.anchor_inventory required";
  if (typeof payload.computed_hash !== "string" || !payload.computed_hash) {
    return "handoff_validation.computed_hash required";
  }
  if (!isStringArray(payload.warnings || [])) return "handoff_validation.warnings must be string[]";
  if (payload.verdict !== expectedVerdict) {
    return `handoff_validation.verdict must be ${expectedVerdict}`;
  }
  if (expectedVerdict === "INVALID") {
    if (!isStringArray(payload.error_codes || []) || (payload.error_codes || []).length < 1) {
      return "handoff_rejected.error_codes must be non-empty string[]";
    }
  } else if (payload.error_codes != null && !isStringArray(payload.error_codes)) {
    return "handoff_validated.error_codes must be string[] when present";
  }
  return null;
}

function validateRecognitionPayload(evt) {
  const p = evt.payload;
  if (!isObject(p)) return "recognition_event.payload must be object";
  if (typeof p.marker_id !== "string" || !p.marker_id) return "recognition_event.marker_id required";
  if (!isObject(p.bind)) return "recognition_event.bind required";
  if (!["turn", "hold"].includes(p.bind.type)) return "recognition_event.bind.type must be turn|hold";
  if (typeof p.bind.id !== "string" || !p.bind.id) return "recognition_event.bind.id required";
  if (!Array.isArray(p.why) || p.why.length < 1 || p.why.some((x) => typeof x !== "string" || !x.trim())) {
    return "recognition_event.why must have at least one non-empty string";
  }
  if (p.signals != null && !isObject(p.signals)) return "recognition_event.signals must be object";
  if (p.signals?.latency_ms != null && !Number.isFinite(Number(p.signals.latency_ms))) {
    return "recognition_event.signals.latency_ms must be number";
  }
  if (p.signals?.dispute_severity != null && !["low", "med", "high", null].includes(p.signals.dispute_severity)) {
    return "recognition_event.signals.dispute_severity must be low|med|high|null";
  }
  if (p.signals?.confidence_drop != null && !Number.isFinite(Number(p.signals.confidence_drop))) {
    return "recognition_event.signals.confidence_drop must be number";
  }
  if (!["none", "prompt", "auto"].includes(p.export_policy)) {
    return "recognition_event.export_policy must be none|prompt|auto";
  }
  if (
    p.requested_export_preset != null &&
    !["tail200", "decisions_disputes", "alarms_only", null].includes(p.requested_export_preset)
  ) {
    return "recognition_event.requested_export_preset invalid";
  }
  if (p.bind.type === "turn" && (!Array.isArray(evt.refs) || evt.refs.length < 1)) {
    return "recognition_event.refs must include turn-linked event ids";
  }
  return null;
}

function validateSelectionShape(selection) {
  if (!isObject(selection)) return "selection must be object";
  if (!["tail", "range"].includes(selection.mode)) return "selection.mode must be tail|range";
  if (selection.mode === "tail" && !Number.isFinite(Number(selection.tail_events))) return "selection.tail_events required";
  if (selection.mode === "range") {
    if (!Number.isFinite(Number(selection.seq_start))) return "selection.seq_start required";
    if (!Number.isFinite(Number(selection.seq_end))) return "selection.seq_end required";
  }
  if (selection.kinds != null && !isStringArray(selection.kinds)) return "selection.kinds must be string[]";
  return null;
}

function validateExportedPayload(payload) {
  if (!isObject(payload)) return "handoff_packet_exported.payload must be object";
  if (typeof payload.export_id !== "string" || !payload.export_id) return "handoff_packet_exported.export_id required";
  if (payload.source_marker_id != null && typeof payload.source_marker_id !== "string") {
    return "handoff_packet_exported.source_marker_id must be string|null";
  }
  if (!EXPORT_PRESET_NAMES.has(payload.preset)) return "handoff_packet_exported.preset invalid";
  const selErr = validateSelectionShape(payload.selection);
  if (selErr) return `handoff_packet_exported.${selErr}`;
  if (!isObject(payload.redactions) || typeof payload.redactions.remove_url !== "boolean") {
    return "handoff_packet_exported.redactions.remove_url required";
  }
  if (typeof payload.packet_hash !== "string" || !payload.packet_hash) return "handoff_packet_exported.packet_hash required";
  if (!isObject(payload.packet_seq_range)) return "handoff_packet_exported.packet_seq_range required";
  if (!Number.isFinite(Number(payload.packet_seq_range.start)) || !Number.isFinite(Number(payload.packet_seq_range.end))) {
    return "handoff_packet_exported.packet_seq_range.start/end required";
  }
  if (Number(payload.packet_seq_range.start) > Number(payload.packet_seq_range.end)) {
    return "handoff_packet_exported.packet_seq_range start must be <= end";
  }
  if (!isObject(payload.packet_chain)) return "handoff_packet_exported.packet_chain required";
  for (const k of ["start_prev_hash", "end_hash", "head_hash"]) {
    if (typeof payload.packet_chain[k] !== "string" || !payload.packet_chain[k]) {
      return `handoff_packet_exported.packet_chain.${k} required`;
    }
  }
  if (!Number.isFinite(Number(payload.bytes)) || Number(payload.bytes) <= 0) {
    return "handoff_packet_exported.bytes must be > 0";
  }
  if (payload.include_audit != null && typeof payload.include_audit !== "boolean") {
    return "handoff_packet_exported.include_audit must be boolean";
  }
  return null;
}

function validateExportFailedPayload(payload) {
  if (!isObject(payload)) return "handoff_packet_export_failed.payload must be object";
  if (typeof payload.export_id !== "string" || !payload.export_id) return "handoff_packet_export_failed.export_id required";
  if (payload.source_marker_id != null && typeof payload.source_marker_id !== "string") {
    return "handoff_packet_export_failed.source_marker_id must be string|null";
  }
  if (!EXPORT_PRESET_NAMES.has(payload.preset)) return "handoff_packet_export_failed.preset invalid";
  const selErr = validateSelectionShape(payload.selection);
  if (selErr) return `handoff_packet_export_failed.${selErr}`;
  if (!isObject(payload.redactions) || typeof payload.redactions.remove_url !== "boolean") {
    return "handoff_packet_export_failed.redactions.remove_url required";
  }
  if (typeof payload.error_code !== "string" || !payload.error_code) return "handoff_packet_export_failed.error_code required";
  if (typeof payload.error_message !== "string" || !payload.error_message) {
    return "handoff_packet_export_failed.error_message required";
  }
  if (payload.include_audit != null && typeof payload.include_audit !== "boolean") {
    return "handoff_packet_export_failed.include_audit must be boolean";
  }
  return null;
}

function runPaths(run_id) {
  const runDir = path.join(KEEL_DIR, run_id);
  return {
    runDir,
    eventsPath: path.join(runDir, "events.ndjson"),
    headPath: path.join(runDir, "HEAD.json"),
    metaPath: path.join(runDir, "meta.json"),
    auditPath: path.join(runDir, "audit.json"),
    statePath: path.join(runDir, "state.json"),
    artifactsDir: path.join(runDir, "artifacts"),
  };
}

function runExists(run_id) {
  if (!validateRunId(run_id)) return false;
  const p = runPaths(run_id);
  return fs.existsSync(p.runDir) && fs.existsSync(p.eventsPath) && fs.existsSync(p.headPath);
}

async function ensureRunCreated(run_id) {
  if (!validateRunId(run_id)) throw new HttpError(400, "invalid run_id");
  const p = runPaths(run_id);
  await mkdirp(p.runDir);
  await mkdirp(p.artifactsDir);

  if (!fs.existsSync(p.headPath)) {
    await writeJsonAtomic(p.headPath, {
      run_id,
      seq: 0,
      last_event_id: null,
      head_hash: "GENESIS",
      created_at: nowIso(),
      version: VERSION,
    });
  }
  if (!fs.existsSync(p.metaPath)) {
    await writeJsonAtomic(p.metaPath, { run_id, created_at: nowIso(), version: VERSION });
  }
  if (!fs.existsSync(p.eventsPath)) {
    await fsp.writeFile(p.eventsPath, "", "utf-8");
  }
  if (!fs.existsSync(p.statePath)) {
    await writeJsonAtomic(p.statePath, {
      run_id,
      version: VERSION,
      state: { goals: [], constraints: [], open_questions: [], decisions: [], artifacts: [] },
      derived_at: nowIso(),
    });
  }
  return p;
}

// -------- writer locking (single process per KEEL_DIR)
function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function acquireBridgeLock() {
  await mkdirp(KEEL_DIR);
  const payload = { pid: process.pid, started_at: nowIso(), host: HOST, port: PORT, version: VERSION };

  try {
    const fh = await fsp.open(LOCK_PATH, "wx");
    try {
      await fh.writeFile(JSON.stringify(payload, null, 2) + "\n", "utf-8");
    } finally {
      await fh.close();
    }
    LOCK_OWNED = true;
    return;
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
  }

  // lock exists
  let treatStale = false;
  try {
    const raw = await fsp.readFile(LOCK_PATH, "utf-8");
    const old = JSON.parse(raw);
    const oldPid = Number(old?.pid);
    if (oldPid && pidAlive(oldPid)) {
      const err = new Error(`bridge lock exists and PID ${oldPid} is alive (refusing start)`);
      err.code = "LIVE_LOCK";
      err.pid = oldPid;
      throw err;
    }
    treatStale = true;
  } catch (err) {
    if (err?.code === "LIVE_LOCK") throw err;
    treatStale = true; // unreadable/corrupt -> stale
  }

  if (!treatStale) throw new Error("lock handling reached impossible state");

  await fsp.unlink(LOCK_PATH).catch((e) => {
    if (e?.code !== "ENOENT") throw e;
  });

  const fh = await fsp.open(LOCK_PATH, "wx");
  try {
    await fh.writeFile(JSON.stringify(payload, null, 2) + "\n", "utf-8");
  } finally {
    await fh.close();
  }
  LOCK_OWNED = true;
}

async function releaseBridgeLock() {
  if (!LOCK_OWNED) return;
  try {
    const raw = await fsp.readFile(LOCK_PATH, "utf-8");
    const cur = JSON.parse(raw);
    if (Number(cur?.pid) === process.pid) await fsp.unlink(LOCK_PATH).catch(() => {});
  } catch {}
}

process.on("exit", () => {
  if (!LOCK_OWNED) return;
  try {
    const raw = fs.readFileSync(LOCK_PATH, "utf-8");
    const cur = JSON.parse(raw);
    if (Number(cur?.pid) === process.pid) fs.unlinkSync(LOCK_PATH);
  } catch {}
});
process.on("SIGINT", async () => {
  await releaseBridgeLock();
  process.exit(0);
});
process.on("SIGTERM", async () => {
  await releaseBridgeLock();
  process.exit(0);
});
process.on("uncaughtException", async () => {
  await releaseBridgeLock();
  process.exit(1);
});
process.on("unhandledRejection", async () => {
  await releaseBridgeLock();
  process.exit(1);
});

// -------- per-run in-process append lock
const runLocks = new Map();
async function withRunLock(run_id, fn) {
  const prior = runLocks.get(run_id) || Promise.resolve();
  let release;
  const next = new Promise((r) => (release = r));
  runLocks.set(run_id, prior.then(() => next).catch(() => next));

  try {
    await prior;
    return await fn();
  } finally {
    release();
    if (runLocks.get(run_id) === next) runLocks.delete(run_id);
  }
}

async function appendEvent(run_id, evtIn) {
  if (!runExists(run_id)) throw new HttpError(404, "run not found (start run first)");

  return withRunLock(run_id, async () => {
    const p = runPaths(run_id);
    const head = await readJson(p.headPath);

    const seq = Number(head.seq || 0) + 1;
    const ts = typeof evtIn.ts === "string" ? evtIn.ts : nowIso();
    const event_id =
      typeof evtIn.event_id === "string" && evtIn.event_id.length
        ? evtIn.event_id
        : `evt_${ts.replace(/[:.]/g, "-")}_${seq.toString().padStart(6, "0")}`;

    const core = {
      event_id,
      id: event_id,
      run_id,
      session_id: run_id,
      seq,
      ts,
      type: evtIn.type,
      kind: evtIn.type,
      actor_id: evtIn.actor_id,
      actor: normalizeActor(evtIn.actor_id, evtIn.actor),
      source: evtIn.source || "unknown",
      links: evtIn.links || [],
      refs: Array.isArray(evtIn.refs) ? evtIn.refs : [],
      transform: typeof evtIn.transform === "undefined" ? null : evtIn.transform,
      payload: evtIn.payload,
      prev_hash: head.head_hash || "GENESIS",
      prev: head.head_hash || "GENESIS",
    };

    const err = validateEventCore(core);
    if (err) throw new HttpError(400, err);
    const runErr = await validateEventAgainstRun(run_id, core);
    if (runErr) throw new HttpError(400, runErr);

    const canonical = stableStringify(core);
    const hash = sha256Hex(Buffer.from(`${core.prev_hash}\n${canonical}`, "utf-8"));

    const fullEvt = { ...core, hash };
    const line = JSON.stringify(fullEvt) + "\n";

    const fh = await fsp.open(p.eventsPath, "a");
    try {
      await fh.write(line, null, "utf-8");
      await fh.sync();
    } finally {
      await fh.close();
    }

    await writeJsonAtomic(p.headPath, {
      ...head,
      seq,
      last_event_id: event_id,
      head_hash: hash,
      updated_at: nowIso(),
      version: VERSION,
    });

    return { event_id, hash, prev_hash: core.prev_hash, seq };
  });
}

function isValidationType(type) {
  return type === "handoff_validated" || type === "handoff_rejected";
}

function validationProceduralHash(evtLike) {
  const canonical = stableStringify({
    type: evtLike.type,
    actor_id: evtLike.actor_id,
    payload: evtLike.payload,
  });
  return sha256Hex(Buffer.from(canonical, "utf-8"));
}

function proposedEventHash(evtLike) {
  const canonical = stableStringify({
    type: evtLike?.type,
    actor_id: evtLike?.actor_id,
    source: evtLike?.source || "unknown",
    refs: Array.isArray(evtLike?.refs) ? evtLike.refs : [],
    payload: evtLike?.payload,
  });
  return sha256Hex(Buffer.from(canonical, "utf-8"));
}

async function appendEventRejected(run_id, proposedEvent, reasonCode, reason, refs = [], violatedCommitmentIds = []) {
  return appendEvent(run_id, {
    type: "event_rejected",
    actor_id: "system:keel-bridge",
    source: "keel-bridge:validation_guard",
    refs,
    payload: {
      proposed_kind: String(proposedEvent?.type || "unknown"),
      reason_code: reasonCode,
      reason,
      violated_commitment_ids: violatedCommitmentIds,
      proposed_event_hash: proposedEventHash(proposedEvent),
    },
  });
}

function buildValidationVerdictObject(ev) {
  return {
    target: ev.payload.target,
    verdict: ev.payload.verdict,
    validator_actor_id: ev.actor_id,
    seq: ev.seq,
    event_id: ev.event_id,
    computed_hash: ev.payload.computed_hash,
    warnings: Array.isArray(ev.payload.warnings) ? ev.payload.warnings : [],
    error_codes: Array.isArray(ev.payload.error_codes) ? ev.payload.error_codes : [],
    schema_check: ev.payload.schema_check,
    hash_check: ev.payload.hash_check,
    chain_check: ev.payload.chain_check,
    anchor_inventory: ev.payload.anchor_inventory,
  };
}

async function handleValidationAppend(run_id, proposedEvent) {
  if (!runExists(run_id)) throw new HttpError(404, "run not found (start run first)");
  const coreErr = validateEventCore({
    type: proposedEvent?.type,
    actor_id: proposedEvent?.actor_id,
    payload: proposedEvent?.payload,
    refs: Array.isArray(proposedEvent?.refs) ? proposedEvent.refs : [],
    source: proposedEvent?.source || "unknown",
    transform: typeof proposedEvent?.transform === "undefined" ? null : proposedEvent.transform,
    links: Array.isArray(proposedEvent?.links) ? proposedEvent.links : [],
  });
  if (coreErr) throw new HttpError(400, coreErr);

  const targetKey = validationTargetKeyFromPayload(proposedEvent.payload);
  if (!targetKey) throw new HttpError(400, "handoff_validation.target invalid");

  const events = await readEvents(run_id);
  const incomingProcHash = validationProceduralHash(proposedEvent);

  const sameIdentity = events.filter((ev) => {
    if (!isValidationType(ev.type)) return false;
    if (ev.actor_id !== proposedEvent.actor_id) return false;
    return validationTargetKeyFromPayload(ev.payload) === targetKey;
  });

  if (sameIdentity.length) {
    const samePayload = sameIdentity.find((ev) => validationProceduralHash(ev) === incomingProcHash);
    if (samePayload) {
      return {
        mode: "idempotent",
        prior: {
          event_id: samePayload.event_id,
          seq: samePayload.seq,
          hash: samePayload.hash,
          target_key: targetKey,
        },
      };
    }

    return {
      mode: "rejected",
      reason_code: "VALIDATION_IDEMPOTENCY_CONFLICT",
      reason: "validator already produced a different validation result for this target",
      refs: sameIdentity.slice(0, 6).map((ev) => ev.event_id),
    };
  }

  const oppositeType = proposedEvent.type === "handoff_validated" ? "handoff_rejected" : "handoff_validated";
  const oppositeVerdicts = events.filter((ev) => {
    if (ev.type !== oppositeType) return false;
    return validationTargetKeyFromPayload(ev.payload) === targetKey;
  });
  if (oppositeVerdicts.length) {
    const hasTargetedDispute = events.some(
      (ev) => ev.type === "dispute_open" && ev?.payload?.target_key === targetKey
    );
    if (!hasTargetedDispute) {
      return {
        mode: "rejected",
        reason_code: "VALIDATION_CONFLICT_REQUIRES_DISPUTE_OPEN",
        reason: "opposite verdict exists for target and no dispute_open(target_key) was recorded",
        refs: oppositeVerdicts.slice(0, 6).map((ev) => ev.event_id),
      };
    }
  }

  const out = await appendEvent(run_id, proposedEvent);
  return { mode: "appended", out, target_key: targetKey };
}

async function startRun(run_id, meta = {}) {
  await ensureRunCreated(run_id);
  const p = runPaths(run_id);
  const head = await readJson(p.headPath);

  if ((head.seq || 0) > 0) return { ok: true, run_id, already_started: true };

  await writeJsonAtomic(p.metaPath, { run_id, created_at: nowIso(), version: VERSION, ...meta });

  await appendEvent(run_id, {
    type: "run_started",
    actor_id: "orchestrator",
    source: "keel-bridge",
    payload: { version: VERSION, meta },
  });

  return { ok: true, run_id, already_started: false };
}

async function readEvents(run_id) {
  const p = runPaths(run_id);
  const raw = await fsp.readFile(p.eventsPath, "utf-8");
  const lines = raw.split("\n").filter((l) => l.trim().length);
  const out = [];
  for (let i = 0; i < lines.length; i++) out.push(JSON.parse(lines[i]));
  return out;
}

function buildRunLookup(events) {
  const byEventId = new Map();
  const byTurnId = new Map();
  const holdIds = new Set();
  for (const ev of events) {
    byEventId.set(ev.event_id, ev);
    const turnId = ev?.payload?.turn_id;
    if (typeof turnId === "string" && turnId) byTurnId.set(turnId, ev);
    const holdId = ev?.payload?.hold_id;
    if (typeof holdId === "string" && holdId) holdIds.add(holdId);
    if (["hold", "release", "discharge"].includes(ev.type) && typeof ev?.payload?.id === "string") {
      holdIds.add(ev.payload.id);
    }
  }
  return { byEventId, byTurnId, holdIds };
}

async function validateEventAgainstRun(run_id, evt) {
  if (evt.type !== "recognition_event") return null;
  const events = await readEvents(run_id);
  const { byEventId, byTurnId, holdIds } = buildRunLookup(events);
  const bind = evt.payload.bind;
  if (bind.type === "turn") {
    const turnExists = byTurnId.has(bind.id) || byEventId.has(bind.id);
    if (!turnExists) return `recognition_event bind turn not found: ${bind.id}`;
    if (!Array.isArray(evt.refs) || evt.refs.length < 1) {
      return "recognition_event turn binding requires refs";
    }
    for (const ref of evt.refs) {
      if (!byEventId.has(ref)) return `recognition_event ref not found: ${ref}`;
    }
    const hasTurnRef = evt.refs.some((ref) => {
      const refEvt = byEventId.get(ref);
      return refEvt?.event_id === bind.id || refEvt?.payload?.turn_id === bind.id;
    });
    if (!hasTurnRef) return "recognition_event refs must include a ref bound to bind.id";
    return null;
  }
  const holdExists = holdIds.has(bind.id) || byEventId.has(bind.id);
  if (!holdExists) return `recognition_event bind hold not found: ${bind.id}`;
  if (Array.isArray(evt.refs)) {
    for (const ref of evt.refs) {
      if (!byEventId.has(ref)) return `recognition_event ref not found: ${ref}`;
    }
  }
  return null;
}

function computeCoverage(events) {
  const userTurns = new Map();
  const agentTurns = new Map();
  for (const e of events) {
    if (e.type === "user_input") {
      const t = e?.payload?.turn_id;
      if (t) userTurns.set(t, e.ts);
    } else if (e.type === "agent_output") {
      const t = e?.payload?.turn_id;
      if (t) agentTurns.set(t, e.ts);
    }
  }
  const missing = [];
  let paired = 0;
  for (const [t, ts] of userTurns) {
    if (agentTurns.has(t)) paired++;
    else missing.push({ turn_id: t, user_ts: ts });
  }
  return { user_turns: userTurns.size, agent_turns: agentTurns.size, paired, missing_agent: missing.length, missing };
}

function countBy(events, key) {
  const m = new Map();
  for (const e of events) m.set(e[key], (m.get(e[key]) || 0) + 1);
  return Object.fromEntries([...m.entries()].sort((a, b) => b[1] - a[1]));
}

function buildValidationSummaryViews(events) {
  const exportScars = [];
  const badgesByTarget = new Map();

  for (const ev of events) {
    if (ev.type === "handoff_packet_exported" || ev.type === "handoff_packet_export_failed") {
      const exportId = typeof ev?.payload?.export_id === "string" && ev.payload.export_id ? ev.payload.export_id : null;
      const packetHash = typeof ev?.payload?.packet_hash === "string" ? ev.payload.packet_hash : null;
      const targetKey = exportId ? `export:${exportId}` : (packetHash ? `hash:${packetHash}` : null);
      exportScars.push({
        scar_type: ev.type,
        event_id: ev.event_id,
        seq: ev.seq,
        export_id: exportId,
        packet_hash: packetHash,
        target_key: targetKey,
        include_audit: ev?.payload?.include_audit ?? null,
      });
    }

    if (isValidationType(ev.type)) {
      const targetKey = validationTargetKeyFromPayload(ev.payload);
      if (!targetKey) continue;
      const prev = badgesByTarget.get(targetKey);
      if (prev && Number(prev.seq) > Number(ev.seq)) continue;

      badgesByTarget.set(targetKey, {
        target_key: targetKey,
        event_id: ev.event_id,
        seq: ev.seq,
        verdict: ev?.payload?.verdict,
        validator_actor_id: ev.actor_id,
        report: buildValidationVerdictObject(ev),
      });
    }
  }

  exportScars.sort((a, b) => Number(b.seq) - Number(a.seq));
  const validationBadges = [...badgesByTarget.values()].sort((a, b) => Number(b.seq) - Number(a.seq));
  return { exportScars, validationBadges };
}

async function auditRun(run_id) {
  if (!runExists(run_id)) throw new HttpError(404, "run not found");
  const p = runPaths(run_id);
  const events = await readEvents(run_id);

  let ok = true;
  const problems = [];
  let prev = "GENESIS";
  let expectedSeq = 1;
  const ids = new Set();
  let lastHash = "GENESIS";
  let lastEventId = null;

  for (let i = 0; i < events.length; i++) {
    const evt = events[i];
    if (ids.has(evt.event_id)) {
      ok = false;
      problems.push({ type: "duplicate_event_id", line: i + 1, event_id: evt.event_id });
      break;
    }
    ids.add(evt.event_id);

    if (Number(evt.seq) !== expectedSeq) {
      ok = false;
      problems.push({ type: "seq_discontinuity", line: i + 1, expected_seq: expectedSeq, found_seq: evt.seq });
      break;
    }
    expectedSeq++;

    if (evt.prev_hash !== prev) {
      ok = false;
      problems.push({ type: "hash_chain_break", line: i + 1, expected_prev_hash: prev, found_prev_hash: evt.prev_hash });
      break;
    }

    const { hash, ...withoutHash } = evt;
    const canonical = stableStringify(withoutHash);
    const recomputed = sha256Hex(Buffer.from(`${evt.prev_hash}\n${canonical}`, "utf-8"));
    if (recomputed !== hash) {
      ok = false;
      problems.push({ type: "hash_mismatch", line: i + 1, expected_hash: recomputed, found_hash: hash });
      break;
    }

    prev = hash;
    lastHash = hash;
    lastEventId = evt.event_id;
  }

  const byId = new Map(events.map((e) => [e.event_id, e]));
  const byTurn = new Map();
  const byHold = new Set();
  for (const ev of events) {
    const turnId = ev?.payload?.turn_id;
    if (typeof turnId === "string" && turnId) byTurn.set(turnId, ev);
    const holdId = ev?.payload?.hold_id;
    if (typeof holdId === "string" && holdId) byHold.add(holdId);
    if (["hold", "release", "discharge"].includes(ev.type) && typeof ev?.payload?.id === "string") {
      byHold.add(ev.payload.id);
    }
  }

  const exportScars = new Map();
  for (const ev of events) {
    if (ev.type === "recognition_event") {
      const bind = ev?.payload?.bind;
      if (!bind || !["turn", "hold"].includes(bind.type) || typeof bind.id !== "string" || !bind.id) {
        ok = false;
        problems.push({ type: "recognition_bind_invalid", event_id: ev.event_id });
        continue;
      }
      if (bind.type === "turn") {
        if (!byTurn.has(bind.id) && !byId.has(bind.id)) {
          ok = false;
          problems.push({ type: "recognition_bind_turn_missing", event_id: ev.event_id, bind_id: bind.id });
        }
        const refs = Array.isArray(ev.refs) ? ev.refs : [];
        if (!refs.length) {
          ok = false;
          problems.push({ type: "recognition_refs_missing", event_id: ev.event_id });
        } else {
          const hasBoundRef = refs.some((ref) => {
            const r = byId.get(ref);
            return r?.event_id === bind.id || r?.payload?.turn_id === bind.id;
          });
          if (!hasBoundRef) {
            ok = false;
            problems.push({ type: "recognition_ref_not_bound", event_id: ev.event_id, bind_id: bind.id });
          }
        }
      } else if (!byHold.has(bind.id) && !byId.has(bind.id)) {
        ok = false;
        problems.push({ type: "recognition_bind_hold_missing", event_id: ev.event_id, bind_id: bind.id });
      }
    }

    if (ev.type === "handoff_packet_exported" || ev.type === "handoff_packet_export_failed") {
      const exportId = ev?.payload?.export_id;
      if (typeof exportId === "string" && exportId) {
        const arr = exportScars.get(exportId) || [];
        arr.push(ev.type);
        exportScars.set(exportId, arr);
      }
    }
  }
  for (const [exportId, scars] of exportScars.entries()) {
    if (scars.length !== 1) {
      ok = false;
      problems.push({ type: "export_scar_multiplicity", export_id: exportId, scars });
    }
  }

  const head = await readJson(p.headPath);
  if (head.head_hash !== lastHash) {
    ok = false;
    problems.push({ type: "head_mismatch", expected_head_hash: lastHash, found_head_hash: head.head_hash });
  }
  if (Number(head.seq) !== events.length) {
    ok = false;
    problems.push({ type: "head_seq_mismatch", expected_seq: events.length, found_seq: head.seq });
  }

  const report = {
    run_id,
    ok,
    lines: events.length,
    last_event_id: lastEventId,
    head_hash: lastHash,
    checked_at: nowIso(),
    problems,
    version: VERSION,
  };

  await writeJsonAtomic(p.auditPath, report);
  return report;
}

async function listRuns(limit = 50) {
  await mkdirp(KEEL_DIR);
  const ents = await fsp.readdir(KEEL_DIR, { withFileTypes: true });
  const runs = [];
  for (const e of ents) {
    if (!e.isDirectory()) continue;
    if (e.name.startsWith(".")) continue;
    const run_id = e.name;
    const p = runPaths(run_id);
    if (!fs.existsSync(p.headPath)) continue;
    try {
      const head = JSON.parse(await fsp.readFile(p.headPath, "utf-8"));
      const st = await fsp.stat(p.headPath);
      runs.push({
        run_id,
        seq: head.seq,
        head_hash: head.head_hash,
        updated_at: head.updated_at || head.created_at || null,
        mtime: st.mtimeMs,
      });
    } catch {}
  }
  runs.sort((a, b) => (b.mtime || 0) - (a.mtime || 0));
  return runs.slice(0, limit);
}

function applyRedactions(events, redact) {
  const redactions = [];
  const out = events.map((e) => JSON.parse(JSON.stringify(e)));

  const removeUrl = redact?.remove_url !== false; // default true
  if (removeUrl) {
    for (const ev of out) {
      if (ev?.payload?.url) {
        delete ev.payload.url;
        redactions.push({ path: `events[seq=${ev.seq}].payload.url`, action: "removed" });
      }
      if (ev?.payload?.ts_capture_url) {
        delete ev.payload.ts_capture_url;
        redactions.push({ path: `events[seq=${ev.seq}].payload.ts_capture_url`, action: "removed" });
      }
    }
  }

  return { events: out, redactions };
}

function normalizeSelection(selectionIn) {
  const mode = selectionIn?.mode === "range" ? "range" : "tail";
  const out = {
    mode,
    tail_events: 0,
    seq_start: 0,
    seq_end: 0,
    kinds: isStringArray(selectionIn?.kinds) ? selectionIn.kinds : [],
  };
  if (mode === "range") {
    out.seq_start = Math.max(1, Number(selectionIn?.seq_start || 1));
    out.seq_end = Math.max(out.seq_start, Number(selectionIn?.seq_end || out.seq_start));
  } else {
    out.tail_events = Math.max(1, Math.min(Number(selectionIn?.tail_events || 200), 5000));
  }
  return out;
}

function normalizeExportRequest(body) {
  const run_id = body.run_id;
  const presetName = typeof body.preset === "string" && EXPORT_PRESET_NAMES.has(body.preset) ? body.preset : "custom";
  const preset = EXPORT_PRESETS[presetName] || null;
  const selection = normalizeSelection(
    preset
      ? {
          mode: preset.mode,
          tail_events: preset.tail_events,
          kinds: preset.kinds,
        }
      : {
          mode: body.mode,
          tail_events: body.tail_events,
          seq_start: body.seq_start,
          seq_end: body.seq_end,
          kinds: Array.isArray(body.types) ? body.types : [],
        }
  );
  const redactions = {
    remove_url: preset ? !!preset.redact_url : body?.redact?.remove_url !== false,
    notes: body?.redact?.notes || null,
  };
  return {
    run_id,
    export_id: typeof body.export_id === "string" && body.export_id ? body.export_id : ulid(),
    source_marker_id: typeof body.source_marker_id === "string" ? body.source_marker_id : null,
    preset: preset ? presetName : "custom",
    selection,
    redactions,
    include_audit: body.include_audit !== false,
    include_state: body.include_state === true,
  };
}

async function exportHandoffPacket(reqExport) {
  const run_id = reqExport.run_id;
  if (!validateRunId(run_id)) throw new HttpError(400, "invalid run_id");
  if (!runExists(run_id)) throw new HttpError(404, "run not found");

  const p = runPaths(run_id);
  const head = await readJson(p.headPath);
  const eventsAll = await readEvents(run_id);

  let selected = [];
  if (reqExport.selection.mode === "range") {
    const s = Number(reqExport.selection.seq_start || 1);
    const e = Number(reqExport.selection.seq_end || head.seq || eventsAll.length);
    selected = eventsAll.filter((x) => Number(x.seq) >= s && Number(x.seq) <= e);
  } else {
    const n = Math.max(1, Math.min(Number(reqExport.selection.tail_events || 200), 5000));
    selected = eventsAll.slice(-n);
  }

  if (reqExport.selection.kinds?.length) {
    selected = selected.filter((ev) => reqExport.selection.kinds.includes(ev.type));
  }
  if (!selected.length) throw new HttpError(400, "selection produced empty packet");

  const seqStart = selected[0].seq;
  const seqEnd = selected[selected.length - 1].seq;
  const startPrevHash = selected[0].prev_hash;
  const endHash = selected[selected.length - 1].hash;

  let audit = null;
  if (reqExport.include_audit && fs.existsSync(p.auditPath)) {
    try {
      audit = JSON.parse(await fsp.readFile(p.auditPath, "utf-8"));
    } catch {}
  }

  let state = null;
  if (reqExport.include_state && fs.existsSync(p.statePath)) {
    try {
      state = JSON.parse(await fsp.readFile(p.statePath, "utf-8"));
    } catch {}
  }

  const { events, redactions } = applyRedactions(selected, { remove_url: reqExport.redactions.remove_url });

  const packet = {
    packet_version: "keel-handoff-v0",
    created_at: nowIso(),
    created_by: "keel-bridge",
    bridge_version: VERSION,
    run_id,
    seq_range: { start: seqStart, end: seqEnd },
    hash_chain: {
      start_prev_hash: startPrevHash,
      end_hash: endHash,
      head_hash: head.head_hash,
      head_seq: head.seq,
    },
    audit: audit
      ? {
          ok: audit.ok,
          lines: audit.lines,
          checked_at: audit.checked_at,
          head_hash: audit.head_hash,
          problems: audit.problems,
        }
      : null,
    state,
    events,
    redactions,
    packet_hash: null,
  };

  const canonical = stableStringify({ ...packet, packet_hash: null });
  packet.packet_hash = sha256Hex(Buffer.from(canonical, "utf-8"));
  return packet;
}

function normalizeRecognitionBody(body) {
  const why = Array.isArray(body.why) ? body.why.map((s) => String(s || "").trim()).filter(Boolean) : [];
  const refs = isStringArray(body.refs) ? body.refs : [];
  return {
    run_id: body.run_id,
    marker_id: typeof body.marker_id === "string" && body.marker_id ? body.marker_id : ulid(),
    bind: {
      type: body?.bind?.type,
      id: body?.bind?.id,
    },
    why,
    signals: {
      latency_ms: body?.signals?.latency_ms == null ? 0 : Number(body.signals.latency_ms),
      dispute_severity: body?.signals?.dispute_severity ?? null,
      confidence_drop: body?.signals?.confidence_drop == null ? 0 : Number(body.signals.confidence_drop),
    },
    export_policy: body.export_policy || "prompt",
    requested_export_preset: body.requested_export_preset || "tail200",
    refs,
  };
}

async function createRecognitionEvent(body) {
  const req = normalizeRecognitionBody(body);
  if (!validateRunId(req.run_id)) throw new HttpError(400, "invalid run_id");
  if (!runExists(req.run_id)) throw new HttpError(404, "run not found");
  const out = await appendEvent(req.run_id, {
    type: "recognition_event",
    actor_id: "human:inspector",
    source: "inspector:mark_weight",
    refs: req.refs,
    payload: {
      marker_id: req.marker_id,
      bind: req.bind,
      why: req.why,
      signals: req.signals,
      export_policy: req.export_policy,
      requested_export_preset: req.requested_export_preset,
    },
  });
  return { req, out };
}

function errorCodeFor(err) {
  if (err?.status === 400) return "BAD_REQUEST";
  if (err?.status === 401) return "UNAUTHORIZED";
  if (err?.status === 403) return "FORBIDDEN";
  if (err?.status === 404) return "NOT_FOUND";
  if (err?.status === 413) return "PAYLOAD_TOO_LARGE";
  return "EXPORT_FAILED";
}

async function appendExportSuccessScar(run_id, reqExport, packet) {
  const scarPayload = {
    export_id: reqExport.export_id,
    source_marker_id: reqExport.source_marker_id,
    preset: reqExport.preset,
    selection: reqExport.selection,
    redactions: reqExport.redactions,
    include_audit: !!reqExport.include_audit,
    packet_hash: packet.packet_hash,
    packet_seq_range: {
      start: packet.seq_range.start,
      end: packet.seq_range.end,
    },
    packet_chain: {
      start_prev_hash: packet.hash_chain.start_prev_hash,
      end_hash: packet.hash_chain.end_hash,
      head_hash: packet.hash_chain.head_hash,
    },
    bytes: Buffer.byteLength(JSON.stringify(packet), "utf-8"),
  };
  return appendEvent(run_id, {
    type: "handoff_packet_exported",
    actor_id: "system:keel-bridge",
    source: "keel-bridge:packet_export",
    refs: reqExport.source_marker_id ? [reqExport.source_marker_id] : [],
    payload: scarPayload,
  });
}

async function appendExportFailureScar(run_id, reqExport, err) {
  return appendEvent(run_id, {
    type: "handoff_packet_export_failed",
    actor_id: "system:keel-bridge",
    source: "keel-bridge:packet_export",
    refs: reqExport?.source_marker_id ? [reqExport.source_marker_id] : [],
    payload: {
      export_id: reqExport?.export_id || ulid(),
      source_marker_id: reqExport?.source_marker_id || null,
      preset: reqExport?.preset || "custom",
      selection: reqExport?.selection || { mode: "tail", tail_events: 200, seq_start: 0, seq_end: 0, kinds: [] },
      redactions: reqExport?.redactions || { remove_url: true },
      include_audit: reqExport?.include_audit !== false,
      error_code: errorCodeFor(err),
      error_message: String(err?.message || err),
    },
  });
}

// -------- Inspector UI assets (tiny, no deps)
const INSPECT_HTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>KEEL-PHNX Inspector</title>
  <link rel="stylesheet" href="/inspect/style.css"/>
</head>
<body>
  <header>
    <h1>keel-phnx inspector</h1>
    <div class="row">
      <label>token <input id="tok" type="password" placeholder="paste KEEL_TOKEN"/></label>
      <button id="saveTok">save</button>
      <button id="refreshRuns">refresh runs</button>
      <span id="status"></span>
    </div>
  </header>

  <main>
    <section class="card">
      <h2>runs</h2>
      <div class="row">
        <select id="runs"></select>
        <button id="loadRun">load</button>
      </div>
      <pre id="runSummary" class="mono"></pre>
    </section>

    <section class="card">
      <h2>export scars + validation</h2>
      <div id="scarList" class="mono"></div>
    </section>

    <section class="card">
      <h2>events</h2>
      <div class="row">
        <label>tail events <input id="tailN" type="number" value="200" min="1" max="5000"/></label>
        <button id="loadTail">load tail</button>
        <button id="markWeight">MARK WEIGHT</button>
        <span id="selectedRow" class="mono">selected: none</span>
      </div>
      <div class="tableWrap">
        <table id="eventsTbl">
          <thead><tr><th>seq</th><th>type</th><th>actor</th><th>ts</th><th>event_id</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <h2>handoff packet</h2>
      <div class="row">
        <label>preset
          <select id="preset">
            <option value="tail200">tail200</option>
            <option value="decisions_disputes">decisions_disputes</option>
            <option value="alarms_only">alarms_only</option>
            <option value="custom">custom</option>
          </select>
        </label>
        <label>mode
          <select id="mode">
            <option value="tail">tail</option>
            <option value="range">range</option>
          </select>
        </label>
        <label>seq start <input id="seqStart" type="number" value="1" min="1"/></label>
        <label>seq end <input id="seqEnd" type="number" value="1" min="1"/></label>
        <label>types (comma) <input id="types" placeholder="custom preset only"/></label>
      </div>
      <div class="row">
        <label><input id="redactUrl" type="checkbox" checked/> redact url</label>
        <label><input id="includeAudit" type="checkbox" checked/> include audit summary</label>
        <label><input id="includeState" type="checkbox"/> include state.json</label>
        <button id="exportPkt">export</button>
        <button id="copyPkt">copy</button>
      </div>
      <textarea id="pktOut" class="mono" rows="12" placeholder="packet JSON appears here"></textarea>
    </section>
  </main>

  <div id="modal" class="modal hidden">
    <div class="modalInner">
      <button id="closeModal">close</button>
      <pre id="modalBody" class="mono"></pre>
    </div>
  </div>

  <div id="markModal" class="modal hidden">
    <div class="modalInner">
      <h3>MARK WEIGHT</h3>
      <div class="row">
        <label>bind type
          <select id="markBindType">
            <option value="turn">turn</option>
            <option value="hold">hold</option>
          </select>
        </label>
        <label>bind id <input id="markBindId" placeholder="turn_id or hold_id"/></label>
        <label>refs (comma event_id) <input id="markRefs" placeholder="evt_...,evt_..."/></label>
      </div>
      <div class="row">
        <label>latency ms <input id="markLatency" type="number" value="0"/></label>
        <label>dispute severity
          <select id="markSeverity">
            <option value="">null</option>
            <option value="low">low</option>
            <option value="med">med</option>
            <option value="high">high</option>
          </select>
        </label>
        <label>confidence drop <input id="markConfidence" type="number" step="0.01" value="0"/></label>
      </div>
      <div class="row">
        <label>export policy
          <select id="markPolicy">
            <option value="prompt">prompt</option>
            <option value="auto">auto</option>
            <option value="none">none</option>
          </select>
        </label>
        <label>preset
          <select id="markPreset">
            <option value="tail200">tail200</option>
            <option value="decisions_disputes">decisions_disputes</option>
            <option value="alarms_only">alarms_only</option>
          </select>
        </label>
      </div>
      <div class="row">
        <label>why (required)</label>
      </div>
      <textarea id="markWhy" class="mono" rows="4" placeholder="one reason per line"></textarea>
      <div class="row">
        <button id="markCommit">COMMIT</button>
        <button id="markClose">close</button>
      </div>
      <pre id="markErr" class="mono"></pre>
    </div>
  </div>

  <script src="/inspect/app.js"></script>
</body>
</html>`;

const INSPECT_CSS = `
:root { color-scheme: dark; }
body { margin:0; font:14px system-ui, -apple-system, sans-serif; background:#0b0b0c; color:#e7e7ea; }
header { padding:14px 16px; border-bottom:1px solid #222; position:sticky; top:0; background:#0b0b0c; z-index:10; }
h1 { margin:0 0 10px 0; font-size:16px; letter-spacing:0.5px; }
main { padding:16px; display:grid; gap:12px; max-width:1100px; }
.card { border:1px solid #222; border-radius:10px; padding:12px; background:#111114; }
.row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
label { display:flex; gap:8px; align-items:center; }
input, select, textarea, button { background:#0f0f12; color:#e7e7ea; border:1px solid #2a2a2f; border-radius:8px; padding:8px; }
button { cursor:pointer; }
button:hover { border-color:#3a3a42; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }
.tableWrap { overflow:auto; max-height:420px; border:1px solid #222; border-radius:10px; }
table { width:100%; border-collapse:collapse; }
th, td { padding:8px; border-bottom:1px solid #1f1f24; text-align:left; white-space:nowrap; }
tr:hover { background:#17171b; }
.selectedRow { background:#233247; }
.modal { position:fixed; inset:0; background:rgba(0,0,0,.55); display:flex; align-items:center; justify-content:center; }
.modalInner { width:min(1000px, 92vw); max-height:88vh; overflow:auto; background:#0f0f12; border:1px solid #2a2a2f; border-radius:12px; padding:12px; }
.modalInner h3 { margin-top:0; }
.scarRow { display:flex; gap:10px; align-items:center; justify-content:space-between; padding:6px 0; border-bottom:1px solid #1f1f24; }
.scarMeta { overflow:auto; white-space:nowrap; }
.badgeOk { background:#1f3f2a; border-color:#2d6b44; }
.badgeBad { background:#4c1f1f; border-color:#7a2e2e; }
.badgeMissing { color:#b6b6bf; }
.hidden { display:none; }
`;

const INSPECT_JS = `
const el = (id)=>document.getElementById(id);
const tokEl = el("tok");
const statusEl = el("status");
const runsEl = el("runs");
const summaryEl = el("runSummary");
const scarListEl = el("scarList");
const tblBody = el("eventsTbl").querySelector("tbody");
const selectedRowEl = el("selectedRow");
const modal = el("modal");
const modalBody = el("modalBody");
const markModal = el("markModal");
const markErr = el("markErr");

let runId = null;
let selectedEvent = null;
let selectedTr = null;

function setStatus(s){ statusEl.textContent=s; setTimeout(()=>statusEl.textContent="", 1800); }
function token(){ return localStorage.getItem("keel_token") || ""; }

async function apiPost(path, body){
  const t = token();
  if(!t) throw new Error("missing token");
  const res = await fetch(path, {
    method:"POST",
    headers: {"content-type":"application/json", "x-keel-token": t},
    body: JSON.stringify(body || {})
  });
  const j = await res.json().catch(()=>({}));
  if(!res.ok || j.ok===false) throw new Error(j.error || ("http "+res.status));
  return j;
}

function openModal(obj){
  modalBody.textContent = JSON.stringify(obj, null, 2);
  modal.classList.remove("hidden");
}
function closeModal(){ modal.classList.add("hidden"); }

function openMarkModal(){ markModal.classList.remove("hidden"); }
function closeMarkModal(){ markModal.classList.add("hidden"); markErr.textContent = ""; }

function clearSelection(){
  selectedEvent = null;
  if(selectedTr) selectedTr.classList.remove("selectedRow");
  selectedTr = null;
  selectedRowEl.textContent = "selected: none";
}

function renderValidationScars(summary){
  const scars = Array.isArray(summary?.export_scars) ? summary.export_scars : [];
  const badges = Array.isArray(summary?.validation_badges) ? summary.validation_badges : [];
  const badgeByTarget = new Map(badges.map((b)=>[b.target_key, b]));
  scarListEl.innerHTML = "";

  if(!scars.length){
    scarListEl.textContent = "no export scars";
    return;
  }

  for(const scar of scars){
    const row = document.createElement("div");
    row.className = "scarRow";

    const meta = document.createElement("span");
    meta.className = "mono scarMeta";
    const key = scar.target_key || "(no target)";
    meta.textContent = "[" + scar.seq + "] " + scar.scar_type + " " + key;
    row.appendChild(meta);

    const badge = key ? badgeByTarget.get(key) : null;
    if(badge){
      const btn = document.createElement("button");
      const verdict = String(badge.verdict || "").toUpperCase();
      btn.textContent = verdict || "UNKNOWN";
      btn.className = verdict === "VALID" ? "badgeOk" : "badgeBad";
      btn.onclick = ()=>openModal({
        target: badge.report?.target || null,
        validator_actor_id: badge.validator_actor_id,
        verdict: badge.report?.verdict || verdict,
        warnings: badge.report?.warnings || [],
        error_codes: badge.report?.error_codes || [],
        computed_hash: badge.report?.computed_hash || null,
        schema_check: badge.report?.schema_check || null,
        hash_check: badge.report?.hash_check || null,
        chain_check: badge.report?.chain_check || null,
        anchor_inventory: badge.report?.anchor_inventory || null,
      });
      row.appendChild(btn);
    } else {
      const miss = document.createElement("span");
      miss.className = "mono badgeMissing";
      miss.textContent = "unvalidated";
      row.appendChild(miss);
    }

    scarListEl.appendChild(row);
  }
}

function selectEvent(ev, tr){
  selectedEvent = ev;
  if(selectedTr) selectedTr.classList.remove("selectedRow");
  selectedTr = tr;
  selectedTr.classList.add("selectedRow");
  selectedRowEl.textContent = "selected: seq " + ev.seq + " " + ev.type + " " + ev.event_id;
}

function applyPresetUi(preset){
  if(preset === "tail200"){
    el("mode").value = "tail";
    el("tailN").value = 200;
    el("types").value = "message,decision,dispute_open,dispute_resolve,hold,release,discharge,recognition_event,session_close,event_rejected,challenge";
  } else if(preset === "decisions_disputes"){
    el("mode").value = "tail";
    el("tailN").value = 500;
    el("types").value = "decision,dispute_open,dispute_resolve,commitment_create,commitment_amend,recognition_event,session_close,event_rejected";
  } else if(preset === "alarms_only"){
    el("mode").value = "tail";
    el("tailN").value = 500;
    el("types").value = "discharge,challenge,event_rejected,dispute_open";
  }
}

el("closeModal").onclick = closeModal;
modal.onclick = (e)=>{ if(e.target===modal) closeModal(); };
el("markClose").onclick = closeMarkModal;
markModal.onclick = (e)=>{ if(e.target===markModal) closeMarkModal(); };

el("saveTok").onclick = ()=>{
  localStorage.setItem("keel_token", tokEl.value.trim());
  setStatus("saved");
};

async function refreshRuns(){
  const j = await apiPost("/v0/runs/list", { limit: 50 });
  runsEl.innerHTML = "";
  for(const r of j.runs){
    const opt = document.createElement("option");
    opt.value = r.run_id;
    opt.textContent = r.run_id + "  (seq " + r.seq + ")";
    runsEl.appendChild(opt);
  }
  if(j.runs.length){
    runsEl.value = j.runs[0].run_id;
    runId = runsEl.value;
  }
}

el("refreshRuns").onclick = ()=>refreshRuns().catch(e=>setStatus(e.message));
el("loadRun").onclick = async ()=>{
  runId = runsEl.value;
  const j = await apiPost("/v0/runs/summary", { run_id: runId });
  summaryEl.textContent = JSON.stringify(j.summary, null, 2);
  renderValidationScars(j.summary);
  el("seqEnd").value = j.summary?.head?.seq || 1;
  clearSelection();
  setStatus("loaded");
};

async function loadTail(){
  if(!runId) runId = runsEl.value;
  const n = Number(el("tailN").value || 200);
  const j = await apiPost("/v0/runs/events", { run_id: runId, mode:"tail", tail_events: n });
  tblBody.innerHTML = "";
  clearSelection();
  for(const ev of j.events){
    const tr = document.createElement("tr");
    tr.innerHTML = "<td>"+ev.seq+"</td><td>"+ev.type+"</td><td>"+ev.actor_id+"</td><td>"+ev.ts+"</td><td>"+ev.event_id+"</td>";
    tr.onclick = ()=>selectEvent(ev, tr);
    tr.ondblclick = ()=>openModal(ev);
    tblBody.appendChild(tr);
  }
  setStatus("events loaded");
}
el("loadTail").onclick = ()=>loadTail().catch(e=>setStatus(e.message));

async function exportPacket(opts){
  if(!runId) runId = runsEl.value;
  const preset = opts?.preset || el("preset").value || "custom";
  const body = {
    run_id: runId,
    preset,
    source_marker_id: opts?.source_marker_id || null,
    include_audit: el("includeAudit").checked,
    include_state: el("includeState").checked,
    redact: { remove_url: el("redactUrl").checked }
  };
  if(preset === "custom"){
    const mode = el("mode").value;
    const typesStr = el("types").value.trim();
    body.mode = mode;
    body.tail_events = Number(el("tailN").value || 200);
    body.seq_start = Number(el("seqStart").value || 1);
    body.seq_end = Number(el("seqEnd").value || 1);
    body.types = typesStr ? typesStr.split(",").map(s=>s.trim()).filter(Boolean) : [];
  }
  const j = await apiPost("/v0/packet/export", body);
  el("pktOut").value = JSON.stringify(j.packet, null, 2);
  setStatus("packet ready");
  return j;
}

el("preset").onchange = ()=>applyPresetUi(el("preset").value);

el("exportPkt").onclick = ()=>exportPacket({}).catch(e=>{
  setStatus(e.message);
});

el("markWeight").onclick = ()=>{
  if(!selectedEvent){
    setStatus("select an event row first");
    return;
  }
  const bindId = selectedEvent?.payload?.turn_id || selectedEvent?.event_id || "";
  el("markBindType").value = "turn";
  el("markBindId").value = bindId;
  el("markRefs").value = selectedEvent?.event_id || "";
  el("markWhy").value = "";
  el("markLatency").value = "0";
  el("markSeverity").value = "";
  el("markConfidence").value = "0";
  el("markPolicy").value = "prompt";
  el("markPreset").value = "tail200";
  markErr.textContent = "";
  openMarkModal();
};

el("markCommit").onclick = async ()=>{
  try{
    if(!runId) runId = runsEl.value;
    const why = el("markWhy").value.split("\\n").map(s=>s.trim()).filter(Boolean);
    const bindType = el("markBindType").value;
    const bindId = el("markBindId").value.trim();
    const refs = el("markRefs").value.split(",").map(s=>s.trim()).filter(Boolean);
    if(!bindId){ markErr.textContent = "bind id required"; return; }
    if(why.length < 1){ markErr.textContent = "why is required"; return; }
    if(bindType === "turn" && refs.length < 1){ markErr.textContent = "turn bind requires refs"; return; }

    const recBody = {
      run_id: runId,
      bind: { type: bindType, id: bindId },
      refs,
      why,
      signals: {
        latency_ms: Number(el("markLatency").value || 0),
        dispute_severity: el("markSeverity").value || null,
        confidence_drop: Number(el("markConfidence").value || 0)
      },
      export_policy: el("markPolicy").value,
      requested_export_preset: el("markPreset").value
    };
    const rec = await apiPost("/v0/recognition/mark", recBody);
    closeMarkModal();
    await loadTail();
    setStatus("recognition committed");

    const policy = recBody.export_policy;
    if(policy === "auto"){
      await exportPacket({ source_marker_id: rec.marker_id, preset: recBody.requested_export_preset });
    } else if(policy === "prompt"){
      const ok = window.confirm("export packet now?");
      if(ok){
        await exportPacket({ source_marker_id: rec.marker_id, preset: recBody.requested_export_preset });
      }
    }
  }catch(e){
    markErr.textContent = String(e.message || e);
  }
};

el("copyPkt").onclick = async ()=>{
  const txt = el("pktOut").value;
  if(!txt) return;
  await navigator.clipboard.writeText(txt);
  setStatus("copied");
};

(async function boot(){
  tokEl.value = token();
  applyPresetUi(el("preset").value);
  try { await refreshRuns(); } catch {}
})();`;

// -------- server
const server = http.createServer(async (req, res) => {
  try {
    assertLocalOnly(req);
    const url = new URL(req.url || "/", `http://${HOST}:${PORT}`);

    // public (no token): health + inspector assets
    if (url.pathname === "/health" && req.method === "GET") {
      return sendJson(res, 200, { ok: true, ts: nowIso(), version: VERSION });
    }
    if (url.pathname === "/inspect" && req.method === "GET") {
      return sendText(res, 200, INSPECT_HTML, "text/html; charset=utf-8");
    }
    if (url.pathname === "/inspect/app.js" && req.method === "GET") {
      return sendText(res, 200, INSPECT_JS, "application/javascript; charset=utf-8");
    }
    if (url.pathname === "/inspect/style.css" && req.method === "GET") {
      return sendText(res, 200, INSPECT_CSS, "text/css; charset=utf-8");
    }

    // everything else requires token
    requireToken(req);

    if (url.pathname === "/v0/runs/start" && req.method === "POST") {
      const body = await readBodyJson(req);
      const run_id = body.run_id;
      if (!validateRunId(run_id)) throw new HttpError(400, "invalid run_id");
      const out = await startRun(run_id, body.meta || {});
      return sendJson(res, 200, out);
    }

    if (url.pathname === "/v0/events/append" && req.method === "POST") {
      const body = await readBodyJson(req);
      const run_id = body.run_id;
      if (!validateRunId(run_id)) throw new HttpError(400, "invalid run_id");
      if (!body.event) throw new HttpError(400, "missing event");

      if (isValidationType(body.event.type)) {
        const gate = await handleValidationAppend(run_id, body.event);
        if (gate.mode === "idempotent") {
          return sendJson(res, 200, {
            ok: true,
            idempotent: true,
            prior_event_id: gate.prior.event_id,
            prior_seq: gate.prior.seq,
            prior_hash: gate.prior.hash,
            target_key: gate.prior.target_key,
          });
        }
        if (gate.mode === "rejected") {
          let rejectionScar = null;
          try {
            rejectionScar = await appendEventRejected(
              run_id,
              body.event,
              gate.reason_code,
              gate.reason,
              gate.refs || [],
              gate.violated_commitment_ids || []
            );
          } catch {}
          return sendJson(res, 409, {
            ok: false,
            error: gate.reason,
            reason_code: gate.reason_code,
            rejected_event_id: rejectionScar?.event_id || null,
            rejected_seq: rejectionScar?.seq || null,
          });
        }
        return sendJson(res, 200, { ok: true, ...gate.out });
      }

      const out = await appendEvent(run_id, body.event);
      return sendJson(res, 200, { ok: true, ...out });
    }

    if (url.pathname === "/v0/runs/audit" && req.method === "POST") {
      const body = await readBodyJson(req);
      const run_id = body.run_id;
      if (!validateRunId(run_id)) throw new HttpError(400, "invalid run_id");
      const report = await auditRun(run_id);
      return sendJson(res, 200, { ok: true, report });
    }

    if (url.pathname === "/v0/runs/head" && req.method === "POST") {
      const body = await readBodyJson(req);
      const run_id = body.run_id;
      if (!validateRunId(run_id)) throw new HttpError(400, "invalid run_id");
      if (!runExists(run_id)) throw new HttpError(404, "run not found");
      const head = await readJson(runPaths(run_id).headPath);
      return sendJson(res, 200, { ok: true, head });
    }

    if (url.pathname === "/v0/runs/list" && req.method === "POST") {
      const body = await readBodyJson(req);
      const limit = Math.max(1, Math.min(Number(body.limit || 50), 200));
      const runs = await listRuns(limit);
      return sendJson(res, 200, { ok: true, runs });
    }

    if (url.pathname === "/v0/runs/events" && req.method === "POST") {
      const body = await readBodyJson(req);
      const run_id = body.run_id;
      if (!validateRunId(run_id)) throw new HttpError(400, "invalid run_id");
      if (!runExists(run_id)) throw new HttpError(404, "run not found");

      const mode = body.mode || "tail";
      const head = await readJson(runPaths(run_id).headPath);
      const eventsAll = await readEvents(run_id);

      let selected = [];
      if (mode === "range") {
        const s = Number(body.seq_start || 1);
        const e = Number(body.seq_end || head.seq || eventsAll.length);
        selected = eventsAll.filter((x) => Number(x.seq) >= s && Number(x.seq) <= e);
      } else {
        const n = Math.max(1, Math.min(Number(body.tail_events || 200), 5000));
        selected = eventsAll.slice(-n);
      }
      return sendJson(res, 200, { ok: true, events: selected });
    }

    if (url.pathname === "/v0/runs/summary" && req.method === "POST") {
      const body = await readBodyJson(req);
      const run_id = body.run_id;
      if (!validateRunId(run_id)) throw new HttpError(400, "invalid run_id");
      if (!runExists(run_id)) throw new HttpError(404, "run not found");

      const p = runPaths(run_id);
      const head = await readJson(p.headPath);
      const events = await readEvents(run_id);
      let audit = null;
      if (fs.existsSync(p.auditPath)) {
        try { audit = JSON.parse(await fsp.readFile(p.auditPath, "utf-8")); } catch {}
      }
      const validationViews = buildValidationSummaryViews(events);

      const summary = {
        run_id,
        head,
        counts: { type: countBy(events, "type"), actor: countBy(events, "actor_id") },
        coverage: computeCoverage(events),
        audit: audit ? { ok: audit.ok, checked_at: audit.checked_at, problems: audit.problems } : null,
        export_scars: validationViews.exportScars,
        validation_badges: validationViews.validationBadges,
      };

      return sendJson(res, 200, { ok: true, summary });
    }

    if (url.pathname === "/v0/recognition/mark" && req.method === "POST") {
      const body = await readBodyJson(req);
      const result = await createRecognitionEvent(body);
      return sendJson(res, 200, {
        ok: true,
        marker_id: result.req.marker_id,
        event_id: result.out.event_id,
        seq: result.out.seq,
      });
    }

    if (url.pathname === "/v0/packet/export" && req.method === "POST") {
      const body = await readBodyJson(req);
      const reqExport = normalizeExportRequest(body);
      if (!validateRunId(reqExport.run_id)) throw new HttpError(400, "invalid run_id");
      if (!runExists(reqExport.run_id)) throw new HttpError(404, "run not found");

      try {
        const packet = await exportHandoffPacket(reqExport);
        const scar = await appendExportSuccessScar(reqExport.run_id, reqExport, packet);
        return sendJson(res, 200, {
          ok: true,
          packet,
          export_id: reqExport.export_id,
          scar_event_id: scar.event_id,
          scar_seq: scar.seq,
        });
      } catch (err) {
        let scar = null;
        try {
          scar = await appendExportFailureScar(reqExport.run_id, reqExport, err);
        } catch {}
        const status = err?.status || 500;
        return sendJson(res, status, {
          ok: false,
          error: String(err?.message || err),
          export_id: reqExport.export_id,
          scar_event_id: scar?.event_id || null,
          scar_seq: scar?.seq || null,
        });
      }
    }

    return sendJson(res, 404, { ok: false, error: "not found" });
  } catch (e) {
    const status = e?.status || 500;
    return sendJson(res, status, { ok: false, error: String(e?.message || e) });
  }
});

await acquireBridgeLock();
server.listen(PORT, HOST, () => {
  console.log(`[keel-bridge] listening on http://${HOST}:${PORT}`);
  console.log(`[keel-bridge] KEEL_DIR=${KEEL_DIR}`);
  console.log(`[keel-bridge] version=${VERSION}`);
  console.log(`[keel-bridge] inspector: http://${HOST}:${PORT}/inspect`);
});
