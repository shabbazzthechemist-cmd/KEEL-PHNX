#!/usr/bin/env node
import { promises as fsp } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

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

function usage() {
  console.error(`usage:
  node keel-verify.mjs /path/to/runs/<run_id>
  node keel-verify.mjs --dir /path/to/runs --run <run_id>

env:
  KEEL_DIR=/path/to/runs (optional)
`);
  process.exit(2);
}

function parseArgs(argv) {
  const args = { runPath: null, dir: process.env.KEEL_DIR || null, run: null, tail: 0 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dir") args.dir = argv[++i];
    else if (a === "--run") args.run = argv[++i];
    else if (a === "--tail") args.tail = Number(argv[++i] || 0);
    else if (!a.startsWith("--") && !args.runPath) args.runPath = a;
    else usage();
  }
  return args;
}

function fmtTs(ts) {
  try {
    return new Date(ts).toISOString();
  } catch {
    return String(ts);
  }
}

async function readNdjson(p) {
  const raw = await fsp.readFile(p, "utf-8");
  const lines = raw.split("\n").filter((l) => l.trim().length);
  const events = [];
  for (let i = 0; i < lines.length; i++) events.push(JSON.parse(lines[i]));
  return events;
}

function buildCoverage(events) {
  const userTurns = new Map();
  const agentTurns = new Map();

  for (const e of events) {
    if (e.type === "user_input") {
      const turn = e?.payload?.turn_id;
      if (turn) userTurns.set(turn, { ts: e.ts, text_len: (e.payload?.raw_text || "").length });
    }
    if (e.type === "agent_output") {
      const turn = e?.payload?.turn_id;
      if (turn) {
        agentTurns.set(turn, {
          ts: e.ts,
          len: (e.payload?.content || "").length,
          settle_evidence: e.payload?.settle_evidence || null,
        });
      }
    }
  }

  let paired = 0;
  let missingAgent = 0;
  const missing = [];
  for (const [turn, u] of userTurns) {
    if (agentTurns.has(turn)) paired++;
    else {
      missingAgent++;
      missing.push({ turn_id: turn, user_ts: u.ts });
    }
  }

  return {
    user_turns: userTurns.size,
    agent_turns: agentTurns.size,
    paired,
    missing_agent: missingAgent,
    missing,
  };
}

function typeCounts(events) {
  const m = new Map();
  for (const e of events) m.set(e.type, (m.get(e.type) || 0) + 1);
  return Object.fromEntries([...m.entries()].sort((a, b) => a[0].localeCompare(b[0])));
}

function actorCounts(events) {
  const m = new Map();
  for (const e of events) m.set(e.actor_id, (m.get(e.actor_id) || 0) + 1);
  return Object.fromEntries([...m.entries()].sort((a, b) => b[1] - a[1]));
}

function verifyHashChain(events) {
  let prev = "GENESIS";
  let expectedSeq = 1;
  const eventIds = new Set();
  const run_id = events[0]?.run_id || null;

  for (let i = 0; i < events.length; i++) {
    const evt = events[i];

    if (run_id && evt.run_id !== run_id) {
      return {
        ok: false,
        where: i + 1,
        error: "run_id_changed",
        expected_run_id: run_id,
        found_run_id: evt.run_id,
      };
    }

    if (eventIds.has(evt.event_id)) {
      return { ok: false, where: i + 1, error: "duplicate_event_id", event_id: evt.event_id };
    }
    eventIds.add(evt.event_id);

    if (Number(evt.seq) !== expectedSeq) {
      return {
        ok: false,
        where: i + 1,
        error: "seq_discontinuity",
        expected_seq: expectedSeq,
        found_seq: evt.seq,
        event_id: evt.event_id,
      };
    }
    expectedSeq++;

    if (evt.prev_hash !== prev) {
      return {
        ok: false,
        where: i + 1,
        error: "hash_chain_break",
        expected_prev: prev,
        found_prev: evt.prev_hash,
        event_id: evt.event_id,
      };
    }

    const { hash, ...withoutHash } = evt;
    const canonical = stableStringify(withoutHash);
    const recomputed = sha256Hex(Buffer.from(`${evt.prev_hash}\n${canonical}`, "utf-8"));
    if (recomputed !== hash) {
      return {
        ok: false,
        where: i + 1,
        error: "hash_mismatch",
        expected_hash: recomputed,
        found_hash: hash,
        event_id: evt.event_id,
      };
    }
    prev = hash;
  }
  return { ok: true, head_hash: prev };
}

async function main() {
  const args = parseArgs(process.argv);
  let runDir = args.runPath;

  if (!runDir) {
    if (!args.dir || !args.run) usage();
    runDir = path.join(args.dir, args.run);
  }

  const eventsPath = path.join(runDir, "events.ndjson");
  const headPath = path.join(runDir, "HEAD.json");
  const events = await readNdjson(eventsPath);
  const chain = verifyHashChain(events);

  let head = null;
  try {
    head = JSON.parse(await fsp.readFile(headPath, "utf-8"));
  } catch {
    // head file optional for offline check.
  }

  const headOk =
    !head ||
    (head.head_hash === chain.head_hash && Number(head.seq) === Number(events.length));

  const out = {
    ok: chain.ok && headOk,
    runDir,
    lines: events.length,
    time: {
      first_ts: events[0]?.ts ? fmtTs(events[0].ts) : null,
      last_ts: events[events.length - 1]?.ts ? fmtTs(events[events.length - 1].ts) : null,
    },
    hash_chain: chain,
    head_file: head
      ? {
          head_hash: head.head_hash,
          seq: head.seq,
          last_event_id: head.last_event_id,
          seq_matches_lines: Number(head.seq) === Number(events.length),
        }
      : null,
    counts: typeCounts(events),
    actors: actorCounts(events),
    coverage: buildCoverage(events),
  };

  console.log(JSON.stringify(out, null, 2));

  if (args.tail > 0) {
    console.log("\n--- tail ---");
    for (const e of events.slice(-args.tail)) {
      console.log(`${e.seq}\t${e.type}\t${e.actor_id}\t${fmtTs(e.ts)}\t${e.event_id}`);
    }
  }

  process.exit(out.ok ? 0 : 1);
}

main().catch((e) => {
  console.error(String(e?.message || e));
  process.exit(1);
});
