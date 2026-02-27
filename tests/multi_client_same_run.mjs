/**
 * Simulates multi-tab same-run concurrency: two clients append concurrently.
 * Assumes keel-bridge is running.
 */
import crypto from "node:crypto";

const KEEL_TOKEN = process.env.KEEL_TOKEN;
const RUN_ID = process.env.RUN_ID || `0xKEELPHNX_multiclient_${Date.now()}`;
const N = Number(process.env.N || 50);

if (!KEEL_TOKEN) {
  console.error("KEEL_TOKEN is required");
  process.exit(2);
}

async function post(path, body) {
  const res = await fetch(`http://127.0.0.1:42069${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-keel-token": KEEL_TOKEN },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok || json.ok === false) throw new Error(json.error || `HTTP ${res.status}`);
  return json;
}

await post("/v0/runs/start", { run_id: RUN_ID, meta: { label: "multiclient_same_run" } });

function mkEvent(client, i) {
  return {
    run_id: RUN_ID,
    event: {
      type: "test",
      actor_id: `client_${client}`,
      source: "tests/multi_client_same_run.mjs",
      payload: { client, i, nonce: crypto.randomBytes(8).toString("hex") },
    },
  };
}

const clientA = Array.from({ length: N }).map((_, i) => post("/v0/events/append", mkEvent("A", i)));
const clientB = Array.from({ length: N }).map((_, i) => post("/v0/events/append", mkEvent("B", i)));

await Promise.all([...clientA, ...clientB]);

const audit = await post("/v0/runs/audit", { run_id: RUN_ID });
console.log(JSON.stringify({ run_id: RUN_ID, audit: audit.report }, null, 2));
