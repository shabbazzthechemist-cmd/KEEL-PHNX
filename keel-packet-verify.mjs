#!/usr/bin/env node
import { promises as fsp } from "node:fs";
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

async function main() {
  const fp = process.argv[2];
  if (!fp) {
    console.error("usage: node keel-packet-verify.mjs /path/to/packet.json");
    process.exit(2);
  }

  const packet = JSON.parse(await fsp.readFile(fp, "utf-8"));
  const claimed = packet.packet_hash;

  const canonical = stableStringify({ ...packet, packet_hash: null });
  const computed = sha256Hex(Buffer.from(canonical, "utf-8"));

  const okHash = claimed === computed;

  const evs = packet.events || [];
  let okChain = true;
  const problems = [];

  if (!evs.length) {
    okChain = false;
    problems.push("no events in packet");
  } else {
    // check boundary + continuity
    if (evs[0].prev_hash !== packet.hash_chain?.start_prev_hash) {
      okChain = false;
      problems.push("start_prev_hash mismatch");
    }
    for (let i = 1; i < evs.length; i++) {
      if (evs[i].prev_hash !== evs[i - 1].hash) {
        okChain = false;
        problems.push(`chain break at index ${i} (seq ${evs[i].seq})`);
        break;
      }
      if (Number(evs[i].seq) !== Number(evs[i - 1].seq) + 1) {
        okChain = false;
        problems.push(`seq discontinuity at index ${i} (seq ${evs[i].seq})`);
        break;
      }
    }
    if (evs[evs.length - 1].hash !== packet.hash_chain?.end_hash) {
      okChain = false;
      problems.push("end_hash mismatch");
    }
  }

  const out = {
    ok: okHash && okChain,
    packet_hash_ok: okHash,
    chain_ok: okChain,
    claimed_packet_hash: claimed,
    computed_packet_hash: computed,
    problems,
  };

  console.log(JSON.stringify(out, null, 2));
  process.exit(out.ok ? 0 : 1);
}

main().catch((e) => {
  console.error(String(e?.message || e));
  process.exit(1);
});
