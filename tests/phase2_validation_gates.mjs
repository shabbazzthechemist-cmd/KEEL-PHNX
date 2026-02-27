#!/usr/bin/env node
import crypto from "node:crypto";

const BASE_URL = process.env.BASE_URL || "http://127.0.0.1:42069";
const KEEL_TOKEN = process.env.KEEL_TOKEN;
const RUN_ID = process.env.RUN_ID || `0xKEELPHNX_valgates_${Date.now()}`;

if (!KEEL_TOKEN) {
  console.error("KEEL_TOKEN is required");
  process.exit(2);
}

async function post(path, body, expectedStatuses = [200]) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-keel-token": KEEL_TOKEN,
    },
    body: JSON.stringify(body),
  });

  const json = await res.json().catch(() => ({}));
  if (!expectedStatuses.includes(res.status)) {
    throw new Error(`HTTP ${res.status}: ${json.error || "unexpected status"}`);
  }
  return { status: res.status, json };
}

function baseReportPayload({ verdict, target, warnings = [], errorCodes = [] }) {
  const procedural = {
    target,
    validator: {
      type: "agent",
      id: "validator",
      name: "validator",
    },
    schema_check: {
      pass: true,
      missing_fields: [],
      extra_fields: [],
      type_errors: [],
    },
    hash_check: {
      packet_hash_ok: verdict === "VALID",
      computed_hash: target.packet_hash,
    },
    chain_check: {
      boundary_start_prev_ok: true,
      boundary_end_hash_ok: true,
      seq_continuity_ok: true,
      link_continuity_ok: true,
      details: [],
    },
    anchor_inventory: {
      recognition_markers: [],
      decisions: [],
      disputes: [],
      holds_releases_discharges: {
        hold: 0,
        release: 0,
        discharge: 0,
      },
    },
    verdict,
    computed_hash: target.packet_hash,
    warnings,
  };

  if (verdict === "INVALID") procedural.error_codes = errorCodes.length ? errorCodes : ["PACKET_HASH_MISMATCH"];
  return procedural;
}

function validatorEvent({ type, actorId, payload, source = "tests/phase2_validation_gates.mjs" }) {
  return {
    type,
    actor_id: actorId,
    source,
    payload,
  };
}

function targetKey(target) {
  return target.export_id ? `export:${target.export_id}` : `hash:${target.packet_hash}`;
}

async function main() {
  const out = {
    run_id: RUN_ID,
    gates: {
      duplicate_idempotent: { pass: false },
      duplicate_payload_mismatch_rejected: { pass: false },
      opposite_without_dispute_rejected: { pass: false },
      opposite_after_dispute_appends: { pass: false },
      summary_badges_present: { pass: false },
    },
  };

  await post("/v0/runs/start", { run_id: RUN_ID, meta: { label: "phase2_validation_gates" } });
  await post("/v0/events/append", {
    run_id: RUN_ID,
    event: {
      type: "user_input",
      actor_id: "human:test",
      source: "tests/phase2_validation_gates.mjs",
      payload: {
        turn_id: `turn_${Date.now()}`,
        raw_text: "seed export",
      },
    },
  });

  await post("/v0/runs/audit", { run_id: RUN_ID });

  const exportOut = await post("/v0/packet/export", {
    run_id: RUN_ID,
    preset: "custom",
    mode: "tail",
    tail_events: 200,
    include_audit: true,
  });

  const packet = exportOut.json.packet;
  const target = {
    export_id: exportOut.json.export_id,
    packet_hash: packet.packet_hash,
  };

  const validatedPayload = baseReportPayload({ verdict: "VALID", target, warnings: ["TEST_WARNING"] });
  const firstValidated = await post("/v0/events/append", {
    run_id: RUN_ID,
    event: validatorEvent({
      type: "handoff_validated",
      actorId: "agent:fabio",
      payload: validatedPayload,
    }),
  });

  const headAfterFirst = await post("/v0/runs/head", { run_id: RUN_ID });

  const duplicateValidated = await post("/v0/events/append", {
    run_id: RUN_ID,
    event: validatorEvent({
      type: "handoff_validated",
      actorId: "agent:fabio",
      payload: validatedPayload,
    }),
  });

  const headAfterDuplicate = await post("/v0/runs/head", { run_id: RUN_ID });

  out.gates.duplicate_idempotent = {
    pass:
      duplicateValidated.json?.idempotent === true &&
      duplicateValidated.json?.prior_event_id === firstValidated.json?.event_id &&
      Number(headAfterFirst.json?.head?.seq) === Number(headAfterDuplicate.json?.head?.seq),
    prior_event_id: duplicateValidated.json?.prior_event_id || null,
    seq_after_first: headAfterFirst.json?.head?.seq,
    seq_after_duplicate: headAfterDuplicate.json?.head?.seq,
  };

  const mismatchPayload = {
    ...validatedPayload,
    warnings: ["TEST_WARNING_CHANGED", crypto.randomBytes(4).toString("hex")],
  };

  const mismatchOut = await post(
    "/v0/events/append",
    {
      run_id: RUN_ID,
      event: validatorEvent({
        type: "handoff_validated",
        actorId: "agent:fabio",
        payload: mismatchPayload,
      }),
    },
    [409]
  );

  out.gates.duplicate_payload_mismatch_rejected = {
    pass: mismatchOut.json?.reason_code === "VALIDATION_IDEMPOTENCY_CONFLICT" && mismatchOut.status === 409,
    reason_code: mismatchOut.json?.reason_code || null,
    rejected_event_id: mismatchOut.json?.rejected_event_id || null,
  };

  const rejectedPayload = baseReportPayload({
    verdict: "INVALID",
    target,
    warnings: ["TEST_WARNING"],
    errorCodes: ["PACKET_HASH_MISMATCH"],
  });

  const oppositeNoDispute = await post(
    "/v0/events/append",
    {
      run_id: RUN_ID,
      event: validatorEvent({
        type: "handoff_rejected",
        actorId: "agent:petey",
        payload: rejectedPayload,
      }),
    },
    [409]
  );

  out.gates.opposite_without_dispute_rejected = {
    pass: oppositeNoDispute.json?.reason_code === "VALIDATION_CONFLICT_REQUIRES_DISPUTE_OPEN" && oppositeNoDispute.status === 409,
    reason_code: oppositeNoDispute.json?.reason_code || null,
    rejected_event_id: oppositeNoDispute.json?.rejected_event_id || null,
  };

  await post("/v0/events/append", {
    run_id: RUN_ID,
    event: {
      type: "dispute_open",
      actor_id: "human:orchestrator",
      source: "tests/phase2_validation_gates.mjs",
      refs: [firstValidated.json.event_id],
      payload: {
        dispute_id: `disp_${Date.now()}`,
        target_key: targetKey(target),
        issue: "Cross-verdict contention requires explicit dispute framing.",
      },
    },
  });

  const oppositeWithDispute = await post("/v0/events/append", {
    run_id: RUN_ID,
    event: validatorEvent({
      type: "handoff_rejected",
      actorId: "agent:petey",
      payload: rejectedPayload,
    }),
  });

  out.gates.opposite_after_dispute_appends = {
    pass: oppositeWithDispute.status === 200 && oppositeWithDispute.json?.ok === true,
    event_id: oppositeWithDispute.json?.event_id || null,
  };

  const summary = await post("/v0/runs/summary", { run_id: RUN_ID });
  const scars = summary.json?.summary?.export_scars || [];
  const badges = summary.json?.summary?.validation_badges || [];

  const scarForTarget = scars.find((s) => s?.target_key === targetKey(target));
  const badgeForTarget = badges.find((b) => b?.target_key === targetKey(target));
  const report = badgeForTarget?.report || null;

  out.gates.summary_badges_present = {
    pass: Boolean(
      !!scarForTarget &&
      !!badgeForTarget &&
      report &&
      report.schema_check &&
      report.hash_check &&
      report.chain_check &&
      report.anchor_inventory &&
      !Object.prototype.hasOwnProperty.call(report, "proposals")
    ),
    scar: scarForTarget || null,
    badge_event_id: badgeForTarget?.event_id || null,
    badge_verdict: badgeForTarget?.verdict || null,
  };

  out.ok = Object.values(out.gates).every((g) => g.pass === true);
  console.log(JSON.stringify(out, null, 2));
  process.exit(out.ok ? 0 : 1);
}

main().catch((e) => {
  console.error(String(e?.message || e));
  process.exit(1);
});
