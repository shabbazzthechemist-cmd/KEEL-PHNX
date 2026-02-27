# KEEL-PHNX

Extension of the "I" into effective personhood.

## Codex Bundle (v0.6.0)

This bundle contains:
- `keel-bridge.mjs` — localhost writer (append-only NDJSON + hash chain + strengthened audit)
- `keel-verify.mjs` — offline verifier (hash chain + seq/run-id/duplicate checks + coverage report)
- `extension/` — browser capture extension (turn-aware capture, settle evidence, alarms)

## Quick start (writer)

```bash
cd KEEL-PHNX_codex_bundle
export KEEL_TOKEN="$(openssl rand -hex 32)"
export KEEL_DIR="$HOME/keel-phnx/runs"
node keel-bridge.mjs
```

Health:

```bash
curl -sS http://127.0.0.1:42069/health
```

## Extension

Target for this release: **Chrome MV3**.

To load:
- Chrome: rename `extension/manifest.chrome.json` to `extension/manifest.json`, then load unpacked.

Configure in extension Options:
- Run ID
- KEEL Token
- Allowed hosts (one per line). Capture is OFF unless host is listed.

Notes:
- Content script registration is dynamic from `allowedHosts` (Chrome MV3 scripting API).
- Capture emits `user_input` and `agent_output` with settle evidence.
- Duplicate send suppression is enforced with an 800ms dedupe window.

## Verify a run

```bash
node keel-verify.mjs --dir "$HOME/keel-phnx/runs" --run "0xKEELPHNX_YYYYMMDD_run001" --tail 12
```

## Concurrency Gate Test

With bridge running and `KEEL_TOKEN` exported:

```bash
RUN_ID="0xKEELPHNX_multiclient_$(date +%s)" N=80 node tests/multi_client_same_run.mjs
```

## Safety posture

- Extension is **transcript-only** and **fail-closed**.
- It only logs on hosts explicitly allowed in options.
- Bridge enforces localhost + token auth.
- Writer is single-process locked per `KEEL_DIR` and rejects live lock takeover.
- Audit/verifier check chain integrity plus sequence and duplicate constraints.

Generated: 2026-02-26T20:03:04.675744Z
