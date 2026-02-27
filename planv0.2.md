# KEEL-PHNX v0.3 -> v0.6 Plan (Draft v0.2, Corrected)

## Objective
Land the thread-agreed v0.6 behavior in code (current workspace is still v0.3), then verify with the exact runtime gates agreed in-thread.

## Thread-Locked Decisions (must be preserved)
1. Browser target is Chrome; Firefox parity is not required for this release.
2. Hard send rules:
   - single commit point for `user_input`
   - trigger aggregation (`keydown`/`click`/`submit`) with one commit per tick
   - authoritative dedupe window: 800ms
   - no empty sends; suppress duplicates deterministically
   - when a new send occurs while waiting, emit `user_sent_while_waiting_agent_output`
3. Hard assistant rules:
   - single finalize point for `agent_output`
   - finalize only when scoped to active waiting turn
   - v0 policy: one `turn_id` -> one `agent_output` (no regen capture while idle)
   - idle assistant output emits alarm, not implicit capture
4. Hashing/dedupe must use SHA-256 fingerprints.
5. Runtime recovery on append 404:
   - invalidate stale `startedRuns`
   - re-run `/v0/runs/start`
   - retry append once
   - if still failing, emit deterministic alarm and stop retrying
6. Writer process model:
   - single bridge process per `KEEL_DIR` via lockfile
   - no lock stealing from live PID
   - stale lock takeover only when PID is not alive or lock is unreadable/corrupt
7. Security posture:
   - broad host permission is accepted for v0 only when paired with dynamic registration and explicit documentation
8. Gates required before ship:
   - send spam dedupe gate
   - multi-client same-run integrity gate

## Implementation Ledger (diffs to apply)

### A) Foundation hardening (v0.4/v0.6 set)
1. `extension/manifest.chrome.json`
   - `version` bump
   - host permission includes `https://*/*` for dynamic registration model
   - remove static `content_scripts` block for Chrome path
2. `extension/background.js`
   - dynamic content script registration from `allowedHosts`
   - self-healing queue (`queue.catch().then(...)`)
   - bounded retries for transient localhost failures
3. `extension/content.js`
   - richer capture pipeline with settle scoring and alarms
   - click/submit handling
   - transcript-root retry and explicit capture-unavailable alarm
4. `keel-bridge.mjs`
   - structured HTTP errors (400/401/404/413/500)
   - run existence enforcement for append/audit/head
   - per-run append locking
   - stronger audit checks (`seq`, duplicate event IDs, head-seq match)
5. `keel-verify.mjs`
   - stronger verification (`run_id` continuity, duplicate event IDs, `seq` continuity)
6. Add `tests/multi_client_same_run.mjs`.

### B) Corrections accepted after review
1. `extension/content.js`
   - bootstrap idempotency guard:
     - `BOOTSTRAPPED`
     - `BOOTSTRAP_PROMISE`
     - `CAPTURE_INSTALLED`
   - commit serialization queue (`COMMIT_QUEUE`) to prevent async dedupe races
2. `extension/background.js`
   - 404 recovery updates `startedRuns` truth (`markStartedRun`)
   - alarm queue fallback in `storage.local` with stable console code
3. `keel-bridge.mjs`
   - lockfile + stale-lock handling
   - synchronous best-effort unlock on `exit`
   - unlock on `SIGINT`, `SIGTERM`, `uncaughtException`, `unhandledRejection`
   - `LIVE_LOCK` error code for deterministic propagation
   - tolerate `ENOENT` on stale-lock unlink race

## Execution Steps
1. Confirm baseline files are still v0.3 (already observed).
2. Apply all accepted diffs in this order:
   - `manifest.chrome.json`
   - `background.js`
   - `content.js`
   - `keel-bridge.mjs`
   - `keel-verify.mjs`
   - add `tests/multi_client_same_run.mjs`
3. Run static checks:
   - `node --check` for all changed JS/MJS files
4. Run runtime gate #1 (send spam):
   - simulate near-simultaneous keydown+click+submit
   - assert one `user_input` per dedupe window/fingerprint
5. Run runtime gate #2 (multi-client same-run):
   - start isolated bridge
   - concurrent appends from 2 clients
   - assert `/v0/runs/audit` and `keel-verify` both pass
6. Document results and only ship on both green gates.

## Explicit Acceptance Criteria
1. Send-spam gate:
   - `duplicate_user_input_detected === false`
   - no repeated `send_fingerprint` accepted inside 800ms
2. Multi-client gate:
   - `audit.ok === true`
   - no `hash_chain_break`, `head_mismatch`, `seq_discontinuity`, or duplicate-event errors
   - verifier exits 0

## Non-Goals for This Cut
1. Firefox parity.
2. Regen content capture while idle.
3. Session-token redesign beyond current v0-local-secret model.
