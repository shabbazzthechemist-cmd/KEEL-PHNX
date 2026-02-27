# KEEL-PHNX v0.3 -> v0.6 Plan (Draft v0.3, Ultimate Recursive Review)

## 0) Recursive Review Snapshot (Current Disk State)

1. Workspace is still the original v0.3 bundle + planning docs:
   - source files: `keel-bridge.mjs`, `keel-verify.mjs`, `extension/*`
   - planning files: `planv0.1.md`, `planv0.2.md`
2. No symlinks found.
3. File-type census shows only text/JSON/HTML/JS (no binaries/archives).
4. macOS quarantine xattr exists on shipped source files (download provenance marker).
5. Current code markers confirm v0.3 state:
   - `manifest.chrome.json` still `version: 0.3.0` with static `content_scripts`
   - `background.js` still `extension_v0.3` and old queue behavior
   - `content.js` still `dom_capture_v0.3:*` and no hard-rule dedupe state machine
   - `keel-bridge.mjs` still v0.1 internals (`ensureRun` auto-create, no lockfile, no typed HTTP errors, no per-run lock)
   - `keel-verify.mjs` still hash/head checks only (no seq/duplicate/run-id continuity checks)

## 1) Thread-Locked v0.6 Requirements (Authoritative)

1. Chrome is the shipping target for this cut.
2. Hard user-send rules:
   - single emit point (`commitUserSend`)
   - trigger aggregation (`keydown` + `click` + `submit`)
   - SHA-256 send fingerprint
   - authoritative dedupe window `800ms`
3. Hard assistant-completion rules:
   - single finalize point for `agent_output`
   - one `turn_id -> one agent_output` in v0
   - idle/orphan assistant output emits deterministic alarm, not implicit capture
4. Bootstrap/listener install must be idempotent.
5. Background delivery:
   - self-healing queue
   - bounded retries for transient failures
   - append 404 recovery: invalidate cache -> restart run -> retry once -> alarm on failure
6. Bridge reliability:
   - run existence checks (no implicit create on inspect)
   - per-run append serialization
   - lockfile with live PID no-steal rule
   - race-safe stale lock overwrite
   - unlock on exit/signals/crash paths
7. Verifier/audit strengthening:
   - seq continuity
   - duplicate `event_id` detection
   - run id consistency (verifier)
   - head seq mismatch checks
8. Runtime gates required before ship:
   - send-spam duplicate prevention gate
   - multi-client same-run integrity gate

## 2) Accepted Diff Ledger (from thread)

### Accepted foundation diffs
1. `extension/manifest.chrome.json`: v0.4+ permission/injection model for Chrome.
2. `extension/background.js`: dynamic registration + queue hardening + retries.
3. `extension/content.js`: stronger capture flow, settle evidence, alarms.
4. `keel-bridge.mjs`: typed HTTP errors, append/audit/head hardening, lock/serialization path.
5. `keel-verify.mjs`: stronger integrity invariants.
6. `tests/multi_client_same_run.mjs`: concurrent append gate.

### Accepted correction diffs
1. Boot/install race + async send dedupe race fixes in `extension/content.js`.
2. 404 recovery cache truth fix in `extension/background.js` (`markStartedRun` path).
3. Lockfile anti-theft and exit/crash unlock fixes in `keel-bridge.mjs`.
4. Final nits:
   - tolerate `ENOENT` on stale-lock unlink race
   - deterministic `LIVE_LOCK` error code handling (no message substring checks)

## 3) Work Plan (Execution Order)

### Phase A: Apply Code Diffs (no partial merges)
1. Apply final accepted `extension/content.js` (v0.6 rules + idempotency + commit queue).
2. Apply final accepted `extension/background.js` (dynamic registration, retry, 404 recovery, alarm queue).
3. Apply final accepted `extension/manifest.chrome.json` (Chrome v0.6 model).
4. Apply final accepted `keel-bridge.mjs` (typed errors, run checks, per-run lock, lockfile, LIVE_LOCK handling).
5. Apply final accepted `keel-verify.mjs` (seq + duplicate + run-id checks).
6. Add `tests/multi_client_same_run.mjs`.

### Phase B: Static Integrity Checks
1. Syntax:
   - `node --check extension/content.js`
   - `node --check extension/background.js`
   - `node --check keel-bridge.mjs`
   - `node --check keel-verify.mjs`
2. Marker assertions (grep):
   - `BOOTSTRAPPED`, `BOOTSTRAP_PROMISE`, `CAPTURE_INSTALLED`, `SEND_DEDUPE_MS`
   - `registerContentScripts`, `alarmQueue`, `append_404_run_not_found_unrecoverable`
   - `LOCK_PATH`, `LIVE_LOCK`, `withRunLock`, `readBodyJson`
   - `seq_discontinuity`, `duplicate_event_id`, `head_seq_mismatch`

### Phase C: Runtime Gate 1 (Send Spam)
1. Simulate near-simultaneous send signals (keydown+click+submit).
2. Assert:
   - one `user_input` commit for identical payload within `800ms`
   - duplicate attempts are suppressed/alarmed, not committed.

### Phase D: Runtime Gate 2 (Multi-Client Same-Run)
1. Start bridge with isolated `KEEL_DIR`.
2. Fire concurrent append traffic from two clients into one run.
3. Assert:
   - `/v0/runs/audit` => `ok: true`
   - no `hash_chain_break`, `head_mismatch`, `seq_discontinuity`, `duplicate_event_id`
   - `node keel-verify.mjs` exits `0`

### Phase E: Release Hygiene
1. Update docs/version callouts from v0.3 references to v0.6 where applicable.
2. Save post-change file hash manifest (sha256) for reproducibility.
3. Record runtime gate outputs in release notes.

## 4) Risk Controls / Failure Discipline

1. If either runtime gate fails, stop and run full RCA before additional edits.
2. Do not ship if only one gate is green.
3. Keep rollback path:
   - retain pre-change hashes and file copies (or patch checkpoint)
   - revert as one unit if regression appears.

## 5) Ship Criteria (Must All Be True)

1. All changed files pass syntax check.
2. Send-spam gate proves no duplicate `user_input` within dedupe window.
3. Multi-client gate proves contiguous, auditable chain integrity.
4. Bridge lock behavior blocks live lock theft and safely recovers stale lock.
5. Thread-locked decisions remain intact (Chrome target, v0 regen policy, explicit alarms).

## 6) Explicit Non-Goals for v0.6 Cut

1. Firefox parity.
2. Regen content capture while idle.
3. Session-token redesign (kept as future hardening).
