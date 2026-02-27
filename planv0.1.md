# KEEL-PHNX v0.3 -> v0.6 Plan (Draft v0.1)

## Goal
Upgrade the codebase from current v0.3 behavior to the thread-agreed v0.6 hardening set:
- stronger capture dedupe and idempotency
- improved bridge reliability/locking
- stronger recovery/alarm behavior
- runtime verification gates

## Phase 1: Baseline + Patch Application
1. Confirm current workspace snapshot (expected: v0.3).
2. Apply accepted diffs for:
   - `extension/content.js`
   - `extension/background.js`
   - `keel-bridge.mjs`
   - `extension/manifest.chrome.json`
   - `keel-verify.mjs`
3. Add new test file:
   - `tests/multi_client_same_run.mjs`

## Phase 2: Static Validation
1. Run syntax checks:
   - `node --check extension/content.js`
   - `node --check extension/background.js`
   - `node --check keel-bridge.mjs`
   - `node --check keel-verify.mjs`
2. Quick grep checks for expected symbols:
   - `BOOTSTRAPPED`, `SEND_DEDUPE_MS`, `registerContentScripts`, `LOCK_PATH`, `LIVE_LOCK`.

## Phase 3: Runtime Validation
1. Start bridge with isolated temp run directory.
2. Run multi-client same-run stress test.
3. Run audit and verify:
   - `/v0/runs/audit`
   - `node keel-verify.mjs --dir ... --run ...`
4. Confirm chain/audit are green.

## Phase 4: Capture Behavior Validation
1. Run enter+click+submit spam check.
2. Confirm no duplicate `user_input` emits under dedupe window.
3. Confirm assistant completion finalizes once per turn.

## Phase 5: Docs + Release Gate
1. Update README version and operational notes.
2. Record final pass/fail outputs for the two runtime gates.
3. Ship only if all gates pass.
