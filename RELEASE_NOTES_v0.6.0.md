# KEEL-PHNX v0.6.0 Release Notes

Date: 2026-02-27

## Summary
v0.6.0 hardens capture dedupe, delivery recovery, and ledger integrity under concurrency.

## Shipped Changes
1. Chrome MV3 extension moved to dynamic content script registration by allowed hosts.
2. Capture pipeline now enforces:
   - single send commit point
   - aggregated send triggers
   - SHA-256 fingerprints
   - dedupe windows (send/output)
   - one `turn_id -> one agent_output` (v0 policy)
3. Background delivery now includes:
   - self-healing queue
   - bounded retries
   - append-404 recovery (`invalidate -> start -> mark -> retry`)
   - persisted fallback alarm queue
4. Bridge now includes:
   - typed HTTP errors
   - no implicit run creation on audit/head
   - per-run append locking
   - lockfile with live-PID no-steal behavior
5. Audit and verifier now validate:
   - hash chain
   - sequence continuity
   - duplicate event IDs
   - head consistency

## Validation Gates
1. Send spam dedupe gate: PASS (`user_input` dedupe observed).
2. Multi-client same-run gate: PASS (`audit.ok=true`, verifier `ok=true`, no integrity problems).

## Notes
1. Release target is Chrome.
2. Firefox parity is out of scope for this cut.
