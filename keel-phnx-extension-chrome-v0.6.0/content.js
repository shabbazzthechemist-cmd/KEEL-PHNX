const api = globalThis.browser || chrome;

// Hard rule: one install per tab.
let BOOTSTRAPPED = false;
let BOOTSTRAP_PROMISE = null;
let CAPTURE_INSTALLED = false;

// Hard rule: serialize commits to prevent async dedupe races.
let COMMIT_QUEUE = Promise.resolve();

const SEND_DEDUPE_MS = 800;
const OUTPUT_DEDUPE_MS = 2000;

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hostAllowed(allowedHosts) {
  const h = location.hostname;
  return Array.isArray(allowedHosts) && allowedHosts.includes(h);
}

function safeUrl() {
  // No query/hash to avoid leaking IDs/tokens.
  return `${location.origin}${location.pathname}`;
}

function isForbiddenAncestor(el) {
  const forbidden = ["NAV", "ASIDE", "HEADER", "FOOTER"];
  let cur = el;
  while (cur && cur !== document.documentElement) {
    if (forbidden.includes(cur.tagName)) return true;
    cur = cur.parentElement;
  }
  return false;
}

function findTranscriptRoot() {
  const byRole = document.querySelector(
    '[role="log"], [aria-label*="Conversation" i], [aria-label*="Chat" i]'
  );
  if (byRole && !isForbiddenAncestor(byRole)) return byRole;

  const candidates = Array.from(document.querySelectorAll("main, section, div"))
    .filter((el) => el.scrollHeight > 800 && el.clientHeight > 200)
    .slice(0, 40);

  for (const el of candidates) {
    if (isForbiddenAncestor(el)) continue;
    const msgs = el.querySelectorAll("p, pre, code");
    if (msgs.length >= 6) return el;
  }
  return null;
}

function normalizeText(s) {
  return (s || "").replace(/\s+/g, " ").trim();
}

function newTurnId() {
  const r = Math.random().toString(16).slice(2);
  return `turn_${Date.now()}_${r}`;
}

async function emit(type, actor_id, payload) {
  const event = {
    type,
    actor_id,
    source: `dom_capture_v0.6:${location.hostname}`,
    payload,
  };

  return new Promise((resolve) => {
    api.runtime.sendMessage({ kind: "keel_event", event }, (resp) => resolve(resp));
  });
}

function captureSendFromTarget(target) {
  let raw = "";
  if (target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement) {
    raw = target.value || "";
  } else if (target instanceof HTMLElement && target.isContentEditable) {
    raw = target.innerText || "";
  }
  raw = raw.trim();
  return raw || null;
}

function findComposerNear(rootEl) {
  if (!rootEl) return null;
  const ta = rootEl.querySelector("textarea");
  if (ta) return ta;
  const inp = rootEl.querySelector("input[type='text'], input:not([type])");
  if (inp) return inp;
  const ce = rootEl.querySelector("[contenteditable='true']");
  if (ce) return ce;
  return null;
}

function composerEnabled(el) {
  if (!el) return null;
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) return !el.disabled;
  if (el instanceof HTMLElement && el.isContentEditable) {
    const ariaDisabled = el.getAttribute("aria-disabled");
    if (ariaDisabled === "true") return false;
    return el.isContentEditable;
  }
  return null;
}

function cursorPresentInText(text) {
  const t = (text || "").trimEnd();
  const last = t.slice(-3);
  return /[▌█▋▍▎▏]/.test(last);
}

function actionBarPresentNear(el) {
  if (!(el instanceof HTMLElement)) return false;

  const wrapper =
    el.closest("article") ||
    el.closest("[role='article']") ||
    el.closest("[data-message]") ||
    el.parentElement;

  if (!wrapper || isForbiddenAncestor(wrapper)) return false;

  const btns = wrapper.querySelectorAll("button");
  const svgs = wrapper.querySelectorAll("svg");
  return btns.length >= 1 && svgs.length >= 1;
}

// De-duplicating extraction: only top-most allowed tags.
function extractTextFromMessage(msgEl) {
  if (!msgEl || isForbiddenAncestor(msgEl)) return null;

  const allowTags = new Set(["P", "SPAN", "LI", "PRE", "CODE", "BLOCKQUOTE", "A"]);
  const denyTags = new Set(["BUTTON", "INPUT", "TEXTAREA", "SELECT", "SVG"]);
  const allowSelector = Array.from(allowTags)
    .map((t) => t.toLowerCase())
    .join(",");

  const parts = [];
  const stack = [msgEl];

  while (stack.length) {
    const el = stack.pop();
    if (!(el instanceof HTMLElement)) continue;
    if (denyTags.has(el.tagName)) continue;
    if (el.getAttribute("aria-hidden") === "true") continue;

    const isAllowed = allowTags.has(el.tagName);
    if (isAllowed) {
      const anc = el.parentElement?.closest(allowSelector);
      if (!anc || anc === msgEl) {
        const txt = el.innerText;
        if (txt && txt.trim()) parts.push(txt.trim());
      }
      continue;
    }

    for (let i = el.children.length - 1; i >= 0; i--) stack.push(el.children[i]);
  }

  const out = parts.join("\n").trim();
  return out.length ? out : null;
}

// Hard rule: listeners can only signal; only commitUserSend emits user_input.
const sendAgg = {
  scheduled: false,
  triggers: new Set(),
  best: null, // { composerEl, raw, priority }
  last: { fp: null, ts: 0 },

  priority(trigger) {
    if (trigger === "submit") return 3;
    if (trigger === "click") return 2;
    if (trigger === "keydown") return 1;
    return 0;
  },

  signal(trigger, composerEl, rawMaybe) {
    this.triggers.add(trigger);
    const raw = rawMaybe || captureSendFromTarget(composerEl);
    if (!raw) return;

    const p = this.priority(trigger);
    if (!this.best || p > this.best.priority) {
      this.best = { composerEl, raw, priority: p };
    }

    if (!this.scheduled) {
      this.scheduled = true;
      queueMicrotask(() => this.flush());
    }
  },

  async flush() {
    this.scheduled = false;
    const best = this.best;
    const triggers = Array.from(this.triggers);
    this.best = null;
    this.triggers.clear();

    if (!best?.raw) return;

    COMMIT_QUEUE = COMMIT_QUEUE
      .catch(() => null)
      .then(() => commitUserSend(best.raw, best.composerEl, triggers));
    return COMMIT_QUEUE;
  },
};

function composerSignature(el) {
  if (!el) return "none";
  const tag = el.tagName || "X";
  const ce = el.isContentEditable ? "ce" : "in";
  const hasForm = el.closest?.("form") ? "form" : "nof";
  const id = el.id ? `#${el.id}` : "";
  const name = el.name ? `:${el.name}` : "";
  return `${tag}|${ce}|${hasForm}${id}${name}`.slice(0, 96);
}

// State machine
let waiting = null;
let lastFocusedComposer = null;
let lastIdleAssistantAlarmTs = 0;

function clearWaiting() {
  if (waiting?.timeout_id) clearTimeout(waiting.timeout_id);
  if (waiting?.tick_timer) clearTimeout(waiting.tick_timer);
  waiting = null;
}

function startCoverageTimer(turn_id) {
  return setTimeout(async () => {
    if (!waiting || waiting.turn_id !== turn_id) return;
    await emit("challenge", "keel", {
      kind: "capture_alarm",
      alarm: "no_agent_output_after_send",
      turn_id,
      seconds: 60,
      url: safeUrl(),
      ts_capture: new Date().toISOString(),
    });
  }, 60_000);
}

function settleScore({ stable_ms, cursor_gone, composer_enabled, actionbar_present }) {
  let score = 0;
  if (stable_ms >= 450) score += 1;
  if (stable_ms >= 900) score += 1;
  if (stable_ms >= 1400) score += 1;
  if (cursor_gone) score += 2;
  if (composer_enabled === true) score += 1;
  if (actionbar_present) score += 1;
  return score;
}

async function commitUserSend(raw, composerEl, triggerEvidence) {
  const now = Date.now();
  const url = safeUrl();
  const norm = normalizeText(raw);
  if (!norm) return;

  const fp = await sha256Hex(`${norm}|${url}|${composerSignature(composerEl)}`);

  if (sendAgg.last.fp === fp && now - sendAgg.last.ts < SEND_DEDUPE_MS) {
    await emit("challenge", "keel", {
      kind: "capture_alarm",
      alarm: "duplicate_user_send_suppressed",
      url,
      send_fingerprint: fp,
      dedupe_ms: SEND_DEDUPE_MS,
      triggers: triggerEvidence,
      ts_capture: new Date().toISOString(),
    });
    return;
  }

  sendAgg.last = { fp, ts: now };
  const turn_id = newTurnId();

  if (waiting && !waiting.output_committed) {
    await emit("challenge", "keel", {
      kind: "capture_alarm",
      alarm: "user_sent_while_waiting_agent_output",
      previous_turn_id: waiting.turn_id,
      new_turn_id: turn_id,
      url,
      ts_capture: new Date().toISOString(),
    });
  }

  await emit("user_input", "user", {
    turn_id,
    raw_text: raw,
    url,
    ts_capture: new Date().toISOString(),
    send_fingerprint: fp,
    send_trigger_evidence: triggerEvidence,
    dedupe_ms_used: SEND_DEDUPE_MS,
  });

  clearWaiting();
  waiting = {
    turn_id,
    user_norm: norm,
    send_fp: fp,
    send_ts: now,
    composerEl,
    candidate_el: null,
    last_norm: null,
    last_change_at: null,
    tick_timer: null,
    timeout_id: startCoverageTimer(turn_id),
    output_committed: false,
    output_fp: null,
    output_ts: 0,
  };

  scheduleTick();
}

function isPromptEcho(candidateNorm, userNorm) {
  if (!candidateNorm || !userNorm) return false;
  if (candidateNorm === userNorm) return true;
  if (!candidateNorm.includes(userNorm)) return false;
  const extra = candidateNorm.replace(userNorm, "").trim();
  return extra.length <= 12;
}

function tryAdoptCandidateMessage(el) {
  if (!waiting || waiting.candidate_el) return;
  if (!(el instanceof HTMLElement)) return;
  if (isForbiddenAncestor(el)) return;

  const txt = extractTextFromMessage(el);
  if (!txt) return;

  const norm = normalizeText(txt);
  if (isPromptEcho(norm, waiting.user_norm)) return;

  waiting.candidate_el = el;
  waiting.last_norm = norm;
  waiting.last_change_at = Date.now();
}

async function finalizeAssistantCompletion(reason) {
  if (!waiting?.candidate_el) return;

  if (waiting.output_committed) {
    await emit("challenge", "keel", {
      kind: "capture_alarm",
      alarm: "duplicate_agent_output_attempt",
      turn_id: waiting.turn_id,
      url: safeUrl(),
      ts_capture: new Date().toISOString(),
    });
    return;
  }

  const txt = extractTextFromMessage(waiting.candidate_el);
  if (!txt) return;

  const url = safeUrl();
  const norm = normalizeText(txt);
  const fp = await sha256Hex(`${norm}|${url}|assistant:${location.hostname}`);
  const now = Date.now();

  if (waiting.output_fp === fp && now - waiting.output_ts < OUTPUT_DEDUPE_MS) {
    return;
  }

  const stable_ms = Date.now() - (waiting.last_change_at || Date.now());
  const cursor_gone = !cursorPresentInText(txt);
  const comp_en = composerEnabled(waiting.composerEl);
  const actionbar = actionBarPresentNear(waiting.candidate_el);

  const evidence = {
    stable_ms,
    cursor_gone,
    composer_enabled: comp_en,
    actionbar_present: actionbar,
    settle_score: settleScore({
      stable_ms,
      cursor_gone,
      composer_enabled: comp_en,
      actionbar_present: actionbar,
    }),
    reason,
  };

  await emit("agent_output", `assistant:${location.hostname}`, {
    turn_id: waiting.turn_id,
    content: txt,
    url,
    ts_capture_final: new Date().toISOString(),
    completion_fingerprint: fp,
    dedupe_output_ms_used: OUTPUT_DEDUPE_MS,
    settle_evidence: evidence,
  });

  waiting.output_committed = true;
  waiting.output_fp = fp;
  waiting.output_ts = now;
  clearWaiting();
}

function scheduleTick() {
  if (!waiting) return;
  if (waiting.tick_timer) clearTimeout(waiting.tick_timer);

  waiting.tick_timer = setTimeout(async () => {
    if (!waiting) return;
    if (!waiting.candidate_el) return scheduleTick();

    const txt = extractTextFromMessage(waiting.candidate_el);
    if (!txt) return scheduleTick();

    const norm = normalizeText(txt);
    if (norm !== waiting.last_norm) {
      waiting.last_norm = norm;
      waiting.last_change_at = Date.now();
    }

    const stable_ms = Date.now() - (waiting.last_change_at || Date.now());
    const cursor_gone = !cursorPresentInText(txt);
    const comp_en = composerEnabled(waiting.composerEl);
    const actionbar = actionBarPresentNear(waiting.candidate_el);

    const score = settleScore({
      stable_ms,
      cursor_gone,
      composer_enabled: comp_en,
      actionbar_present: actionbar,
    });

    if (score >= 4) return finalizeAssistantCompletion("score_threshold_met");
    if (stable_ms >= 3500) return finalizeAssistantCompletion("hard_fallback_stable_3500ms");
    scheduleTick();
  }, 250);
}

function installSendListeners() {
  document.addEventListener(
    "focusin",
    (e) => {
      const t = e.target;
      if (t instanceof HTMLTextAreaElement || t instanceof HTMLInputElement) {
        lastFocusedComposer = t;
      } else if (t instanceof HTMLElement && t.isContentEditable) {
        lastFocusedComposer = t;
      }
    },
    true
  );

  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key !== "Enter") return;
      if (e.shiftKey) return;

      const t = e.target;
      const raw = captureSendFromTarget(t);
      if (!raw) return;
      sendAgg.signal("keydown", t, raw);
    },
    true
  );

  document.addEventListener(
    "click",
    (e) => {
      const btn = e.target?.closest?.("button");
      if (!btn) return;
      if (isForbiddenAncestor(btn)) return;

      const form = btn.closest("form");
      const composer = findComposerNear(form) || lastFocusedComposer;
      const raw = captureSendFromTarget(composer);
      if (!raw) return;
      sendAgg.signal("click", composer, raw);
    },
    true
  );

  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target instanceof HTMLFormElement ? e.target : null;
      const composer = findComposerNear(form) || lastFocusedComposer;
      const raw = captureSendFromTarget(composer);
      if (!raw) return;
      sendAgg.signal("submit", composer, raw);
    },
    true
  );
}

function installObserver(root) {
  const obs = new MutationObserver(async (mutations) => {
    for (const m of mutations) {
      for (const n of m.addedNodes) {
        if (!(n instanceof HTMLElement)) continue;
        if (isForbiddenAncestor(n)) continue;

        if (waiting && !waiting.candidate_el) {
          tryAdoptCandidateMessage(n);
        } else if (!waiting) {
          const now = Date.now();
          if (now - lastIdleAssistantAlarmTs > 5000) {
            const looksLikeMsg = n.matches?.("p,pre,code") || n.querySelector?.("p,pre,code");
            if (looksLikeMsg) {
              lastIdleAssistantAlarmTs = now;
              await emit("challenge", "keel", {
                kind: "capture_alarm",
                alarm: "assistant_output_detected_while_idle",
                url: safeUrl(),
                ts_capture: new Date().toISOString(),
              });
            }
          }
        }
      }
    }
  });

  obs.observe(root, { childList: true, subtree: true, characterData: true });
}

async function bootstrapCapture() {
  if (CAPTURE_INSTALLED) return;

  const cfg = await api.storage.local.get({ allowedHosts: [] });
  if (!hostAllowed(cfg.allowedHosts)) return;

  const maxMs = 30_000;
  const startedAt = Date.now();
  let attempts = 0;
  let root = null;

  while (!root && Date.now() - startedAt < maxMs) {
    attempts++;
    root = findTranscriptRoot();
    if (root) break;

    const wait = Math.min(200 + attempts * 150, 2000);
    await new Promise((r) => setTimeout(r, wait));
  }

  if (!root) {
    await emit("challenge", "keel", {
      kind: "capture_alarm",
      alarm: "capture_unavailable_transcript_root_not_found",
      url: safeUrl(),
      attempts,
      waited_ms: Date.now() - startedAt,
      ts_capture: new Date().toISOString(),
    });
    return;
  }

  installSendListeners();
  installObserver(root);
  CAPTURE_INSTALLED = true;
}

function bootstrapOnce() {
  if (BOOTSTRAP_PROMISE) return BOOTSTRAP_PROMISE;
  BOOTSTRAP_PROMISE = bootstrapCapture().catch(() => {});
  return BOOTSTRAP_PROMISE;
}

(async function boot() {
  if (BOOTSTRAPPED) return;
  BOOTSTRAPPED = true;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => bootstrapOnce(), { once: true });
  }
  bootstrapOnce();
})();
