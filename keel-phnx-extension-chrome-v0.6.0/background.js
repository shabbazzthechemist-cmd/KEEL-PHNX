const api = globalThis.browser || chrome;

let queue = Promise.resolve();

// Deterministic alarm fallback when bridge is unavailable.
async function pushAlarm(code, details) {
  const key = "alarmQueue";
  const max = 200;
  const rec = { code, now: new Date().toISOString(), details };

  try {
    const cur = await api.storage.local.get({ [key]: [] });
    const q = Array.isArray(cur[key]) ? cur[key] : [];
    q.push(rec);
    while (q.length > max) q.shift();
    await api.storage.local.set({ [key]: q });
  } catch {
    // Best-effort path; console signal remains.
  }

  console.error(`KEEL_ALARM:${code}`, rec);
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function getConfig() {
  return api.storage.local.get({
    runId: "",
    token: "",
    allowedHosts: [],
    startedRuns: {},
  });
}

async function keelFetch(path, token, body) {
  const res = await fetch(`http://127.0.0.1:42069${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-keel-token": token },
    body: JSON.stringify(body),
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.ok === false) {
    const err = new Error(json.error || `keel error: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return json;
}

async function ensureRunStarted(runId, token) {
  const cfg = await getConfig();
  if (cfg.startedRuns?.[runId]) return;

  await keelFetch("/v0/runs/start", token, {
    run_id: runId,
    meta: { source: "extension_v0.6" },
  });

  const startedRuns = { ...(cfg.startedRuns || {}), [runId]: true };
  await api.storage.local.set({ startedRuns });
}

async function invalidateStartedRun(runId) {
  const cfg = await getConfig();
  const startedRuns = { ...(cfg.startedRuns || {}) };
  delete startedRuns[runId];
  await api.storage.local.set({ startedRuns });
}

async function markStartedRun(runId) {
  const cfg = await getConfig();
  const startedRuns = { ...(cfg.startedRuns || {}), [runId]: true };
  await api.storage.local.set({ startedRuns });
}

function hostToMatch(h) {
  return `https://${h}/*`;
}

async function registerContentScriptsIfSupported(allowedHosts) {
  if (!api.scripting?.registerContentScripts) return;

  const id = "keel_phnx_capture";
  try {
    await api.scripting.unregisterContentScripts({ ids: [id] });
  } catch {
    // Ignore missing script registration.
  }

  const matches = (allowedHosts || [])
    .map((h) => String(h || "").trim())
    .filter(Boolean)
    .map(hostToMatch);

  if (!matches.length) return;

  try {
    await api.scripting.registerContentScripts([
      {
        id,
        js: ["content.js"],
        matches,
        runAt: "document_start",
        allFrames: false,
      },
    ]);
  } catch (e) {
    await pushAlarm("content_script_registration_failed", {
      error: String(e?.message || e),
      matches,
    });
  }
}

api.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local") return;
  if (!changes.allowedHosts) return;

  const cfg = await getConfig();
  await registerContentScriptsIfSupported(cfg.allowedHosts);
});

api.runtime.onInstalled?.addListener(async () => {
  const cfg = await getConfig();
  await registerContentScriptsIfSupported(cfg.allowedHosts);
});

api.runtime.onStartup?.addListener(async () => {
  const cfg = await getConfig();
  await registerContentScriptsIfSupported(cfg.allowedHosts);
});

async function deliverEvent(msg) {
  const cfg = await getConfig();
  if (!cfg.runId || !cfg.token) {
    throw new Error("missing runId/token (set in extension options)");
  }

  await ensureRunStarted(cfg.runId, cfg.token);

  const max = 3;
  for (let attempt = 1; attempt <= max; attempt++) {
    try {
      const out = await keelFetch("/v0/events/append", cfg.token, {
        run_id: cfg.runId,
        event: msg.event,
      });
      return out;
    } catch (e) {
      const status = e.status || 0;

      // Hard rule: 404 run not found -> invalidate cache, restart run once, retry append once.
      if (status === 404) {
        try {
          await invalidateStartedRun(cfg.runId);
          await keelFetch("/v0/runs/start", cfg.token, {
            run_id: cfg.runId,
            meta: { source: "extension_recovery_404" },
          });
          await markStartedRun(cfg.runId);

          const out = await keelFetch("/v0/events/append", cfg.token, {
            run_id: cfg.runId,
            event: msg.event,
          });
          return out;
        } catch (re) {
          await pushAlarm("append_404_run_not_found_unrecoverable", {
            runId: cfg.runId,
            path: "/v0/events/append",
            host: "127.0.0.1:42069",
            last_error: String(re?.message || re),
          });
          throw re;
        }
      }

      const retryable = status === 0 || status === 429 || (status >= 500 && status < 600);
      if (!retryable || attempt === max) throw e;

      await sleep(150 * attempt);
    }
  }
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.kind !== "keel_event") return;

  // Self-healing queue: never allow permanent rejection poisoning.
  queue = queue
    .catch(() => null)
    .then(() => deliverEvent(msg));

  queue
    .then((out) => sendResponse({ ok: true, out }))
    .catch(async (e) => {
      await pushAlarm("bridge_delivery_failed", { error: String(e?.message || e) });
      sendResponse({ ok: false, error: String(e?.message || e) });
    });

  return true;
});
