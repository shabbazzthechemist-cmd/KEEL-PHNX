const api = globalThis.browser || chrome;

const els = {
  runId: document.getElementById("runId"),
  token: document.getElementById("token"),
  hosts: document.getElementById("hosts"),
  save: document.getElementById("save"),
  status: document.getElementById("status"),
};

async function load() {
  const { runId, token, allowedHosts } = await api.storage.local.get({
    runId: "",
    token: "",
    allowedHosts: [],
  });
  els.runId.value = runId || "";
  els.token.value = token || "";
  els.hosts.value = (allowedHosts || []).join("\n");
}

async function save() {
  const runId = els.runId.value.trim();
  const token = els.token.value.trim();
  const allowedHosts = els.hosts.value
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  await api.storage.local.set({ runId, token, allowedHosts });

  els.status.textContent = "saved";
  setTimeout(() => (els.status.textContent = ""), 900);
}

els.save.addEventListener("click", save);
load();
