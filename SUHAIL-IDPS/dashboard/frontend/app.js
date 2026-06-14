/* SUHAIL-IDPS dashboard runtime.
 * Single-page app with hash routing across: Overview, Live, Alerts, Sources,
 * Models, Settings. Consumes the Flask backend over REST + Server-Sent Events.
 */
(() => {
  "use strict";

  const API = location.protocol.startsWith("http") ? location.origin : "http://localhost:5000";
  const $ = (id) => document.getElementById(id);
  const el = (sel, root = document) => root.querySelector(sel);

  // ---- shared state ----
  const state = {
    events: [],          // newest first
    timeline: [],        // threat score points
    alerts: [],
    health: null,
    stats: null,
    blocked: [],
    interfaces: [],
    route: "overview",
    eventFilter: "all",
    sourceFilter: "",
    paused: false,
  };
  const MAX_EVENTS = 400;
  const MAX_TIMELINE = 120;

  // ---------------------------------------------------------------- utils
  const fmt = (v, d = 3) =>
    v === null || v === undefined || Number.isNaN(Number(v)) ? "--" : Number(v).toFixed(d);
  const pct = (v) => `${Math.round((Number(v) || 0) * 100)}%`;
  const timeStr = (iso) => new Date(iso).toLocaleTimeString();
  const escapeHtml = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function api(path, options = {}) {
    const res = await fetch(`${API}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    const ct = res.headers.get("content-type") || "";
    return ct.includes("json") ? res.json() : res.text();
  }

  function toast(message, kind = "info") {
    const box = $("toasts");
    if (!box) return;
    const node = document.createElement("div");
    node.className = `toast ${kind}`;
    node.innerHTML = message;
    box.appendChild(node);
    setTimeout(() => node.remove(), 5200);
  }

  function setLive(stateName, text) {
    document.querySelectorAll(".live-dot").forEach((d) => (d.className = `dot live-dot ${stateName}`));
    document.querySelectorAll(".live-text").forEach((t) => (t.textContent = text));
  }

  // ---------------------------------------------------------------- routing
  const PAGES = ["overview", "live", "alerts", "sources", "models", "settings"];
  function route() {
    const hash = (location.hash || "#overview").slice(1);
    state.route = PAGES.includes(hash) ? hash : "overview";
    PAGES.forEach((p) => {
      const page = $(`page-${p}`);
      if (page) page.classList.toggle("active", p === state.route);
      const link = el(`.nav a[href="#${p}"]`);
      if (link) link.classList.toggle("active", p === state.route);
    });
    renderRoute();
  }

  function renderRoute() {
    if (state.route === "overview") renderOverview();
    else if (state.route === "live") renderLive();
    else if (state.route === "alerts") renderAlerts();
    else if (state.route === "sources") renderSources();
    else if (state.route === "models") renderModels();
    else if (state.route === "settings") renderSettings();
  }

  // ---------------------------------------------------------------- ingest
  function ingest(event) {
    if (state.paused) return;
    state.events.unshift(event);
    if (state.events.length > MAX_EVENTS) state.events.pop();
    state.timeline.push(event.result.threat_score || 0);
    if (state.timeline.length > MAX_TIMELINE) state.timeline.shift();

    const status = event.result.status;
    if ((status === "ATTACK" || status === "SUSPICIOUS") && event.source !== "api") {
      const sev = event.result.severity || "";
      toast(
        `<b>${status}</b> ${escapeHtml(event.metadata.src_ip || "unknown")} &rarr; ${escapeHtml(event.metadata.dst_ip || "?")}<br><span class="mono">${escapeHtml(event.result.reason)}</span>`,
        status.toLowerCase()
      );
    }
    // live re-render only the active page's volatile bits
    if (state.route === "overview") renderOverviewLive(event);
    if (state.route === "live") renderLiveTable();
    updateNavPips();
  }

  // ---------------------------------------------------------------- nav pips
  function updateNavPips() {
    const s = state.stats;
    if (!s) return;
    const setPip = (page, value, alert) => {
      const link = el(`.nav a[href="#${page}"] .pip`);
      if (!link) return;
      link.textContent = value;
      link.classList.toggle("alert", !!alert);
    };
    setPip("alerts", s.alert_count || 0, (s.attacks || 0) > 0);
    setPip("sources", s.blocked_count || 0, (s.blocked_count || 0) > 0);
  }

  // ---------------------------------------------------------------- charts
  function lineChart(canvasId, points, opts = {}) {
    const canvas = $(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = (canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1));
    const H = (canvas.height = canvas.clientHeight * (window.devicePixelRatio || 1));
    const dpr = window.devicePixelRatio || 1;
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = "#0f1318";
    ctx.fillRect(0, 0, W, H);
    ctx.strokeStyle = "#222a32";
    ctx.lineWidth = 1 * dpr;
    for (let i = 1; i < 4; i++) {
      const y = (H / 4) * i;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }
    if (!points.length) return;
    const max = opts.max || 1;
    const pad = 10 * dpr;
    const step = (W - pad * 2) / Math.max(points.length - 1, 1);
    const yOf = (v) => H - pad - (Math.min(v / max, 1) * (H - pad * 2));

    // area fill
    ctx.beginPath();
    points.forEach((v, i) => {
      const x = pad + i * step, y = yOf(v);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.lineTo(pad + (points.length - 1) * step, H - pad);
    ctx.lineTo(pad, H - pad);
    ctx.closePath();
    ctx.fillStyle = opts.fill || "rgba(103,183,220,.12)";
    ctx.fill();

    // line
    ctx.beginPath();
    points.forEach((v, i) => {
      const x = pad + i * step, y = yOf(v);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = opts.color || "#67b7dc";
    ctx.lineWidth = 2.5 * dpr;
    ctx.stroke();

    if (opts.dots) {
      points.forEach((v, i) => {
        const x = pad + i * step, y = yOf(v);
        ctx.fillStyle = v > 0.75 ? "#ef6666" : v > 0.45 ? "#f0b44c" : "#4fc37b";
        ctx.beginPath(); ctx.arc(x, y, 2.6 * dpr, 0, Math.PI * 2); ctx.fill();
      });
    }
  }

  function barChart(canvasId, entries) {
    const canvas = $(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const W = (canvas.width = canvas.clientWidth * dpr);
    const H = (canvas.height = canvas.clientHeight * dpr);
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = "#0f1318"; ctx.fillRect(0, 0, W, H);
    if (!entries.length) return;
    const max = Math.max(...entries.map((e) => e.value), 1);
    const pad = 28 * dpr;
    const bw = (W - pad) / entries.length;
    entries.forEach((e, i) => {
      const h = (e.value / max) * (H - pad * 1.4);
      const x = i * bw + bw * 0.18;
      const w = bw * 0.64;
      const y = H - pad - h;
      ctx.fillStyle = e.color || "#67b7dc";
      ctx.fillRect(x, y, w, h);
      ctx.fillStyle = "#94a3af";
      ctx.font = `${11 * dpr}px Inter, sans-serif`;
      ctx.textAlign = "center";
      ctx.fillText(e.label, x + w / 2, H - pad + 16 * dpr);
      ctx.fillStyle = "#eef3f6";
      ctx.fillText(String(e.value), x + w / 2, y - 5 * dpr);
    });
  }

  // ---------------------------------------------------------------- barriers
  function renderBarriers(result, prefix) {
    const map = {
      routine: result.barriers.routine_xgboost,
      context: result.barriers.context_transformer,
      zero: result.barriers.zero_day_autoencoder,
    };
    Object.entries(map).forEach(([key, barrier]) => {
      if (!barrier) return;
      const id = `${prefix}${key.charAt(0).toUpperCase()}${key.slice(1)}`;
      const card = $(`${id}Card`);
      if (!card) return;
      const score = barrier.score;
      const threshold = Number(barrier.threshold || 1);
      const ratio = score === null || score === undefined ? 0 : (Number(score) / Math.max(threshold, 1e-6)) * 70;
      const meterPct = Math.min(100, Math.max(0, ratio));
      const st = (barrier.state || "WAITING").toLowerCase();
      const cls = st === "alert" ? "alert" : st === "pass" ? "pass" : st === "unavailable" ? "unavailable" : "waiting";
      card.className = `barrier ${cls}`;
      const setT = (suffix, val) => { const n = $(`${id}${suffix}`); if (n) n.textContent = val; };
      setT("Score", fmt(score, key === "zero" ? 5 : 3));
      const meter = $(`${id}Meter`); if (meter) meter.style.width = `${meterPct}%`;
      setT("State", barrier.state || "WAITING");
      setT("Latency", `${fmt(barrier.latency_ms, 1)} ms`);
      const modeTag = $(`${id}Mode`);
      if (modeTag) {
        const mode = barrier.mode || "model";
        modeTag.textContent = mode;
        modeTag.className = `mode-tag ${mode}`;
      }
    });
  }

  // ---------------------------------------------------------------- OVERVIEW
  function renderOverview() {
    const s = state.stats;
    if (s) {
      $("ovTotal").textContent = s.total;
      $("ovNormal").textContent = s.normal;
      $("ovSuspicious").textContent = s.suspicious;
      $("ovAttacks").textContent = s.attacks;
      $("ovBlocked").textContent = s.blocked_count;
      $("ovPpm").textContent = `${s.packets_per_minute} pkt/min`;
      $("ovAttackRate").textContent = `${pct(s.attack_rate)} attack rate`;
      $("ovUptime").textContent = `${Math.floor(s.uptime_seconds / 60)}m uptime`;
      // protocol mix
      const colors = { ICMP: "#ef6666", TCP: "#67b7dc", UDP: "#4fc37b" };
      const entries = Object.entries(s.by_protocol || {})
        .sort((a, b) => b[1] - a[1]).slice(0, 6)
        .map(([k, v]) => ({ label: k, value: v, color: colors[k] || "#7c5cff" }));
      barChart("ovProtoChart", entries);
    }
    if (state.events[0]) renderOverviewLive(state.events[0]);
    lineChart("ovTimeline", state.timeline, { dots: true });
    renderModelHealthList("ovModelHealth");
  }

  function renderOverviewLive(event) {
    const r = event.result;
    const pillEl = $("ovLastDecision");
    if (pillEl) pillEl.innerHTML = `<span class="badge ${r.status.toLowerCase()}">${r.status}</span> ${pct(r.threat_score)}`;
    const seq = $("ovSequenceState");
    if (seq) seq.textContent = `Flow ctx ${r.sequence.length}/${r.sequence.target_length}${r.sequence.padded ? " (early)" : ""}`;
    renderBarriers(r, "ov");
    lineChart("ovTimeline", state.timeline, { dots: true });
  }

  // ---------------------------------------------------------------- LIVE
  function renderLive() {
    populateInterfaceSelect();
    renderLiveTable();
  }

  function renderLiveTable() {
    const tbody = $("liveEventsBody");
    if (!tbody) return;
    const rows = state.events
      .filter((e) => state.eventFilter === "all" || e.result.status === state.eventFilter)
      .filter((e) => !state.sourceFilter || (e.metadata.src_ip || e.metadata.source || "") === state.sourceFilter)
      .slice(0, 120)
      .map((e) => {
        const st = e.result.status;
        const md = e.metadata || {};
        const act = e.action || {};
        const flow = e.result.flow_key || "";
        return `<tr class="clickable" data-flow="${escapeHtml(flow)}">
          <td>${timeStr(e.timestamp)}</td>
          <td><span class="badge ${st.toLowerCase()}">${st}</span></td>
          <td class="mono">${escapeHtml(md.src_ip || md.source || "unknown")}</td>
          <td class="mono">${escapeHtml(md.dst_ip || "unknown")}</td>
          <td>${escapeHtml(String(md.protocol || "ip"))}</td>
          <td>${pct(e.result.threat_score)}</td>
          <td>${escapeHtml(e.result.reason)}</td>
          <td>${escapeHtml(act.type || "observe")}</td>
        </tr>`;
      })
      .join("");
    tbody.innerHTML = rows || `<tr><td colspan="8" class="empty">No matching events yet.</td></tr>`;
  }

  // ---------------------------------------------------------------- ALERTS
  async function renderAlerts() {
    try {
      state.alerts = await api("/api/alerts?limit=300");
    } catch (_) {}
    const tbody = $("alertsBody");
    if (!tbody) return;
    const rows = [...state.alerts].reverse().map((a) => `
      <tr class="clickable" data-flow="${escapeHtml(a.flow_key || "")}">
        <td>${timeStr(a.timestamp)}</td>
        <td><span class="badge ${a.status.toLowerCase()}">${a.status}</span></td>
        <td><span class="badge sev-${a.severity}">${a.severity}</span></td>
        <td class="mono">${escapeHtml(a.src_ip)}</td>
        <td class="mono">${escapeHtml(a.dst_ip)}</td>
        <td>${escapeHtml(String(a.protocol))}</td>
        <td>${pct(a.threat_score)}</td>
        <td>${escapeHtml(a.reason)}</td>
      </tr>`).join("");
    tbody.innerHTML = rows || `<tr><td colspan="8" class="empty">No alerts yet.</td></tr>`;
    $("alertsCount").textContent = state.alerts.length;
  }

  // ---------------------------------------------------------------- SOURCES
  async function renderSources() {
    const s = state.stats;
    const list = $("sourcesList");
    if (s && list) {
      list.innerHTML = s.top_sources.length
        ? s.top_sources.map((src) => `
          <div class="list-item">
            <div class="row">
              <strong class="mono">${escapeHtml(src.ip)}</strong>
              <button class="danger ghost block-btn" data-ip="${escapeHtml(src.ip)}">Block</button>
            </div>
            <span>${src.total} pkts &middot; <b style="color:var(--bad)">${src.attacks}</b> attacks &middot; ${src.suspicious} suspicious</span>
          </div>`).join("")
        : `<div class="empty">No sources observed.</div>`;
    }
    await renderBlocked();
  }

  async function renderBlocked() {
    try {
      state.blocked = await api("/api/blocked");
    } catch (_) {}
    const list = $("blockedList");
    if (!list) return;
    list.innerHTML = state.blocked.length
      ? state.blocked.map((b) => `
        <div class="list-item">
          <div class="row">
            <strong class="mono">${escapeHtml(b.ip)}</strong>
            <button class="ghost unblock-btn" data-ip="${escapeHtml(b.ip)}">Unblock</button>
          </div>
          <span>${b.dry_run ? "Dry-run" : "<b style='color:var(--bad)'>Enforced</b>"} &middot; ${escapeHtml(b.reason)} &middot; until ${timeStr(b.expires_at)}</span>
        </div>`).join("")
      : `<div class="empty">No active blocks.</div>`;
  }

  // ---------------------------------------------------------------- MODELS
  function renderModelHealthList(targetId) {
    const target = $(targetId);
    if (!target || !state.health) return;
    const models = state.health.engine.models;
    const role = {
      xgboost: "Barrier 1 - routine per-packet classifier",
      transformer: "Barrier 2 - session context (broader view)",
      autoencoder: "Barrier 3 - zero-day anomaly detector",
    };
    target.innerHTML = Object.values(models).map((m) => `
      <div class="list-item">
        <div class="row">
          <strong>${m.name}</strong>
          <span class="mode-tag ${m.mode}">${m.mode}</span>
        </div>
        <span>${role[m.name] || ""}</span>
        ${m.error && m.mode !== "model" ? `<div class="help" style="color:var(--muted-2);margin-top:6px">${escapeHtml(m.error).slice(0, 120)}</div>` : ""}
      </div>`).join("");
  }

  function renderModels() {
    if (!state.health) return;
    const e = state.health.engine;
    $("modelSeqLen").textContent = e.sequence_len;
    $("modelPadEarly").textContent = e.transformer_pad_early ? "Enabled (early reads)" : "Strict (full window)";
    $("modelFeatures").textContent = e.feature_order.join(", ");
    renderModelHealthList("modelsHealth");
    const anySurrogate = Object.values(e.models).some((m) => m.mode === "surrogate");
    const banner = $("modelsBanner");
    if (banner) banner.style.display = anySurrogate ? "block" : "none";
    // threshold display
    const th = e.thresholds;
    $("modelThresholds").innerHTML = Object.entries(th).map(([k, v]) =>
      `<div class="list-item"><div class="row"><strong>${k}</strong><span class="mono">${v}</span></div></div>`).join("");
  }

  // ---------------------------------------------------------------- SETTINGS
  function renderSettings() {
    if (!state.health) return;
    const snap = state.health.settings;
    const th = snap.thresholds, pol = snap.policy;
    $("setXgbSuspicious").value = th.xgb_suspicious;
    $("setXgbAttack").value = th.xgb_attack;
    $("setTransformer").value = th.transformer;
    $("setAutoencoder").value = th.autoencoder;
    $("setAutoBlock").checked = pol.auto_block;
    $("setDryRun").checked = pol.dry_run;
    $("setBlockThreshold").value = pol.block_threshold;
    $("setBlockDuration").value = pol.block_duration_seconds;
  }

  async function saveSettings() {
    const body = {
      thresholds: {
        xgb_suspicious: Number($("setXgbSuspicious").value),
        xgb_attack: Number($("setXgbAttack").value),
        transformer: Number($("setTransformer").value),
        autoencoder: Number($("setAutoencoder").value),
      },
      policy: {
        auto_block: $("setAutoBlock").checked,
        dry_run: $("setDryRun").checked,
        block_threshold: Number($("setBlockThreshold").value || 5),
        block_duration_seconds: Number($("setBlockDuration").value || 300),
      },
    };
    await api("/api/settings", { method: "POST", body: JSON.stringify(body) });
    await loadHealth();
    toast("Settings saved &amp; persisted.", "info");
  }

  // ---------------------------------------------------------------- flow modal
  async function openFlow(flowKey) {
    if (!flowKey) return;
    const modal = $("flowModal");
    $("flowTitle").textContent = flowKey;
    $("flowBody").innerHTML = `<div class="empty">Loading...</div>`;
    modal.classList.add("open");
    try {
      const items = await api(`/api/flow/${encodeURIComponent(flowKey)}`);
      $("flowBody").innerHTML = items.length
        ? `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Status</th><th>Threat</th><th>XGB</th><th>Transformer</th><th>AE</th><th>Reason</th></tr></thead><tbody>${
            items.reverse().map((e) => {
              const b = e.result.barriers;
              return `<tr><td>${timeStr(e.timestamp)}</td>
                <td><span class="badge ${e.result.status.toLowerCase()}">${e.result.status}</span></td>
                <td>${pct(e.result.threat_score)}</td>
                <td>${fmt(b.routine_xgboost?.score, 3)}</td>
                <td>${fmt(b.context_transformer?.score, 3)}</td>
                <td>${fmt(b.zero_day_autoencoder?.score, 5)}</td>
                <td>${escapeHtml(e.result.reason)}</td></tr>`;
            }).join("")
          }</tbody></table></div>`
        : `<div class="empty">No recent packets for this flow.</div>`;
    } catch (err) {
      $("flowBody").innerHTML = `<div class="empty">Could not load flow.</div>`;
    }
  }

  // ---------------------------------------------------------------- loaders
  async function loadHealth() {
    state.health = await api("/api/health");
    setCaptureReplayButtons();
    if (state.route === "models") renderModels();
    if (state.route === "settings") renderSettings();
    renderModelHealthList("ovModelHealth");
  }

  async function loadStats() {
    try {
      state.stats = await api("/api/stats");
      updateNavPips();
      if (state.route === "overview") renderOverview();
      if (state.route === "sources") renderSources();
    } catch (_) {}
  }

  async function loadInterfaces() {
    try {
      const r = await api("/api/interfaces");
      state.interfaces = r.interfaces || [];
      populateInterfaceSelect();
    } catch (_) {}
  }

  function populateInterfaceSelect() {
    const sel = $("ifaceSelect");
    if (!sel || sel.dataset.filled === String(state.interfaces.length)) return;
    sel.innerHTML =
      `<option value="">All interfaces</option>` +
      state.interfaces.map((i) => `<option value="${escapeHtml(i.name)}">${escapeHtml(i.name)}${i.address ? ` (${escapeHtml(i.address)})` : ""}</option>`).join("");
    sel.dataset.filled = String(state.interfaces.length);
  }

  async function loadRecentEvents() {
    const recent = await api("/api/events?limit=120");
    recent.reverse().forEach(ingest);
  }

  function setCaptureReplayButtons() {
    if (!state.health) return;
    const cap = state.health.capture.running;
    const rep = state.health.replay.running;
    const setBtn = (id, on) => { const b = $(id); if (b) b.disabled = on; };
    setBtn("startCapture", cap);
    setBtn("stopCapture", !cap);
    setBtn("startReplay", rep);
    setBtn("stopReplay", !rep);
    const ci = $("captureInfo");
    if (ci) ci.textContent = cap ? `Capturing on ${state.health.capture.interface} [${state.health.capture.filter}]` : "Capture idle";
  }

  // ---------------------------------------------------------------- stream
  function connectStream() {
    if (!window.EventSource) {
      setLive("down", "Polling");
      setInterval(loadRecentEvents, 3000);
      return;
    }
    const stream = new EventSource(`${API}/api/stream`);
    stream.addEventListener("open", () => setLive("live", "Live"));
    stream.addEventListener("packet", (m) => ingest(JSON.parse(m.data)));
    stream.addEventListener("error", () => setLive("down", "Reconnecting"));
  }

  // ---------------------------------------------------------------- actions
  function wireEvents() {
    window.addEventListener("hashchange", route);

    // capture / replay (Live page)
    document.body.addEventListener("click", async (ev) => {
      const t = ev.target.closest("button, tr.clickable");
      if (!t) return;

      if (t.id === "startReplay")
        return void api("/api/replay/start", { method: "POST", body: JSON.stringify({ profile: $("profileSelect").value, speed: Number($("speedInput").value || 25) }) }).then(loadHealth);
      if (t.id === "stopReplay") return void api("/api/replay/stop", { method: "POST" }).then(loadHealth);
      if (t.id === "startCapture")
        return void api("/api/capture/start", { method: "POST", body: JSON.stringify({ interface: $("ifaceSelect").value || null, source_ip: $("srcFilterInput").value || null, protocol: $("protoFilterSelect").value || null }) }).then(loadHealth).catch((e) => toast("Capture failed: " + e.message, "attack"));
      if (t.id === "stopCapture") return void api("/api/capture/stop", { method: "POST" }).then(loadHealth);
      if (t.id === "saveSettings") return void saveSettings();
      if (t.id === "reloadModels") return void api("/api/reload", { method: "POST" }).then(loadHealth).then(() => toast("Models reloaded.", "info"));
      if (t.id === "exportEvents") return void window.open(`${API}/api/events/export`, "_blank");
      if (t.id === "pauseToggle") {
        state.paused = !state.paused;
        t.textContent = state.paused ? "Resume" : "Pause";
        t.classList.toggle("danger", state.paused);
        return;
      }
      if (t.id === "flowClose" || t.classList.contains("modal-backdrop")) {
        $("flowModal").classList.remove("open");
        return;
      }
      if (t.classList.contains("block-btn")) {
        await api("/api/block", { method: "POST", body: JSON.stringify({ ip: t.dataset.ip }) });
        toast(`Block registered for ${escapeHtml(t.dataset.ip)}.`, "attack");
        return void renderSources();
      }
      if (t.classList.contains("unblock-btn")) {
        await api("/api/unblock", { method: "POST", body: JSON.stringify({ ip: t.dataset.ip }) });
        return void renderSources();
      }
      if (t.classList.contains("clickable") && t.dataset.flow) return void openFlow(t.dataset.flow);
    });

    const filt = $("eventFilterSelect");
    if (filt) filt.addEventListener("change", (e) => { state.eventFilter = e.target.value; renderLiveTable(); });
    const srcFilt = $("eventSourceFilter");
    if (srcFilt) srcFilt.addEventListener("input", (e) => { state.sourceFilter = e.target.value.trim(); renderLiveTable(); });
  }

  // ---------------------------------------------------------------- boot
  async function boot() {
    wireEvents();
    route();
    try {
      await Promise.all([loadHealth(), loadStats(), loadInterfaces(), loadRecentEvents()]);
      connectStream();
      renderRoute();
    } catch (err) {
      setLive("down", "Backend offline");
      toast("Backend offline - start the Flask server.", "attack");
      console.error(err);
    }
    setInterval(loadStats, 2500);
    setInterval(loadHealth, 12000);
    setInterval(() => { if (state.route === "sources") renderBlocked(); }, 5000);
    setInterval(() => { if (state.route === "alerts") renderAlerts(); }, 4000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
