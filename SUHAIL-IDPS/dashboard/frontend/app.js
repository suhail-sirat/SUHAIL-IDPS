/* SUHAIL-IDPS dashboard runtime.
 * Single-page app with hash routing across: Overview, Live, Alerts, Sources,
 * Models, Settings. Consumes the Flask backend over REST + Server-Sent Events.
 *
 * Every user-visible string goes through i18n.js: static labels are tagged with
 * data-i18n in index.html, runtime strings call t(), and English sentences the
 * backend produces are mapped back through tServer(). Switching locale re-runs
 * the full render so nothing stale is left on screen.
 */
(() => {
  "use strict";

  const API = location.protocol.startsWith("http") ? location.origin : "http://localhost:5000";
  const $ = (id) => document.getElementById(id);
  const el = (sel, root = document) => root.querySelector(sel);
  const t = (key, params) => window.I18N.t(key, params);
  const tServer = (text) => window.I18N.serverText(text);

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
    liveState: "",       // dot class: "", "live", "down"
    liveKey: "live.connecting",
  };
  const MAX_EVENTS = 400;
  const MAX_TIMELINE = 120;

  // ---------------------------------------------------------------- utils
  const fmt = (v, d = 3) =>
    v === null || v === undefined || Number.isNaN(Number(v)) ? "--" : Number(v).toFixed(d);
  const pct = (v) => `${Math.round((Number(v) || 0) * 100)}%`;
  // Clock stays Latin-digit 24h in every locale — timestamps are correlated with
  // pcap/iptables output, which never uses Arabic-Indic numerals.
  const timeStr = (iso) => new Date(iso).toLocaleTimeString("en-GB");

  // Localised labels for the enum-ish values the backend sends.
  const tStatus = (s) => t(`status.${String(s || "UNKNOWN").toUpperCase()}`);
  const tState = (s) => t(`state.${String(s || "WAITING").toUpperCase()}`);
  const tSeverity = (s) => t(`sev.${String(s || "low").toLowerCase()}`);
  const tMode = (m) => t(`mode.${String(m || "model").toLowerCase()}`);
  const tAction = (a) => {
    const key = `action.${String(a || "observe").toLowerCase()}`;
    return window.I18N.has(key) ? t(key) : String(a);
  };
  const tAttackType = (type) => {
    const raw = String(type || "").toLowerCase();
    const key = `atype.${raw}`;
    return window.I18N.has(key) ? t(key) : String(type).toUpperCase();
  };

  // Attack-type label + confidence for a scored result (null when not hostile).
  function attackInfo(result) {
    const at = result && result.attack_type;
    if (!at || !at.type) return null;
    const conf = at.confidence === undefined || at.confidence === null ? null : Number(at.confidence);
    return { label: tAttackType(at.type), conf, src: at.source || "" };
  }
  // A barrier score shown as a percentage. XGB + transformer are probabilities;
  // the autoencoder is a reconstruction-error (MSE) so it's normalised against
  // its own threshold into an "anomaly level" instead of a raw x100.
  function barrierPct(barrier, key) {
    const s = barrier.score;
    if (s === null || s === undefined) return "--";
    if (key === "zero") {
      const thr = Math.max(Number(barrier.threshold || 0), 1e-9);
      return `${Math.round(Math.min(Number(s) / (thr * 2), 1) * 100)}%`;
    }
    return `${Math.round(Math.min(Math.max(Number(s), 0), 1) * 100)}%`;
  }
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

  function setLive(stateName, key) {
    state.liveState = stateName;
    state.liveKey = key;
    document.querySelectorAll(".live-dot").forEach((d) => (d.className = `dot live-dot ${stateName}`));
    document.querySelectorAll(".live-text").forEach((n) => (n.textContent = t(key)));
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
      const info = attackInfo(event.result);
      const typeChip = info
        ? ` &middot; <span class="atk">${escapeHtml(info.label)}</span>${info.conf !== null ? ` <span class="atk-conf">${pct(info.conf)}</span>` : ""}`
        : "";
      const src = escapeHtml(event.metadata.src_ip || t("status.UNKNOWN"));
      const dst = escapeHtml(event.metadata.dst_ip || "?");
      toast(
        `<div class="toast-head"><b>${escapeHtml(tStatus(status))}</b>${typeChip}<span class="toast-time">${escapeHtml(timeStr(event.timestamp))}</span></div>
         <div class="mono" style="margin:3px 0">${src} &rarr; ${dst}</div>
         <span class="mono" style="color:var(--muted)">${escapeHtml(tServer(event.result.reason))}</span>`,
        status.toLowerCase()
      );
    }
    // Distinct heads-up when the prevention policy auto-blocks a source.
    const act = event.action || {};
    if (act.type === "block" && act.auto) {
      toast(
        `<div class="toast-head"><b>${escapeHtml(t("toast.autoBlocked"))}</b><span class="toast-time">${escapeHtml(timeStr(event.timestamp))}</span></div>
         <div class="mono">${escapeHtml(event.metadata.src_ip || t("unit.source"))}</div>
         <span class="mono" style="color:var(--muted)">${escapeHtml(tServer(act.message || ""))}</span>`,
        "attack"
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
  /** The font-family the active locale resolved to, for canvas text. */
  function chartFontStack(node) {
    const f = getComputedStyle(node).fontFamily;
    return f && f.trim() ? f : "sans-serif";
  }

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
      // Track whatever face the active locale resolved to, so canvas labels
      // match the rest of the UI instead of pinning Inter.
      ctx.font = `${11 * dpr}px ${chartFontStack(canvas)}`;
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
      // Primary read is a percentage; keep the raw score on hover for detail.
      setT("Score", barrierPct(barrier, key));
      const scoreNode = $(`${id}Score`);
      if (scoreNode) {
        scoreNode.title =
          key === "zero"
            ? t("unit.rawMse", { n: fmt(score, 5) })
            : t("unit.rawProb", { n: fmt(score, 3) });
      }
      const meter = $(`${id}Meter`); if (meter) meter.style.width = `${meterPct}%`;
      setT("State", tState(barrier.state));
      setT("Latency", t("unit.ms", { n: fmt(barrier.latency_ms, 1) }));
      const modeTag = $(`${id}Mode`);
      if (modeTag) {
        const mode = barrier.mode || "model";
        modeTag.textContent = tMode(mode);
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
      $("ovPpm").textContent = t("ov.flowsPerMin", { n: s.packets_per_minute });
      $("ovAttackRate").textContent = t("ov.attackRate", { p: pct(s.attack_rate) });
      $("ovUptime").textContent = t("ov.uptime", { n: Math.floor(s.uptime_seconds / 60) });
      // protocol mix
      const colors = { ICMP: "#f87171", TCP: "#56b6e6", UDP: "#34d399" };
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
    if (pillEl)
      pillEl.innerHTML =
        `<span class="badge ${r.status.toLowerCase()}">${escapeHtml(tStatus(r.status))}</span> ${pct(r.threat_score)}`;
    const seq = $("ovSequenceState");
    if (seq)
      seq.textContent =
        t("ov.hostCtx", { n: r.sequence.length, m: r.sequence.target_length }) +
        (r.sequence.padded ? t("ov.hostCtxEarly") : "");
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
        const pkts = (e.flow && e.flow.total_packets) ? Math.round(e.flow.total_packets) : "--";
        const info = attackInfo(e.result);
        const atk = info ? ` <span class="tag">${escapeHtml(info.label)}</span>` : "";
        const unknown = t("status.UNKNOWN");
        const rowCls = `clickable${e.final === false ? " interim" : ""}${st === "ATTACK" ? " row-attack" : st === "SUSPICIOUS" ? " row-suspicious" : ""}`;
        return `<tr class="${rowCls}" data-flow="${escapeHtml(flow)}">
          <td class="mono">${timeStr(e.timestamp)}</td>
          <td><span class="badge ${st.toLowerCase()}">${escapeHtml(tStatus(st))}</span></td>
          <td class="mono">${escapeHtml(md.src_ip || md.source || unknown)}${atk}</td>
          <td class="mono">${escapeHtml(md.dst_ip || unknown)}</td>
          <td>${escapeHtml(String(md.protocol || "ip"))}</td>
          <td>${pkts}</td>
          <td>${pct(e.result.threat_score)}</td>
          <td>${escapeHtml(tServer(e.result.reason))}</td>
          <td>${escapeHtml(tAction(act.type || "observe"))}</td>
        </tr>`;
      })
      .join("");
    tbody.innerHTML = rows || `<tr><td colspan="9" class="empty">${escapeHtml(t("empty.noEvents"))}</td></tr>`;
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
        <td class="mono">${timeStr(a.timestamp)}</td>
        <td><span class="badge ${a.status.toLowerCase()}">${escapeHtml(tStatus(a.status))}</span></td>
        <td><span class="badge sev-${a.severity}">${escapeHtml(tSeverity(a.severity))}</span></td>
        <td class="mono">${escapeHtml(a.src_ip)}</td>
        <td class="mono">${escapeHtml(a.dst_ip)}</td>
        <td>${escapeHtml(String(a.protocol))}</td>
        <td>${a.attack_type ? `<span class="tag">${escapeHtml(tAttackType(a.attack_type))}</span>` : "--"}</td>
        <td>${pct(a.threat_score)}</td>
        <td>${escapeHtml(tServer(a.reason))}</td>
      </tr>`).join("");
    tbody.innerHTML = rows || `<tr><td colspan="9" class="empty">${escapeHtml(t("empty.noAlerts"))}</td></tr>`;
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
              <button class="danger ghost block-btn" data-ip="${escapeHtml(src.ip)}">${escapeHtml(t("btn.block"))}</button>
            </div>
            <span>${escapeHtml(t("src.stats", { total: src.total, attacks: src.attacks, suspicious: src.suspicious }))}</span>
          </div>`).join("")
        : `<div class="empty">${escapeHtml(t("empty.noSources"))}</div>`;
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
      ? state.blocked.map((b) => {
          // The template is ours, so params may carry markup; every untrusted
          // value is escaped on the way in.
          const meta = t("src.blockMeta", {
            mode: b.dry_run
              ? escapeHtml(t("src.dryRun"))
              : `<b style="color:var(--bad)">${escapeHtml(t("src.enforced"))}</b>`,
            reason: escapeHtml(tServer(b.reason)),
            time: escapeHtml(timeStr(b.expires_at)),
          });
          return `
        <div class="list-item">
          <div class="row">
            <strong class="mono">${escapeHtml(b.ip)}</strong>
            <button class="ghost unblock-btn" data-ip="${escapeHtml(b.ip)}">${escapeHtml(t("btn.unblock"))}</button>
          </div>
          <span>${meta}</span>
        </div>`;
        }).join("")
      : `<div class="empty">${escapeHtml(t("empty.noBlocks"))}</div>`;
  }

  // ---------------------------------------------------------------- MODELS
  function renderModelHealthList(targetId) {
    const target = $(targetId);
    if (!target || !state.health) return;
    const models = state.health.engine.models;
    target.innerHTML = Object.values(models).map((m) => {
      const roleKey = `role.${m.name}`;
      const role = window.I18N.has(roleKey) ? t(roleKey) : "";
      return `
      <div class="list-item">
        <div class="row">
          <strong class="mono">${escapeHtml(m.name)}</strong>
          <span class="mode-tag ${m.mode}">${escapeHtml(tMode(m.mode))}</span>
        </div>
        <span>${escapeHtml(role)}</span>
        ${m.error && m.mode !== "model" ? `<div class="help" style="color:var(--muted-2);margin-top:6px">${escapeHtml(m.error).slice(0, 120)}</div>` : ""}
      </div>`;
    }).join("");
  }

  function renderModels() {
    if (!state.health) return;
    const e = state.health.engine;
    const fc = $("modelFeatureCount"); if (fc) fc.textContent = (e.feature_order || []).length;
    $("modelSeqLen").textContent = e.sequence_len;
    $("modelPadEarly").textContent = e.transformer_pad_early ? t("models.padEnabled") : t("models.padStrict");
    $("modelFeatures").textContent = e.feature_order.join(", ");
    renderModelHealthList("modelsHealth");
    const anySurrogate = Object.values(e.models).some((m) => m.mode === "surrogate");
    const banner = $("modelsBanner");
    if (banner) banner.style.display = anySurrogate ? "block" : "none";
    // threshold display — probabilities shown as %, autoencoder as raw MSE
    const th = e.thresholds;
    const asDisplay = (k, v) =>
      k === "autoencoder" ? t("unit.mse", { n: fmt(v, 4) }) : `${pct(v)} (${fmt(v, 2)})`;
    const thrLabel = (k) => (window.I18N.has(`thr.${k}`) ? t(`thr.${k}`) : k);
    $("modelThresholds").innerHTML = Object.entries(th).map(([k, v]) =>
      `<div class="list-item"><div class="row"><strong>${escapeHtml(thrLabel(k))}</strong><span class="mono">${escapeHtml(asDisplay(k, v))}</span></div></div>`).join("");
    // attack-typing route (A heuristic vs B trained model)
    const at = e.attack_typer;
    const atNode = $("modelAttackTyper");
    if (atNode && at) {
      // The backend's `route` field is English prose ("A (heuristic)"), so derive
      // the label from `mode` instead of rendering it verbatim.
      const isModel = at.mode === "model";
      const tagCls = isModel ? "model" : "surrogate";
      atNode.innerHTML =
        `${escapeHtml(t("models.route"))} <b>${escapeHtml(t(isModel ? "route.B" : "route.A"))}</b> ` +
        `<span class="mode-tag ${tagCls}">${escapeHtml(tMode(at.mode))}</span>`;
    }
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
    toast(t("toast.settingsSaved"), "info");
  }

  // ---------------------------------------------------------------- flow modal
  // Feature key -> [i18n key, decimals]
  const FLOW_FEATURES = [
    ["total_packets", 0], ["total_bytes", 0],
    ["flow_duration", 3], ["flow_pkts_per_s", 1],
    ["down_up_ratio", 2], ["syn_flag_count", 0],
    ["rst_flag_count", 0], ["pkt_len_mean", 0],
  ];

  async function openFlow(flowKey) {
    if (!flowKey) return;
    const modal = $("flowModal");
    $("flowTitle").textContent = flowKey;
    $("flowBody").innerHTML = `<div class="empty">${escapeHtml(t("modal.loading"))}</div>`;
    modal.classList.add("open");
    try {
      const items = await api(`/api/flow/${encodeURIComponent(flowKey)}`);
      if (!items.length) {
        $("flowBody").innerHTML = `<div class="empty">${escapeHtml(t("modal.noRecentFlows"))}</div>`;
        return;
      }
      // feature breakdown of the most recent flow in this host history
      const latest = items[items.length - 1];
      const f = latest.flow || {};
      const breakdown = FLOW_FEATURES.map(([k, d]) =>
        `<div class="flow-cell"><label>${escapeHtml(t(`feat.${k}`))}</label><b>${fmt(f[k], d)}</b></div>`).join("");
      const head = ["th.time", "th.status", "th.threat", "th.xgb", "th.transformer", "th.ae", "th.reason"]
        .map((k) => `<th>${escapeHtml(t(k))}</th>`).join("");
      const history = `<div class="table-wrap" style="margin-top:14px"><table><thead><tr>${head}</tr></thead><tbody>${
          [...items].reverse().map((e) => {
            const b = e.result.barriers;
            return `<tr><td class="mono">${timeStr(e.timestamp)}</td>
              <td><span class="badge ${e.result.status.toLowerCase()}">${escapeHtml(tStatus(e.result.status))}</span></td>
              <td>${pct(e.result.threat_score)}</td>
              <td>${fmt(b.routine_xgboost?.score, 3)}</td>
              <td>${fmt(b.context_transformer?.score, 3)}</td>
              <td>${fmt(b.zero_day_autoencoder?.score, 5)}</td>
              <td>${escapeHtml(tServer(e.result.reason))}</td></tr>`;
          }).join("")
        }</tbody></table></div>`;
      $("flowBody").innerHTML =
        `<div class="section-title" style="color:var(--muted);font-size:11px;text-transform:uppercase;margin-bottom:10px">${escapeHtml(t("modal.latestFeatures"))}</div>
         <div class="flow-grid">${breakdown}</div>${history}`;
    } catch (err) {
      $("flowBody").innerHTML = `<div class="empty">${escapeHtml(t("modal.loadFailed"))}</div>`;
    }
  }

  // ---------------------------------------------------------------- loaders
  async function loadHealth() {
    state.health = await api("/api/health");
    setCaptureReplayButtons();
    renderEngineTag();
    if (state.route === "models") renderModels();
    if (state.route === "settings") renderSettings();
    renderModelHealthList("ovModelHealth");
  }

  function renderEngineTag() {
    const tag = $("engineTag");
    if (!tag || !state.health) return;
    const modes = Object.values(state.health.engine.models).map((m) => m.mode);
    const allModel = modes.every((m) => m === "model");
    const cls = allModel ? "model" : "surrogate";
    const label = allModel ? t("engine.trainedModels") : t("engine.surrogateMode");
    tag.innerHTML = `<span class="engine-tag mode-tag ${cls}">● ${escapeHtml(label)}</span>`;
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
    const keep = sel.value;
    sel.innerHTML =
      `<option value="">${escapeHtml(t("livep.allInterfaces"))}</option>` +
      state.interfaces.map((i) => `<option value="${escapeHtml(i.name)}">${escapeHtml(i.name)}${i.address ? ` (${escapeHtml(i.address)})` : ""}</option>`).join("");
    sel.value = keep;
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
    if (ci)
      ci.textContent = cap
        ? t("side.capturingOn", { iface: state.health.capture.interface, filter: state.health.capture.filter })
        : t("side.captureIdle");
  }

  // ---------------------------------------------------------------- stream
  function connectStream() {
    if (!window.EventSource) {
      setLive("down", "live.polling");
      setInterval(loadRecentEvents, 3000);
      return;
    }
    const stream = new EventSource(`${API}/api/stream`);
    stream.addEventListener("open", () => setLive("live", "live.live"));
    stream.addEventListener("packet", (m) => ingest(JSON.parse(m.data)));
    stream.addEventListener("error", () => setLive("down", "live.reconnecting"));
  }

  // ---------------------------------------------------------------- locale
  /**
   * Localise the overview slots that hold formatted values rather than plain
   * labels. Until the first flow arrives nothing else writes to them, so they
   * would otherwise sit in English on a quiet sensor.
   */
  function renderIdleShell() {
    const set = (id, text) => { const n = $(id); if (n) n.textContent = text; };
    if (!state.stats) {
      set("ovPpm", t("ov.flowsPerMin", { n: 0 }));
      set("ovUptime", t("ov.uptime", { n: 0 }));
      set("ovAttackRate", t("ov.attackRate", { p: pct(0) }));
    }
    if (!state.events.length) {
      const seqLen = (state.health && state.health.engine.sequence_len) || 0;
      set("ovSequenceState", t("ov.hostCtx", { n: 0, m: seqLen }));
      ["ovRoutine", "ovContext", "ovZero"].forEach((id) =>
        set(`${id}Latency`, t("unit.ms", { n: fmt(0, 1) }))
      );
    }
  }

  /** Re-apply every string after a locale switch, static and runtime alike. */
  function onLocaleChange() {
    window.I18N.applyStatic();
    // Nodes that carry runtime values need re-deriving; applyStatic reset them
    // to their default label.
    setLive(state.liveState, state.liveKey);
    const pause = $("pauseToggle");
    if (pause) pause.textContent = state.paused ? t("livep.resume") : t("livep.pause");
    const sel = $("ifaceSelect");
    if (sel) delete sel.dataset.filled;   // force rebuild with the new "All interfaces"
    populateInterfaceSelect();
    setCaptureReplayButtons();
    renderEngineTag();
    renderModelHealthList("ovModelHealth");
    renderRoute();
    renderIdleShell();
    if (state.events[0]) renderOverviewLive(state.events[0]);
  }

  // ---------------------------------------------------------------- actions
  function wireEvents() {
    window.addEventListener("hashchange", route);

    // capture / replay (Live page)
    document.body.addEventListener("click", async (ev) => {
      const target = ev.target.closest("button, tr.clickable");
      if (!target) return;

      if (target.id === "startReplay")
        return void api("/api/replay/start", { method: "POST", body: JSON.stringify({ profile: $("profileSelect").value, speed: Number($("speedInput").value || 25) }) }).then(loadHealth);
      if (target.id === "stopReplay") return void api("/api/replay/stop", { method: "POST" }).then(loadHealth);
      if (target.id === "startCapture")
        return void api("/api/capture/start", { method: "POST", body: JSON.stringify({ interface: $("ifaceSelect").value || null, source_ip: $("srcFilterInput").value || null, protocol: $("protoFilterSelect").value || null }) }).then(loadHealth).catch((e) => toast(t("toast.captureFailed", { error: escapeHtml(e.message) }), "attack"));
      if (target.id === "stopCapture") return void api("/api/capture/stop", { method: "POST" }).then(loadHealth);
      if (target.id === "saveSettings") return void saveSettings();
      if (target.id === "reloadModels") return void api("/api/reload", { method: "POST" }).then(loadHealth).then(() => toast(t("toast.modelsReloaded"), "info"));
      if (target.id === "exportEvents") return void window.open(`${API}/api/events/export`, "_blank");
      if (target.id === "pauseToggle") {
        state.paused = !state.paused;
        target.textContent = state.paused ? t("livep.resume") : t("livep.pause");
        target.classList.toggle("danger", state.paused);
        return;
      }
      if (target.id === "flowClose" || target.classList.contains("modal-backdrop")) {
        $("flowModal").classList.remove("open");
        return;
      }
      if (target.classList.contains("block-btn")) {
        await api("/api/block", { method: "POST", body: JSON.stringify({ ip: target.dataset.ip }) });
        toast(t("toast.blockRegistered", { ip: escapeHtml(target.dataset.ip) }), "attack");
        return void renderSources();
      }
      if (target.classList.contains("unblock-btn")) {
        await api("/api/unblock", { method: "POST", body: JSON.stringify({ ip: target.dataset.ip }) });
        return void renderSources();
      }
      if (target.classList.contains("clickable") && target.dataset.flow) return void openFlow(target.dataset.flow);
    });

    const filt = $("eventFilterSelect");
    if (filt) filt.addEventListener("change", (e) => { state.eventFilter = e.target.value; renderLiveTable(); });
    const srcFilt = $("eventSourceFilter");
    if (srcFilt) srcFilt.addEventListener("input", (e) => { state.sourceFilter = e.target.value.trim(); renderLiveTable(); });
  }

  // ---------------------------------------------------------------- boot
  async function boot() {
    window.I18N.applyStatic();
    window.I18N.mountSwitcher();
    window.I18N.onChange(onLocaleChange);
    wireEvents();
    route();
    renderIdleShell();
    try {
      await Promise.all([loadHealth(), loadStats(), loadInterfaces(), loadRecentEvents()]);
      connectStream();
      renderRoute();
      renderIdleShell();
    } catch (err) {
      setLive("down", "live.offline");
      toast(t("toast.backendOffline"), "attack");
      console.error(err);
    }
    setInterval(loadStats, 2500);
    setInterval(loadHealth, 12000);
    setInterval(() => { if (state.route === "sources") renderBlocked(); }, 5000);
    setInterval(() => { if (state.route === "alerts") renderAlerts(); }, 4000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
