# SUHAIL-IDPS — Dashboard Guide

A walk-through of every page and panel in the live console
(`http://localhost:5000`), what it shows, and why it's there. The left sidebar
switches between the six pages; the little pulsing dot (top-right and sidebar) is
the live connection: green = streaming, amber = reconnecting.

The sidebar also always shows the **three barriers** and an engine tag
(`trained models` vs `surrogate mode`) so you know at a glance whether real
models or the built-in fallbacks are serving.

---

## 1. Overview
The command screen — the single page you leave open to read the health of the
whole system at a glance. Everything on it updates live as flows are scored (the
metrics refresh every ~2.5 s; the barrier cards and timeline update on each new
flow). It answers three questions top-to-bottom: *how much is happening?* (metric
cards), *what did the AI just decide and why?* (barrier cards), and *where is it
trending?* (timeline + protocol mix + model health).

### Top bar
The page title and a **live status pill** with the pulsing connection dot:
**green = Live** (streaming over Server-Sent Events), **amber = Reconnecting**,
**grey/down = backend offline**. If it's not green, the numbers on the page have
stopped moving — check that the Flask backend is running.

### Metric cards (the headline row)
Five running counters for the whole session (since the backend started). Each big
number has a smaller sub-line under it:

- **◷ Total flows** — every bidirectional flow scored so far. Sub-line
  **flows/min** is the current rate (flows seen in the last 60 s), i.e. how busy
  the link is right now.
- **✓ Normal** (green) — flows all barriers judged benign. Sub-line shows engine
  **uptime**. In healthy traffic this should be the large majority.
- **◐ Suspicious** (amber) — flows that crossed a *warn* threshold but not a hard
  *attack* threshold: worth watching, not yet conclusive.
- **✕ Attacks** (red) — flows that crossed an attack policy. Sub-line **attack
  rate** = attacks ÷ total, as a %. A sudden jump here is your primary alarm.
- **⛔ Blocked** — how many sources are currently blocked (auto + manual). Sub-line
  "Active entries". Drops back down as blocks expire.

Read them together: e.g. high flows/min **and** a climbing attack rate = an
active flood; low volume with a few attacks = a probe/scan.

### Three-Barrier AI Decision
The heart of the page — the three detection models' verdicts on the **most recent
flow**, each as a card. This is the "layered defence": a flow has to get past all
three. Each card shows a big **percentage** score, a state pill, the scoring
**latency** (ms), and a `model` / `surrogate` mode tag in the corner. The card's
left edge is colour-coded by state, and its meter bar fills toward the threshold.

- **⚡ Routine — XGBoost (Barrier 1).** The always-on first line: classifies each
  completed flow on its own features as attack-like or not. Its % is the model's
  attack probability. This is what fires on obvious single-flow attacks.
- **◈ Context — Transformer (Barrier 2).** The "broader view": instead of one
  flow, it looks at the recent **sequence** of flows from the same source host,
  so it catches attacks that only make sense across many flows — port scans,
  DDoS, beaconing. It stays **WAITING** until a flow already looks suspicious and
  there's enough host history (you'll see it engage exactly when Barrier 1 or 3
  raises a flag). Its % is the sequence-threat level.
- **☢ Zero-day — Autoencoder (Barrier 3).** Trained on **normal** traffic only,
  it tries to reconstruct each flow; a flow it *can't* reconstruct well is
  out-of-distribution — a candidate **novel / zero-day** event. Because its raw
  output is a reconstruction **error (MSE)**, not a probability, the % here is an
  *anomaly level* relative to its threshold rather than a literal probability.

State pills: **PASS** (below threshold, green), **ALERT** (crossed, red),
**WAITING** (not enough context yet, amber), **UNAVAILABLE** (no scorer). Hover
any score to see the **raw** value — probability for XGBoost/Transformer, raw MSE
for the Autoencoder. The `surrogate` tag means that barrier is running its
built-in fallback, not a trained model (see the Models page to fix that).

The status pill on this panel's header (**"Last decision"**) shows the overall
verdict for that latest flow — a coloured badge (NORMAL / SUSPICIOUS / ATTACK)
plus its combined **threat %**.

### Threat Timeline
A rolling line chart of the combined **threat score** of recent flows (most
recent on the right). The dots are colour-graded — **green** safe, **amber**
elevated, **red** threat — so a wall of red dots or a rising line is an at-a-
glance "things are getting worse". The header pill (**Host ctx N/16**) shows how
much per-host sequence context the Context barrier has accumulated for the latest
source (out of the 16-flow window); `(early)` means it's scoring on padded,
partial context.

### Protocol Mix
A small bar chart of observed traffic by protocol (TCP / UDP / ICMP, colour-
coded). Useful for spotting a shift in the *shape* of traffic — e.g. a spike in
ICMP or UDP often accompanies a flood.

### Model Health
Three tiles, one per barrier, showing each one's live **mode** — `model` (real
trained model loaded) vs `surrogate` (dependency-free fallback) — its role, and
any load error. This is your quick confirmation of whether the system is running
on the real AI or the fallbacks; if anything reads `surrogate`, the Models page
tells you how to switch to trained models.

## 2. Live Traffic
Where you feed the engine and watch every scored flow.

- **Live Capture** — pick a network interface and (optionally) filter by protocol
  or source IP, then **Start Capture** to sniff real traffic off this machine
  (needs root). Packets are assembled into bidirectional flows and scored.
- **Flow Replay** — no capture needed: replays the bundled labelled dataset
  (`data/flows/all_flows.csv`) if present, else generates synthetic normal +
  attack flows. Choose a profile (Mixed / Attack / Normal) and speed. This is the
  easiest way to demo the system.
- **Live Flow Events** — the streaming table of every scored flow: time, status,
  source/destination, protocol, packet count, **threat %**, reason, and the
  action taken. Attack rows are tagged with their **attack type** (e.g.
  `SYNFLOOD`). Filter by status or source; **Pause** to freeze the stream;
  **Export** to download the buffer as NDJSON. Click any row to open the
  **flow drill-down** (feature breakdown + barrier-by-barrier history).

## 3. Alerts
The filtered feed of everything hostile — only ATTACK and SUSPICIOUS decisions.
Columns: time, status, **severity**, source, destination, protocol, **Type**
(the named attack archetype), threat %, and reason. Click a row for the same flow
drill-down. Use this as the incident list.

## 4. Sources & Blocking
Per-source intelligence and the prevention list.

- **Hot Sources** — the IPs generating the most attacks/suspicion, ranked. Each
  has a one-click **Block** button.
- **Blocked IPs** — currently blocked sources (auto or manual), whether the block
  is **Enforced** (real `iptables`) or **Dry-run** (simulated), the reason, and
  when it expires. Unblock any of them here.

## 5. Models
The engine's configuration and what's actually running.

- **Surrogate banner** — appears if any barrier is on its fallback, with how to
  upgrade to trained models.
- **Model cards** — each barrier's role, mode (`model`/`surrogate`) and any load
  error.
- **Engine Configuration** — the flow feature count, the transformer context
  window (flows per host), the early-context setting, **Attack typing route**
  (`Route A (heuristic)` vs `Route B (multi-class model)`), and the full feature
  list.
- **Active Thresholds** — the decision cutoffs, shown as **%** for the
  probability barriers and raw **MSE** for the autoencoder.
- **Reload Models** (top-right) — re-loads model files from disk without a
  restart; use it right after training to switch from fallback to real models,
  or to flip Route A → Route B.

## 6. Settings
Tune detection and prevention; everything here **persists** across restarts.

- **Decision Thresholds** — per-barrier sensitivity:
  - *XGB suspicious* / *XGB attack* — routine warn vs. hard-block levels.
  - *Transformer* — sequence-attack level.
  - *Autoencoder* — reconstruction-error cutoff (raw MSE).
  Lower = more sensitive (more alerts, more false positives); higher = stricter.
- **Prevention Policy**:
  - *Auto-block offenders* — let the system block sources on its own.
  - *Dry-run (simulate)* — ON simulates blocks; OFF enforces with real
    `iptables` (needs root).
  - *Block after N alerts* — how many alerts from one source trigger an
    auto-block.
  - *Block duration (sec)* — how long a block lasts before auto-expiring.
  Hit **Save & Persist** to apply.

---

### Toasts (pop-ups, bottom-right)
Every hostile flow raises a toast showing the **status**, the **attack type** and
its confidence, the **time**, and the source→destination + reason. A separate
red **AUTO-BLOCKED** toast fires when the prevention policy blocks a source.

### Flow drill-down (modal)
Opened by clicking any flow/alert row: the latest flow's key features (packets,
bytes, duration, rates, flags) and the full per-barrier history for that host, so
you can see exactly why a decision was made.
