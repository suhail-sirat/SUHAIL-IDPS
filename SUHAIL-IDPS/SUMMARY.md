# SUHAIL-IDPS — Summary

## What this system is

**SUHAIL-IDPS** is a live Intrusion Detection & Prevention System driven by a
**three-barrier AI pipeline** and presented through a full, multi-page,
real-time web dashboard.

Traffic — captured live from this computer's network interfaces, or replayed
from labelled datasets — flows through three independently-trained models, each
playing a distinct defensive role:

1. **Routine barrier (XGBoost)** — a fast per-packet classifier that scores
   *every* packet. This is the always-on first line for ordinary traffic.
2. **Context barrier (Transformer)** — the "broader point of view". It looks at
   the recent *sequence* of a flow (a sliding window of packets), so it can
   catch attacks that are only visible across time — floods, scans, slow probes —
   that a single-packet view would miss. It engages when a packet looks
   suspicious or anomalous.
3. **Zero-day barrier (Autoencoder)** — trained only on *normal* traffic, it
   flags anything it can't reconstruct well, i.e. anything **out of the
   ordinary**. This is the net for novel / zero-day behaviour.

The three scores are fused into one verdict — **NORMAL / SUSPICIOUS / ATTACK /
UNKNOWN** — plus a 0–100% threat score, and streamed live to the dashboard.
Offending sources can be auto-blocked (real `iptables`, or a safe dry-run).

This matches the design you described: a routine checker, a broader-view checker
for suspicious packets, and an out-of-ordinary checker for zero-day attacks —
fused into one live decision stream.

---

## What I found that didn't fit, and fixed

When I explored the project, several things didn't match the intended design:

- **The models couldn't run at all.** The runtime Python had no `xgboost` and no
  `tensorflow`, so all three barriers loaded as *unavailable* — the dashboard
  was a dead shell. You asked me **not** to install heavy dependencies, so
  instead I made the engine **degrade gracefully**: a pluggable scorer layer
  that uses the real trained models when the libraries are present, and falls
  back to **dependency-free surrogate scorers** otherwise. The surrogates are
  **calibrated against the real training data** (they read the persisted
  `MinMaxScaler` ranges and learn the normal-traffic centroid), so they cleanly
  separate normal vs. attack traffic. The system now works **today**, and
  upgrades to the genuine neural models the moment you install the deps and hit
  *Reload Models*. Every barrier shows `model` vs `surrogate` in the UI.

- **Train/serve feature skew.** Live capture emitted features in a different
  shape than the models were trained on. I routed both paths through one shared
  feature pipeline (`features.py`) and made the serving side mirror training
  (column order, numeric/hex coercion).

- **The context (transformer) barrier was effectively dead.** It needs 50
  packets of flow history, which live/replay traffic rarely accumulated, so it
  never fired. I implemented **"pad & score early"** (your chosen option): once
  a flow has a few packets it's padded to full length for an early,
  lower-confidence read (downgraded from ATTACK to SUSPICIOUS so partial context
  isn't over-trusted). I also fixed replay to use stable per-source flow keys so
  the barrier actually engages. Verified: the context barrier now produces live
  reads.

- **Legacy prototype cruft.** `ID&PS.py` (a single-model Tkinter GUI) and
  `RF_MODEL.py` (a Random-Forest experiment) had hardcoded `/home/kali/…` and
  `/home/maihan/…` paths and contradicted the three-barrier architecture. Moved
  to `legacy/` with a note; they're no longer part of the system.

- **Broken training/preprocessing paths.** The training scripts did
  `pd.read_csv("attack_processed.csv")` assuming the wrong working directory.
  Fixed them to resolve project-relative paths and create their output dirs.

- **No multi-page UI, no interface selection, no persistence.** Addressed below.

---

## What I built / completed

### Core engine
- `src/core/config.py` — single source of truth for paths, thresholds and a
  **persisted** runtime settings object (`config.runtime.json`).
- `src/core/scorers.py` — the pluggable **model-or-surrogate** scorer layer for
  all three barriers, calibrated on the real data.
- `src/core/decision_engine.py` — rewired to the scorer layer, per-flow context
  with pad-early, hot-reload, and a clear fused decision policy.

### Backend (`dashboard/backend/app.py`)
- **Live interface enumeration** (`/api/interfaces`) + capture from any
  interface with **source-IP and protocol filtering** (composed into a BPF).
- Dataset replay, Server-Sent-Events stream (with keep-alives), rolling stats,
  protocol mix, an **alert feed**, per-source intelligence, **per-flow
  drill-down**, **NDJSON event export**, persisted settings, model hot-reload,
  and `iptables` block/unblock (auto + manual, with dry-run).

### Dashboard (`dashboard/frontend/` — `index.html` · `app.css` · `app.js`)
A real multi-page SPA (hash routing) with **6 pages**: Overview, Live Traffic,
Alerts, Sources & Blocking, Models, Settings. Live SSE updates, threat timeline
and protocol charts, the three-barrier decision panel, clickable flow drill-down
modal, attack toasts, an interface dropdown with source/protocol filters, and a
full Settings page that **persists across restarts**.

### Tooling & docs
`requirements.txt`, `run.sh`, package `__init__.py` files, an expanded
`.gitignore`, this `SUMMARY.md`, the top-level `README.md`, and **`TODOS.md`**
listing the manual steps (installing the real model deps, retraining, running
live capture as root) you asked me to write down rather than do.

---

## Verified working

Launched the backend and ran end-to-end:

- All three barriers score live; normal vs. attack traffic separates cleanly
  (replay: ~50% attack rate on mixed profile, normal traffic stays NORMAL).
- The context barrier engages and produces early padded reads.
- SSE stream, stats, alerts, per-source ranking, NDJSON export, settings
  persistence, interface enumeration, and BPF filter composition all confirmed.

---

## How to run

```bash
cd SUHAIL-IDPS
python3 -m pip install -r requirements.txt
./run.sh            # dashboard at http://localhost:5000
# sudo ./run.sh     # for LIVE capture + real iptables blocking
```

Then open the dashboard and either start a **dataset replay** (Live Traffic
page) or, as root, **Start Capture** on a chosen interface.

See **`TODOS.md`** for the (optional) steps to switch from surrogate scorers to
the real trained models.
