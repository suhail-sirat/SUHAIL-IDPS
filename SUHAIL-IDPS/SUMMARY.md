# SUHAIL-IDPS — Summary

## What this system is

**SUHAIL-IDPS** is a live, flow-based Intrusion Detection & Prevention System
driven by a **three-barrier AI pipeline** and a full multi-page real-time
dashboard.

Traffic — captured live from this machine's interfaces, or replayed for demos —
is assembled into **bidirectional flows** (CICFlowMeter-style: each network
conversation summarised by duration, byte/packet rates, packet-size and
inter-arrival statistics, and TCP flag counts). Each flow passes three
independently-trained models that act as layered defences:

1. **Routine barrier — XGBoost.** Classifies each completed flow. Fast, always-on
   first line.
2. **Context barrier — Transformer.** Looks at the recent *sequence of flows* from
   the same source host — the "broader view" that catches multi-flow attacks
   (port scans, DDoS, beaconing, slow-DoS) a single flow can't express.
3. **Zero-day barrier — Autoencoder.** Trained on normal flows only; high
   reconstruction error == out-of-distribution == candidate novel/zero-day event.

The three scores fuse into one verdict — **NORMAL / SUSPICIOUS / ATTACK /
UNKNOWN** — plus a threat score, streamed live to the dashboard. Offending
sources can be auto-blocked (real `iptables`, or a safe dry-run).

The same feature definition (`src/core/flow_features.py` + `flow_tracker.py`) is
used for **both** offline training (from PCAPs) and **live serving** (from the
capture stream), so there is no train/serve skew.

---

## What I changed this round

You asked for three things: correct, paper-grade **training + conversion
scripts** with a fresh **data-collection guide**, and a **better dashboard**.

### 1. Moved from per-packet to flow-based (the paper standard)

The old pipeline was per-packet with several mean-imputed constant columns
(no signal, inflated anomaly scores). The literature (CIC-IDS2017/2018,
UNSW-NB15, recent NIDS papers) uses **bidirectional flow features** — so I built
that end to end:

- `src/core/flow_features.py` — the canonical ~50-feature flow schema (single
  source of truth).
- `src/core/flow_tracker.py` — `FlowStats` + `FlowTracker`: assembles packets
  into bi-flows with CICFlowMeter-style idle/active timeouts; computes the
  feature vector. Used by both offline and live paths.

### 2. Conversion + training scripts (rewritten entirely)

- `src/preprocessing/pcap_to_flows.py` — PCAP → labelled flow CSV.
- `src/preprocessing/merge_flows.py` — merge per-capture CSVs into one dataset.
- `src/preprocessing/build_flow_sequences.py` — flows → per-host sequences for
  the transformer.
- `src/preprocessing/synth_flows.py` — synthetic normal/attack flow generator
  for replay + tests (port-scan, SYN/UDP flood, slow-DoS archetypes).
- `src/training/train_xgboost.py` — single-flow tabular; class-imbalance
  weighting, stratified split, precision/recall/F1/ROC-AUC, feature importances.
- `src/training/train_autoencoder.py` — normal-only; bottleneck AE, early
  stopping, **threshold derived from the normal error distribution** and
  persisted.
- `src/training/train_transformer.py` — multi-head-attention encoder over flow
  sequences; AUC-monitored early stopping; persisted standardiser.

Each model trains on its **correct data format** and each script detects missing
deps and exits with a clear message.

### 3. Data-collection guide

`DATA_COLLECTION.md` — a full walkthrough: lab setup, `tcpdump` capture commands
for normal traffic, attack-generation commands (nmap / hping3 / slowhttptest /
hydra) each captured to its own PCAP, the conversion→merge→sequence→train
commands, and a data-quality checklist. (Lab-safety warning included.)

### 4. Live engine aligned to flows

- `src/core/scorers.py` + `decision_engine.py` rewritten to score flow vectors;
  the context barrier now tracks **per-host flow history** with pad-early.
- `src/live_ids/flow_source.py` — assembles capture/replay packets into flows and
  emits scored events (final + interim/open-flow reads).
- The backend capture path feeds packets through the flow tracker; replay
  generates flows (or replays a real flow CSV if you've built one).
- Pluggable **model-or-surrogate** design retained: surrogates (now calibrated on
  flow features) keep the whole system working before you train, and it upgrades
  automatically on **Reload Models**.

### 5. Dashboard restyle + more functional

`dashboard/frontend/{index.html,app.css,app.js}` — a refreshed visual design
(gradient theme, animated live indicator, switches, hover states, cleaner
cards/charts/tables) and new functionality: per-flow **packet-count** column,
**attack-type** tags, interim-vs-final flow styling, an **engine-mode** badge in
the sidebar, and a flow drill-down modal that now shows a **feature breakdown**
of the latest flow alongside the barrier-by-barrier history.

---

## Verified working

- Engine separates normal vs. attack flows cleanly (normal ≈0.21 avg threat,
  attack ≈1.0); all three barriers engage live.
- Offline pipeline proven end to end: synthetic PCAP → 61 flows → merge → 55
  sequences of shape (16, 52), correct labels.
- Live: replay → flow assembly → scoring → SSE (≈200 events/3s), stats, alerts,
  per-host flow drill-down, NDJSON export, settings persistence, model reload,
  interface enumeration — all confirmed.
- All JS-referenced DOM IDs exist in the HTML (no broken references after the
  restyle).

---

## How to run

```bash
cd SUHAIL-IDPS
python3 -m pip install -r requirements.txt
./run.sh                # dashboard at http://localhost:5000
# sudo ./run.sh         # for LIVE capture + real iptables blocking
```

Open the dashboard → **Live Traffic** → **Start Replay** to see it move, or
collect data and train per **DATA_COLLECTION.md** / **TODOS.md** to serve the
real models.
