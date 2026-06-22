# SUHAIL-IDPS

A live, **flow-based Intrusion Detection & Prevention System** built around a
**three-barrier AI pipeline**, with a full multi-page real-time web dashboard.

Traffic (captured live from this machine's interfaces, or replayed for demos) is
assembled into **bidirectional flows** — CICFlowMeter-style summaries of each
conversation (duration, byte/packet rates, packet-size & inter-arrival stats, TCP
flag counts) — then scored by three independent models working as layered
defences:

| Barrier | Model | Role |
|--------|-------|------|
| **1 — Routine** | XGBoost | Fast per-flow classifier. The always-on first line. |
| **2 — Context** | Transformer | Looks at the recent *sequence of flows* per host — the "broader view" that catches scans / DDoS / slow-DoS. |
| **3 — Zero-day** | Autoencoder | Reconstruction-error anomaly detector trained on normal flows only — flags anything out of the ordinary. |

Scores fuse into a single verdict — **NORMAL / SUSPICIOUS / ATTACK / UNKNOWN** —
plus a threat score, streamed live to the dashboard. The same feature definition
is used for training (from PCAPs) and live serving (from the capture stream), so
there's no train/serve skew.

---

## Quick start

```bash
cd SUHAIL-IDPS
python3 -m pip install -r requirements.txt   # flask, numpy, pandas, sklearn, scapy (+ optional xgboost/tensorflow)
./run.sh                                      # http://localhost:5000
#   sudo ./run.sh                             # needed only for LIVE capture + iptables blocking
```

Open <http://localhost:5000> → **Live Traffic → Start Replay** to see the whole
system in motion immediately.

> **Surrogate mode:** if `xgboost` / `tensorflow` aren't installed (or no models
> are trained yet), the three barriers run dependency-free **surrogate** scorers
> calibrated on flow features, so the full system still works. Collect data +
> train (see below), install the two packages, and hit **Models → Reload Models**
> to switch to the real models. See [`SUHAIL-IDPS/TODOS.md`](SUHAIL-IDPS/TODOS.md).

---

## Collecting data & training

The whole pipeline — `tcpdump` capture, attack generation, PCAP→flow conversion,
and training — is documented step-by-step in
[`SUHAIL-IDPS/DATA_COLLECTION.md`](SUHAIL-IDPS/DATA_COLLECTION.md).

```bash
# PCAP -> flows -> dataset -> sequences
python3 src/preprocessing/pcap_to_flows.py --pcap captures/normal.pcap  --label 0 --out data/flows/normal_flows.csv
python3 src/preprocessing/pcap_to_flows.py --pcap captures/attack_*.pcap --label 1 --out data/flows/attack_flows.csv
python3 src/preprocessing/merge_flows.py   --in  data/flows/normal_flows.csv data/flows/attack_flows.csv --out data/flows/all_flows.csv
python3 src/preprocessing/build_flow_sequences.py --in data/flows/all_flows.csv --out data/flows/flow_sequences.csv

# train each barrier on its correct format
python3 src/training/train_xgboost.py     --data data/flows/all_flows.csv
python3 src/training/train_autoencoder.py --data data/flows/all_flows.csv
python3 src/training/train_transformer.py --data data/flows/flow_sequences.csv
```

---

## The dashboard (6 pages)

- **Overview** — live metrics, the three-barrier decision panel, threat timeline,
  protocol mix, model health.
- **Live Traffic** — capture from any interface (dropdown) with source-IP /
  protocol filtering, flow replay, and the live flow table (packet count,
  attack-type tags, interim vs. final flows; click a row to drill into the host's
  flow history + feature breakdown).
- **Alerts** — every suspicious / hostile decision, with severity.
- **Sources & Blocking** — per-source intelligence and the active block list.
- **Models** — barrier status (model vs. surrogate), engine config, thresholds.
- **Settings** — per-barrier thresholds + prevention policy. **Persisted.**

Live updates arrive over **Server-Sent Events**; toasts pop for new attacks.

---

## Layout

```
SUHAIL-IDPS/
├─ run.sh, requirements.txt, DATA_COLLECTION.md, TODOS.md, SUMMARY.md
├─ data/raw/                 (old per-packet CSVs — superseded, kept for reference)
├─ data/flows/               flow datasets you build (gitignored)
├─ captures/                 your PCAPs (gitignored)
├─ models/{xgboost,transformer,autoencoder}/   trained artifacts + scalers
├─ src/core/
│   ├─ config.py             central config + persisted runtime settings
│   ├─ flow_features.py       canonical bidirectional-flow feature schema
│   ├─ flow_tracker.py        packet → flow assembly (offline + live)
│   ├─ scorers.py             pluggable barrier scorers (model OR surrogate)
│   └─ decision_engine.py     three-barrier fusion + per-host flow context
├─ src/preprocessing/        pcap_to_flows · merge_flows · build_flow_sequences · synth_flows
├─ src/training/             train_xgboost · train_transformer · train_autoencoder
├─ src/live_ids/flow_source.py   live flow assembly for capture/replay
└─ dashboard/
    ├─ backend/app.py        Flask API + live capture/replay/SSE/blocking
    └─ frontend/             index.html · app.css · app.js  (multi-page SPA)
legacy/                      archived prototypes + the old per-packet pipeline
```

## Key environment variables

| Var | Default | Purpose |
|-----|---------|---------|
| `IDPS_PORT` | `5000` | Dashboard port |
| `IDPS_HOST` | `0.0.0.0` | Bind address (use `127.0.0.1` to keep it local) |
| `IDPS_SEQUENCE_LEN` | `16` | Flow-sequence window length for the context barrier |
| `IDPS_TRANSFORMER_PAD_EARLY` | `1` | Score the context barrier early on short host histories |

See [`SUHAIL-IDPS/TODOS.md`](SUHAIL-IDPS/TODOS.md) for manual steps (collecting
data, installing the real model deps, running live capture as root).
