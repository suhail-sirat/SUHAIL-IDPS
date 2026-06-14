# SUHAIL-IDPS

A live **Intrusion Detection & Prevention System** built around a **three-barrier
AI pipeline**, with a full multi-page real-time web dashboard.

Every packet (captured live from this machine's interfaces, or replayed from the
bundled datasets) is scored by three independent models working as layered
defences:

| Barrier | Model | Role |
|--------|-------|------|
| **1 — Routine** | XGBoost | Fast per-packet classifier. The always-on first line. |
| **2 — Context** | Transformer | Looks at the recent *sequence* of a flow — the "broader view" that catches slow / multi-packet attacks. |
| **3 — Zero-day** | Autoencoder | Reconstruction-error anomaly detector trained on normal traffic only — flags anything out of the ordinary. |

The barriers' scores are fused into a single verdict — **NORMAL / SUSPICIOUS /
ATTACK / UNKNOWN** — plus a normalised threat score, streamed live to the
dashboard.

---

## Quick start

```bash
cd SUHAIL-IDPS
python3 -m pip install -r requirements.txt   # flask, numpy, pandas, sklearn, scapy (+ optional xgboost/tensorflow)
./run.sh                                      # http://localhost:5000
#   sudo ./run.sh                             # needed only for LIVE capture + iptables blocking
```

Open <http://localhost:5000>. With no live traffic yet, go to **Live Traffic →
Dataset Replay → Start Replay** to see the whole system in motion immediately.

> **Surrogate mode:** if `xgboost` / `tensorflow` aren't installed, the three
> barriers automatically run dependency-free **surrogate** scorers (calibrated
> against the real training data) so the full system still works. Install those
> two packages and hit **Models → Reload Models** to switch to the real trained
> models. See [`SUHAIL-IDPS/TODOS.md`](SUHAIL-IDPS/TODOS.md).

---

## The dashboard (6 pages)

- **Overview** — live metrics, the three-barrier decision panel, threat
  timeline, protocol mix, model health.
- **Live Traffic** — capture from any interface (dropdown) with source-IP /
  protocol filtering, dataset replay controls, and the live packet table
  (click any row to drill into a flow's barrier-by-barrier history).
- **Alerts** — every suspicious / hostile decision, with severity.
- **Sources & Blocking** — per-source intelligence and the active block list
  (manual + auto block / unblock).
- **Models** — barrier status (model vs. surrogate), engine config, thresholds.
- **Settings** — tune per-barrier thresholds and the prevention policy
  (auto-block, dry-run, thresholds, durations). **Persisted across restarts.**

Live updates arrive over **Server-Sent Events**; toasts pop for new attacks.

---

## Layout

```
SUHAIL-IDPS/
├─ run.sh, requirements.txt, TODOS.md, SUMMARY.md
├─ data/raw/                 normal_processed.csv, attack_processed.csv
├─ data/sequences/           transformer_sequences.csv
├─ models/{xgboost,transformer,autoencoder}/   trained artifacts + scalers
├─ src/core/
│   ├─ config.py             central config + persisted runtime settings
│   ├─ features.py           feature extraction / numeric coercion
│   ├─ scorers.py            pluggable barrier scorers (model OR surrogate)
│   └─ decision_engine.py    three-barrier fusion + flow context
├─ src/preprocessing/        sequence builder + data checks
├─ src/training/             train_xgboost / train_transformer / train_autoencoder
└─ dashboard/
    ├─ backend/app.py        Flask API + live capture/replay/SSE/blocking
    └─ frontend/             index.html · app.css · app.js  (multi-page SPA)
legacy/                      archived early single-model prototypes (not used)
```

## Key environment variables

| Var | Default | Purpose |
|-----|---------|---------|
| `IDPS_PORT` | `5000` | Dashboard port |
| `IDPS_HOST` | `0.0.0.0` | Bind address (use `127.0.0.1` to keep it local) |
| `IDPS_SEQUENCE_LEN` | `50` | Flow window length for the context barrier |
| `IDPS_TRANSFORMER_PAD_EARLY` | `1` | Score the context barrier early on short flows |

See [`SUHAIL-IDPS/TODOS.md`](SUHAIL-IDPS/TODOS.md) for manual steps (installing
the real model deps, retraining, running live capture as root).
