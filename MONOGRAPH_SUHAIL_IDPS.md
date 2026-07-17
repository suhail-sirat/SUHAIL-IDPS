# AI-Based Intrusion Detection and Prevention System (IDPS)
## Technical Reference Document for the Monograph

> **Purpose of this document.** This is a complete technical briefing on the IDPS project, written to give whoever prepares the monograph every implementation, methodology, dataset and results detail in one place. It describes the full project as designed and built: a live, flow-based, three-barrier AI Intrusion Detection & Prevention System with a real-time dashboard. Where the monograph needs experimental numbers (accuracy, precision, etc.), result tables are laid out ready to be filled from the training/evaluation runs.

**Project:** IDPS — a live, flow-based, three-barrier AI IDPS
**Author:** Suhail Sirat
**Platform:** Linux (Kali/Ubuntu) · Python 3.12
**Repository root:** `IDPS/`

---

## Table of Contents

1. Project Overview and Architecture
2. Development Environment
3. Complete Project File Structure
4. Dataset Information
5. Data Preprocessing and Feature Engineering
6. AI/ML Models Implementation
7. Model Comparison
8. Live IDPS Implementation
9. Prevention (IPS) Module
10. Dashboard Implementation
11. Evaluation and Results (Chapter 4)
12. Limitations and Future Work (Chapter 5)
13. Source Code Submission

---

# 1. Project Overview and Architecture

## 1.1 What the system is

**IDPS** is a live, **flow-based** Intrusion Detection & Prevention System driven by a **three-barrier AI pipeline** and a full multi-page real-time web dashboard.

Network traffic — captured live from the host's interfaces, or replayed for demonstrations — is assembled into **bidirectional flows** (CICFlowMeter / CIC-IDS-2017 style: each network conversation summarised by duration, byte/packet rates, packet-size and inter-arrival statistics, and TCP-flag counts). Each completed flow passes three independently-trained models that act as layered defences ("barriers"):

| Barrier | Model | Role |
|---------|-------|------|
| **1 — Routine** | XGBoost | Fast per-flow classifier — the always-on first line. |
| **2 — Context** | Transformer (multi-head attention) | Looks at the recent *sequence of flows* from the same source host — the "broader view" that catches multi-flow attacks (port scans, DDoS, beaconing, slow-DoS) that a single flow cannot express. |
| **3 — Zero-day** | Autoencoder | Reconstruction-error anomaly detector trained on **normal flows only** — high reconstruction error = out-of-distribution = candidate novel/zero-day event. |

The three scores are **fused** into one verdict — **NORMAL / SUSPICIOUS / ATTACK / UNKNOWN** — plus a numeric **threat score**, and streamed live to the dashboard over Server-Sent Events (SSE). Offending source IPs can be **auto-blocked** using real `iptables` rules (with a safe dry-run mode for testing).

A central design principle is **no train/serve skew**: the *same* feature definition (`src/core/flow_features.py`) and the *same* flow-assembly code (`src/core/flow_tracker.py`) are used for **both** offline training (from PCAPs) and **live serving** (from the capture stream).

## 1.2 End-to-end workflow (beginning → end)

```
                    ┌─────────────────────────────────────────────────────┐
                    │  DATA COLLECTION (own machine / lab)                 │
   tcpdump  ──────► │  normal_*.pcap   (benign traffic captures)           │
   nmap/hping3/     │  attack_*.pcap   (6 attack types) + *.meta.json      │
   slowhttptest     └─────────────────────────────────────────────────────┘
                                        │
                                        ▼
       ┌─────────────────────────── OFFLINE PIPELINE ───────────────────────────┐
       │ pcap_to_flows.py   PCAP → labelled bidirectional-flow CSV (52 features) │
       │ merge_flows.py     per-capture CSVs → one shuffled all_flows.csv        │
       │ build_flow_sequences.py  flows → per-host sequences (16×52) for barrier2│
       └────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
       ┌─────────────────────────────  TRAINING  ───────────────────────────────┐
       │ train_xgboost.py      → models/xgboost/xgb_model.pkl (+scaler,+features)│
       │ train_autoencoder.py  → models/autoencoder/autoencoder.h5 (+scaler,+thr)│
       │ train_transformer.py  → models/transformer/transformer_model.h5 (+scaler)│
       └────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
       ┌──────────────────────────  LIVE SERVING  ──────────────────────────────┐
       │ scapy sniff ─► flow_tracker ─► flow_source ─► decision_engine (3 barriers)│
       │                                    │                                     │
       │                                    ▼                                     │
       │  Flask backend (app.py):  scoring, stats, alerts, SSE stream, iptables  │
       │                                    │                                     │
       │                                    ▼                                     │
       │  Web dashboard (index.html/app.js/app.css): 6 live pages                │
       └────────────────────────────────────────────────────────────────────────┘
```

**Step-by-step:**

1. **Capture** — `tcpdump` records normal traffic to `dataset/normal/*.pcap`; `collect_attack.sh` generates and captures each attack type to `dataset/attack/attack_<type>.pcap` with a `.meta.json` sidecar recording the victim/attacker IPs, attacked port(s) and the exact attack time-window.
2. **Convert** — `pcap_to_flows.py` streams each PCAP with scapy, assembles bidirectional flows with `FlowTracker`, computes the 52-feature vector per flow, and writes a labelled CSV. Attacks use **windowed labelling** (only attacker↔victim flows on the attacked port(s) inside the attack window are labelled `1`; background flows stay `0`).
3. **Merge & sequence** — `merge_flows.py` concatenates and shuffles all per-capture CSVs into `all_flows.csv`; `build_flow_sequences.py` groups flows per source host into fixed-length sliding windows of 16 flows for the transformer.
4. **Train** — three scripts train the three barriers, each on its correct data format, saving models + scalers (+ autoencoder threshold) to `models/`.
5. **Serve** — the Flask backend captures/replays traffic, assembles flows live, scores each with the three-barrier `DecisionEngine`, fuses a verdict, streams it to the browser, and applies the prevention policy.
6. **Respond** — when auto-block is enabled and a source crosses the alert threshold, the backend inserts an `iptables … -j DROP` rule and schedules automatic unblock after the configured duration.

## 1.3 Component / module map and communication

| Layer | Module(s) | Responsibility | Communicates with |
|-------|-----------|----------------|-------------------|
| **Feature contract** | `src/core/flow_features.py` | Canonical 52-feature flow schema (single source of truth), sequence length, timeouts | imported by everything |
| **Flow assembly** | `src/core/flow_tracker.py` | `FlowStats` + `FlowTracker`: packets → bi-flows → feature vector | preprocessing + live source |
| **Scorers** | `src/core/scorers.py` | `RoutineScorer` (XGBoost), `ContextScorer` (Transformer), `AnomalyScorer` (Autoencoder) | decision engine |
| **Decision fusion** | `src/core/decision_engine.py` | Runs the three barriers, keeps per-host flow history, fuses verdict + threat score | backend |
| **Config/settings** | `src/core/config.py` | Paths, thresholds, prevention policy, persisted runtime settings | all modules |
| **Offline preprocessing** | `src/preprocessing/*` | PCAP→flows, merge, sequences, capture analysis | CLI scripts |
| **Training** | `src/training/*` | XGBoost / Autoencoder / Transformer trainers | CLI scripts |
| **Live source** | `src/live_ids/flow_source.py` | Wraps `FlowTracker` for capture/replay; emits scored flow events (final + interim) | backend |
| **Backend** | `dashboard/backend/app.py` | Flask REST + SSE, capture/replay threads, stats/alerts, iptables prevention | frontend, engine |
| **Frontend** | `dashboard/frontend/{index.html,app.js,app.css}` | 6-page single-page dashboard | backend REST/SSE |

**Communication mechanisms:** intra-Python via direct imports and a shared in-process `DecisionEngine` singleton; backend ↔ frontend via **HTTP REST** (`/api/*`) and a **Server-Sent-Events** stream (`/api/stream`); prevention via `subprocess` calls to the system `iptables` binary.

## 1.4 Deployment model

- **Deployment target:** a **personal-computer / single-host monitoring system**. It captures on the host's own network interfaces (Wi-Fi `wlp2s0`/`wlan0`, Ethernet `eth0`, or a Docker bridge such as `br-…`) and protects that host.
- **OS:** developed and run on **Linux**. The data-collection guide targets **Kali Linux**, which ships the attack tools (`nmap`, `hping3`, `slowhttptest`); the engine and dashboard run equally on Ubuntu.
- **Prevention scope:** blocks inbound traffic at the local host firewall (`iptables INPUT` chain) — host-level enforcement.
- The sensor can also be pointed at a Docker bridge interface to monitor container traffic, which is how the attack lab is built (attacker = host, victim = local WordPress/Apache container on a `172.18.0.0/16` bridge, a realistic L2 path with MTU 1500 rather than loopback).

---

# 2. Development Environment

| Item | Value |
|------|-------|
| **Operating System** | Linux, kernel `6.8.0-124-generic`. Data collection performed on Kali Linux (attack tooling); engine/dashboard run on Ubuntu-family Linux. |
| **Python version** | **Python 3.12** |
| **Primary language** | Python 3 (engine, preprocessing, training, backend) |
| **Frontend languages** | HTML5, CSS3, vanilla JavaScript (ES6, no framework, no build step) |
| **Shell** | Bash (data-collection + run scripts) |
| **IDE / development environment** | Visual Studio Code |
| **Version control** | Git |
| **Hardware** | x86-64 laptop/PC, standard multi-core CPU and RAM; **CPU-only** execution (models configured for CPU; no GPU required). Local storage holds the captured PCAP dataset. |

### Python frameworks / libraries (`requirements.txt`)

**Engine + dashboard:**
- `flask>=3.0` — REST API + SSE backend
- `numpy>=1.26`, `pandas>=2.0` — numerics + CSV handling
- `scikit-learn>=1.3` — `StandardScaler`, `MinMaxScaler`, `train_test_split`, evaluation metrics
- `joblib>=1.3` — model/scaler serialization
- `scapy>=2.5` — live packet capture + PCAP reading

**Model training / inference:**
- `xgboost>=2.0` — Barrier 1 (routine classifier)
- `tensorflow-cpu>=2.15` — Barriers 2 & 3 (transformer + autoencoder)

**System tools (data collection / prevention):** `tcpdump`, `nmap`, `hping3`, `slowhttptest`, `iptables`, `docker`, plus everyday clients (`curl`, `dig`, `ping`, `openssl`, `ssh`, `whois`).

---

# 3. Complete Project File Structure

```
IDPS/                                  (outer repository)
├─ README.md
├─ setup_project.sh
├─ dataset/                                   ← self-collected raw PCAPs
│  ├─ normal/   normal_*.pcap                          benign traffic captures
│  └─ attack/   attack_<type>.pcap + .meta.json        6 attack types + signatures
└─ IDPS/                               ← main project
   ├─ run.sh                                  launch dashboard (sudo for live capture)
   ├─ requirements.txt
   ├─ DATA_COLLECTION.md                      full capture + attack-generation guide
   ├─ TODOS.md, SUMMARY.md
   ├─ collect_attack.sh                       ATTACK capture automation (Docker victim)
   ├─ collect_normal_topup.sh                 diverse NORMAL traffic generator + capture
   ├─ captures/                               working PCAP dir
   ├─ data/
   │  └─ flows/   normal_flows.csv, attack_*.csv, all_flows.csv, flow_sequences.csv
   ├─ models/
   │  ├─ xgboost/     xgb_model.pkl, xgb_scaler.pkl, xgb_features.pkl
   │  ├─ autoencoder/ autoencoder.h5, ae_scaler.pkl, ae_threshold.pkl
   │  └─ transformer/ transformer_model.h5, transformer_scaler.pkl
   ├─ logs/
   ├─ src/
   │  ├─ core/
   │  │  ├─ config.py            central config + persisted runtime settings
   │  │  ├─ flow_features.py     canonical 52-feature flow schema (source of truth)
   │  │  ├─ flow_tracker.py      packet → bidirectional-flow assembly (offline + live)
   │  │  ├─ scorers.py           barrier scorers (per-model inference)
   │  │  └─ decision_engine.py   three-barrier fusion + per-host flow context
   │  ├─ preprocessing/
   │  │  ├─ pcap_to_flows.py         PCAP → labelled flow CSV (windowed labelling)
   │  │  ├─ merge_flows.py           merge per-capture CSVs → all_flows.csv
   │  │  ├─ build_flow_sequences.py  flows → per-host sequences (transformer)
   │  │  └─ analyze_captures.py      PCAP dataset-health report
   │  ├─ training/
   │  │  ├─ train_xgboost.py         Barrier 1 trainer
   │  │  ├─ train_autoencoder.py     Barrier 3 trainer
   │  │  └─ train_transformer.py     Barrier 2 trainer
   │  └─ live_ids/
   │     └─ flow_source.py           live flow assembly for capture/replay
   └─ dashboard/
      ├─ backend/app.py              Flask API + live capture/replay/SSE/blocking
      └─ frontend/ index.html · app.js · app.css   (multi-page SPA)
```

### Purpose of each important file (by function requested)

| Function | File(s) |
|----------|---------|
| **Data preprocessing** | `src/preprocessing/pcap_to_flows.py`, `merge_flows.py`, `build_flow_sequences.py`; feature definition `src/core/flow_features.py`; flow assembly `src/core/flow_tracker.py`; dataset health `src/preprocessing/analyze_captures.py` |
| **Model training** | `src/training/train_xgboost.py`, `train_autoencoder.py`, `train_transformer.py` |
| **Model testing / evaluation** | Held-out split + metrics **inside each training script** (`classification_report`, `confusion_matrix`, `roc_auc_score`; autoencoder threshold separation) |
| **Prediction / detection** | `src/core/decision_engine.py` (fusion), `src/core/scorers.py` (per-barrier inference) |
| **Live monitoring** | `dashboard/backend/app.py` (capture/replay threads + SSE), `src/live_ids/flow_source.py` |
| **Packet capture** | `dashboard/backend/app.py` → `capture_packets()` / `process_scapy_packet()` (scapy `sniff`); PCAP reading `pcap_to_flows.py::iter_packets` |
| **Prevention module** | `dashboard/backend/app.py` → `block_ip()`, `unblock_ip()`, `cleanup_expired_blocks()`, `maybe_respond()` (iptables) |
| **Flask backend** | `dashboard/backend/app.py` |
| **Dashboard frontend** | `dashboard/frontend/index.html`, `app.js`, `app.css` |
| **Config** | `src/core/config.py` (+ persisted `config.runtime.json`) |

---

# 4. Dataset Information

The system is trained and evaluated on a **self-collected network-traffic dataset** captured on the author's own machine/lab (the only legally testable target), following `DATA_COLLECTION.md`.

## 4.1 Collection method

- **Capture tool:** `tcpdump` (full-packet capture, `-s 0`, `-nn`), driven by two helper scripts.
- **Normal traffic:** `collect_normal_topup.sh` runs `tcpdump -i <iface> -nn -s 0 ip -w normal_topup_<ts>.pcap` while generating a **diverse client-protocol mix** so "normal" is not a monoculture — DNS (`dig` A/AAAA/MX to ~28 domains), ICMP (`ping`), HTTP (`curl` :80), HTTPS (`curl` :443), FTP, SSH handshakes, IMAPS/POP3S/SMTPS TLS handshakes (`openssl s_client`), NTP (UDP/123), WHOIS (:43), and real bulk downloads. Rotating captures (`-G 600 -W 6`) are also used.
- **Attack traffic:** `collect_attack.sh` uses a **local Docker WordPress/Apache container as the victim** (real L2 bridge, MTU 1500 — realistic, not loopback). It captures **one filtered PCAP per attack type** (BPF `host <victim>`) plus a `.meta.json` recording the attack signature and precise time-window.

## 4.2 Network environment

| Property | Value |
|----------|-------|
| Environment | LAN / wireless (host Wi-Fi) for normal traffic; Docker bridge (`172.18.0.0/16`) for attack traffic |
| Interfaces | Wi-Fi `wlp2s0` / `wlan0` (normal), Docker bridge `br-…` (attacks) |
| Capture tool | `tcpdump` (snaplen 0 = full packets, `-nn`, BPF `ip` / `host <victim>`) |
| PCAP reader | scapy `PcapReader` (streaming) in `pcap_to_flows.py` and `analyze_captures.py` |
| Victim (attacks) | Docker container (WordPress/Apache), e.g. `172.18.0.4` |
| Attacker (attacks) | Docker bridge gateway (the host), e.g. `172.18.0.1` |

## 4.3 Attack types generated

| Attack type | Tool | Target port(s) | Category |
|-------------|------|----------------|----------|
| Port scan | `nmap -sS / -sV / -sU` (bounded) | 1–10000 / top-100 / top-30 UDP | Reconnaissance |
| SYN flood | `hping3 -S -i u200 -p 80` | 80 | DoS/DDoS (TCP) |
| UDP flood | `hping3 --udp -i u200 -p 80` | 80 | DoS/DDoS (UDP) |
| ICMP flood | `hping3 -1 -i u200` | — (ICMP) | DoS/DDoS (ICMP) |
| Slowloris | `slowhttptest -c 800 -H` | 80 | Slow / low-rate DoS (application-layer) |
| HTTP flood | 40× parallel `curl` GET burst | 80 | Application-layer flood |

Each attack is captured to its own PCAP with a `.meta.json` such as:
```json
{ "attack_type": "synflood", "victim_ip": "172.18.0.4", "attacker_ip": "172.18.0.1",
  "victim_ports": [80], "start_ts": 1784285710.5437, "end_ts": 1784285730.5804 }
```

## 4.4 PCAP → CSV conversion and labelling

- **Conversion:** `pcap_to_flows.py` streams packets (scapy), assembles bidirectional flows keyed by the 5-tuple, computes the 52-feature vector, and writes `FLOW_FEATURES + [src_ip, dst_ip, attack_type, label]`.
- **Labelling method — windowed / signature-based (CIC-IDS-2017 style):** a capture is *never* labelled wholesale. A flow gets `label=1` **only** if it matches the attack signature from `.meta.json`: victim IP present, attacker IP present, on the attacked port(s), inside the `[start_ts, end_ts]` window. All other (background) flows stay `label=0`. Pure normal captures are labelled `--label 0` wholesale.

## 4.5 Dataset composition

- **Two classes (binary):** `0` = normal, `1` = attack. An `attack_type` sub-label column is retained for per-type analysis.
- **Feature count:** **52** bidirectional-flow features (+ label) — see §5.1.
- **Structure:** per-attack flow CSVs + a normal flow CSV are merged and shuffled into `all_flows.csv`; the transformer additionally consumes per-host sequences (`flow_sequences.csv`).
- **Target balance (per `DATA_COLLECTION.md` data-quality guidance):** roughly **60–80 % normal / 20–40 % attack** across the merged set — realistic (traffic is mostly normal) but with enough attack signal. Class imbalance is additionally handled at training time (`scale_pos_weight` for XGBoost). SYN-flood and port-scan yield the highest flow volumes; slowloris and HTTP-flood contribute lower-rate and application-layer signatures for diversity.

*(Populate the final per-class flow counts and total sample count here after the dataset build completes: `data/flows/all_flows.csv` label distribution is printed by `merge_flows.py`.)*

| Class | Flows (fill after build) |
|-------|--------------------------|
| Normal (0) | _tbd_ |
| Attack (1) — total | _tbd_ |
| &nbsp;&nbsp;• port scan | _tbd_ |
| &nbsp;&nbsp;• SYN flood | _tbd_ |
| &nbsp;&nbsp;• UDP flood | _tbd_ |
| &nbsp;&nbsp;• ICMP flood | _tbd_ |
| &nbsp;&nbsp;• slowloris | _tbd_ |
| &nbsp;&nbsp;• HTTP flood | _tbd_ |
| **Total** | _tbd_ |

---

# 5. Data Preprocessing and Feature Engineering

## 5.1 The 52 flow features (final feature list used by the models)

Defined once in `src/core/flow_features.py` (`FLOW_FEATURES`), computed by `FlowStats.to_features()`:

**Duration / counts (7):** `flow_duration`, `total_fwd_packets`, `total_bwd_packets`, `total_packets`, `total_fwd_bytes`, `total_bwd_bytes`, `total_bytes`
**Forward packet-length (4):** `fwd_pkt_len_max/min/mean/std`
**Backward packet-length (4):** `bwd_pkt_len_max/min/mean/std`
**Overall packet-length (5):** `pkt_len_max/min/mean/std/var`
**Throughput (5):** `flow_bytes_per_s`, `flow_pkts_per_s`, `fwd_pkts_per_s`, `bwd_pkts_per_s`, `down_up_ratio`
**Flow inter-arrival time — IAT (4):** `flow_iat_mean/std/max/min`
**Forward IAT (5):** `fwd_iat_total/mean/std/max/min`
**Backward IAT (5):** `bwd_iat_total/mean/std/max/min`
**TCP flag counts (6):** `fin/syn/rst/psh/ack/urg_flag_count`
**Header / ratio (5):** `fwd_header_len`, `bwd_header_len`, `avg_pkt_size`, `fwd_seg_size_avg`, `bwd_seg_size_avg`
**Protocol / port context (2):** `protocol` (6=TCP, 17=UDP, 1=ICMP), `dst_port`

## 5.2 How features are extracted from traffic

- Packets are normalised to a dict (`ts, length, proto, src_ip, dst_ip, src_port, dst_port, header_len, tcp_flags`).
- `FlowTracker` keys packets into bidirectional flows (5-tuple; first-seen endpoint ordering fixes the forward direction), accumulating per-direction lengths, timestamps (for IAT), header bytes and OR-ed TCP flags.
- Flows are **emitted** when: idle ≥ `IDLE_TIMEOUT = 15 s`, or alive ≥ `ACTIVE_TIMEOUT = 120 s`, or (for TCP) on `RST` / double-`FIN`, or on capacity eviction. `to_features()` then computes max/min/mean/std of lengths and IATs, throughput rates, ratios and flag counts.
- The **same** code path runs offline (PCAP) and live (capture) → identical feature space, so there is no train/serve skew.

## 5.3 Cleaning, conversion, encoding

| Step | Implementation |
|------|----------------|
| Missing values | `_finite()` maps NaN/Inf → 0.0 at feature-build; every trainer/merger uses `pd.read_csv(...).fillna(0)` |
| Data-type conversion | Features cast to `float`; label cast to `int` |
| Categorical encoding | Minimal — `protocol` is a numeric code (6/17/1) and `dst_port` is numeric, so no one-hot encoding is needed. Verdict labels are strings only at the UI layer. |
| Label conversion | Binary `0/1`; string `attack_type` retained for analysis |
| Scaling — XGBoost | `sklearn.StandardScaler` (fit on train fold; persisted `xgb_scaler.pkl` for serving parity) |
| Scaling — Autoencoder | `sklearn.MinMaxScaler` → [0,1] (pairs with the sigmoid output); persisted `ae_scaler.pkl` |
| Scaling — Transformer | Per-feature standardisation (train-fold mean/std), persisted in `transformer_scaler.pkl` |
| Train/test split | `train_test_split(test_size=0.2, random_state=42, stratify=y)` → **80/20 stratified** |
| Random state | **42** (all trainers/mergers) |
| Feature selection / reduction | The 52-feature set is a deliberate focused subset of the full ~80 CICFlowMeter features. XGBoost prints `feature_importances_` for post-hoc insight. |

## 5.4 Sequence construction (Barrier 2)

`build_flow_sequences.py`: group flows by `src_ip`; slide a window of **`SEQUENCE_LEN = 16`** flows with **stride 4**; a window is labelled attack if **any** flow in it is an attack (`labels.max()`). Short hosts are zero-padded up to one window. Output is flattened to `16 × 52 = 832` columns + `label`.

---

# 6. AI/ML Models Implementation

## 6.1 XGBoost — Barrier 1 (Routine)

- **Training file:** `src/training/train_xgboost.py`
- **Input:** `data/flows/all_flows.csv` (one row per flow) → `X = FLOW_FEATURES`, `y = label`
- **Configuration / hyper-parameters (`XGBClassifier`):**

| Parameter | Value |
|-----------|-------|
| `n_estimators` (number of estimators) | **400** |
| `max_depth` (tree depth) | **7** |
| `learning_rate` | **0.05** |
| `subsample` | 0.9 |
| `colsample_bytree` | 0.9 |
| `reg_lambda` | 1.0 |
| `min_child_weight` | 2 |
| `scale_pos_weight` | `n_neg / n_pos` (computed from the training fold — class-imbalance weighting) |
| `objective` | `binary:logistic` |
| `eval_metric` | `aucpr` |
| `n_jobs` | −1 (all cores) |
| `random_state` | 42 |

- **Training process:** StandardScaler → stratified 80/20 split → `fit` with an `eval_set` validation fold → predict probabilities.
- **Testing process:** on the 20 % hold-out — `confusion_matrix`, `classification_report` (precision/recall/F1, 4-dp), `roc_auc_score`, and the top-12 feature importances.
- **Model saving:** `joblib.dump` → `models/xgboost/xgb_model.pkl`, `xgb_scaler.pkl`, `xgb_features.pkl`.

## 6.2 Autoencoder — Barrier 3 (Zero-day)

- **Training file:** `src/training/train_autoencoder.py`
- **Input:** **normal rows only** (`label == 0`) from `all_flows.csv`
- **Architecture (Keras Sequential — symmetric, with a bottleneck):**

| Layer | Neurons | Activation |
|-------|---------|-----------|
| Input | 52 | — |
| Dense | 48 | ReLU |
| Dense | 24 | ReLU |
| Dense (bottleneck) | 12 | ReLU |
| Dense | 24 | ReLU |
| Dense | 48 | ReLU |
| Output | 52 | Sigmoid |

- **Number of layers:** 6 Dense layers (3 encoder + 3 decoder) around a 12-unit bottleneck.
- **Optimizer:** Adam · **Loss:** MSE (mean squared error) · **Epochs:** 60 with **EarlyStopping** (`val_loss`, patience 8, restore best weights) · **Batch size:** 128 · **validation_split:** 0.15
- **Threshold calculation:** reconstruction MSE is computed over the normal set; the detection threshold = **99th percentile** of the normal-error distribution, persisted to `ae_threshold.pkl` (`{"threshold": …, "percentile": 99}`). The script also reports the percentage of attack flows above the threshold (separation).
- **Model saving:** `model.save` → `autoencoder.keras` **and** `autoencoder.h5`; `joblib.dump` scaler + threshold.

## 6.3 Transformer — Barrier 2 (Context)

- **Training file:** `src/training/train_transformer.py`
- **Input:** `flow_sequences.csv` reshaped to `(N, 16, 52)`
- **Architecture:** input `(16, 52)` → Dense(64) projection (learnable embedding) → **2 × Transformer encoder blocks**, each: LayerNorm → **MultiHeadAttention (num_heads = 4, key_dim = 32, dropout = 0.2)** → residual add → LayerNorm → Dense(128, ReLU) → Dropout(0.2) → Dense(back to width) → residual add → GlobalAveragePooling1D → Dense(64, ReLU) → Dropout(0.3) → **Dense(1, sigmoid)**.

| Hyper-parameter | Value |
|-----------------|-------|
| Encoder blocks (layers) | 2 |
| Attention heads | 4 |
| Head size (`key_dim`) | 32 |
| Feed-forward dimension | 128 |
| Embedding / projection size | 64 |
| Dropout | 0.2 (blocks) / 0.3 (head) |
| Optimizer | Adam (learning rate 1e-3) |
| Loss | binary cross-entropy |
| Metrics | accuracy, AUC |
| Epochs | 40, EarlyStopping on `val_auc` (max, patience 6, restore best) |
| Batch size | 64 |
| Split | stratified 80/20, seed 42 |

- **Training method:** per-feature standardisation (train-fold mean/std) → fit with validation set → predict.
- **Testing:** `confusion_matrix`, `classification_report`, `roc_auc_score` on the hold-out.
- **Model saving:** `transformer_model.keras` + `.h5`; scaler dict `{mean, std, seq_len, n_features}` → `transformer_scaler.pkl`.

## 6.4 Resilience feature — graceful degradation

`src/core/scorers.py` implements each barrier as a pluggable scorer that loads the trained model when present and, if a model is temporarily unavailable, falls back to a lightweight **surrogate** calibrated on the normal-flow profile — so the full dashboard remains demonstrable at all times and upgrades to the trained models automatically via **Reload Models**. Each barrier reports its current mode (`model`) to the dashboard.

---

# 7. Model Comparison

**Design intent:** the three models are **complementary layered barriers**, not competing alternatives — each covers a different failure mode:

- **XGBoost** — sharp on **known** single-flow attack signatures (fast, always-on).
- **Transformer** — catches **multi-flow / temporal** campaigns a single flow cannot show.
- **Autoencoder** — flags **novel / zero-day** out-of-distribution flows (trained on normal only).

**Evaluation metrics used for each model:** Accuracy, Precision, Recall, F1-score, Confusion Matrix, Classification Report, and ROC-AUC (for XGBoost & Transformer); reconstruction-error separation and detection-rate-above-threshold (Autoencoder).

**Why the final decision uses all three (fusion, `decision_engine.py::_decide`):** rather than selecting a single "best" model, the engine combines them so that the strengths of each cover the others' blind spots:
- Transformer ≥ threshold on full context → **ATTACK (critical)**; on early/padded context → **SUSPICIOUS**.
- XGBoost ≥ attack-threshold (0.85) → **ATTACK**; combined with an autoencoder anomaly → stronger evidence.
- Autoencoder anomaly and/or XGBoost ≥ suspicious-threshold (0.60) → **SUSPICIOUS**.
- No model available → **UNKNOWN**; all below thresholds → **NORMAL**.
- The **threat score** = the maximum of the normalised per-barrier scores.

**Comparison results table (fill from the training/evaluation runs):**

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|-------|----------|-----------|--------|-----|---------|
| XGBoost (Barrier 1) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| Transformer (Barrier 2) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| Autoencoder (Barrier 3) | detection-rate @ p99 threshold: _tbd_ | — | _tbd_ | — | — |

---

# 8. Live IDPS Implementation

## 8.1 Packet-capture module

- **Library / tool:** **scapy** (`sniff`), in `dashboard/backend/app.py::capture_packets()` (thread) + `process_scapy_packet()` (per-packet callback).
- **How packets are captured:** `sniff(iface=…, filter=<BPF>, prn=process_scapy_packet, store=False, stop_filter=…)`. Each IP packet is normalised (ts, length, proto, IPs, ports, header_len, tcp_flags) and fed to the flow assembler.
- **Interface:** operator-selected from a dropdown (`/api/interfaces` via scapy `get_if_list`) — any host NIC or "all".
- **Capture filters:** a BPF filter composed from the UI controls (`build_bpf`): base `ip`, optional `tcp|udp|icmp`, optional `src host <ip>`.
- **Files responsible:** `app.py` (`capture_packets`, `process_scapy_packet`, `build_bpf`, `list_interfaces`) and `src/live_ids/flow_source.py`. Live capture runs with **root** privileges.

## 8.2 Feature-extraction module (live)

- Live packets → `LiveFlowSource.feed()` → `FlowTracker` → `FlowStats.to_features()` — the **exact same** 52-feature function used in training. **The live features are therefore identical to the training features** (no skew).
- Two emission triggers: **final** (flow completes/expires) and **interim** (an open flow re-scored as it grows — first at ≥ 2 packets, then every +6 packets) so the dashboard shows activity live instead of waiting for slow flows to close.

## 8.3 Detection module

- **Model loading:** `scorers.py` loads XGBoost (`joblib`) and the Keras `.keras/.h5` models; reloadable at runtime via `/api/reload`.
- **Prediction:** `DecisionEngine.analyze_flow()` always scores the routine + anomaly barriers, and runs the transformer when the routine or anomaly barrier already flags the flow (needs context), using the host's recent flow window (padded early per config).
- **Output format:** a JSON verdict — `status ∈ {NORMAL, SUSPICIOUS, ATTACK, UNKNOWN}`, `severity ∈ {low, medium, high, critical}`, `reason`, `threat_score ∈ [0,1]`, and per-barrier `{score, threshold, mode, state (PASS/ALERT/WAITING), latency_ms}`.
- **Confidence:** the `threat_score` (max normalised barrier score) is the system confidence; XGBoost `predict_proba` gives the per-flow attack probability.

---

# 9. Prevention (IPS) Module

- **Technology:** **Linux `iptables`** (host firewall), invoked via `subprocess`. Files: `dashboard/backend/app.py` → `maybe_respond()`, `block_ip()`, `unblock_ip()`, `cleanup_expired_blocks()`.
- **How malicious traffic is blocked:** on an ATTACK/SUSPICIOUS verdict the source IP's alert counter increments; when auto-block is enabled and the counter reaches the threshold, a DROP rule is inserted:
  ```bash
  iptables -A INPUT -s <ip> -j DROP        # block
  iptables -D INPUT -s <ip> -j DROP        # unblock
  ```
- **Blocking condition / threshold:** policy `block_threshold` (default **5** alerts from a source) with `auto_block` enabled; SUSPICIOUS-and-above verdicts count.
- **Blocking duration:** `block_duration_seconds` (default **300 s** = 5 minutes).
- **Automatic unblock:** `cleanup_expired_blocks()` runs on each stats/blocked poll; when an entry's `expires_at` passes, `unblock_ip()` removes the rule. Manual block/unblock is available via `/api/block` and `/api/unblock`.
- **Dry-run mode:** `policy.dry_run` (toggle in Settings) registers a block in the UI **without** touching iptables — safe for testing; real enforcement requires running as root.
- **Defaults (`config.py::DEFAULT_POLICY`):** `auto_block=False`, `dry_run=False`, `block_threshold=5`, `block_duration_seconds=300`, `alert_min_severity="suspicious"`.

---

# 10. Dashboard Implementation

## 10.1 Backend (Flask)

- **Main backend file:** `dashboard/backend/app.py` (Flask, threaded server with an SSE-capable streaming endpoint).
- **API routes:**

| Route | Method | Purpose |
|-------|--------|---------|
| `/` , `/<page>` | GET | serve the SPA (index.html / static assets) |
| `/api/health` | GET | engine + capture + replay + prevention + settings snapshot |
| `/api/interfaces` | GET | list network interfaces |
| `/api/settings` (`/api/config`) | GET/POST | thresholds + policy (persisted) |
| `/api/reload` | POST | reload models |
| `/api/stats` | GET | rolling counters, protocol mix, top sources, throughput |
| `/api/events` | GET | recent scored events (filter by status/source) |
| `/api/events/export` | GET | NDJSON export of the event buffer |
| `/api/alerts` | GET | alert feed |
| `/api/flow/<flow_key>` | GET | per-flow drill-down history |
| `/api/analyze` | POST | score a posted flow / feature dict |
| `/api/replay/{start,stop,status}` | POST/GET | replay control |
| `/api/capture/{start,stop,status}` | POST/GET | live-capture control |
| `/api/blocked`, `/api/block`, `/api/unblock` | GET/POST | prevention list |
| `/api/stream` | GET (SSE) | live scored-event stream |

- **Data exchanged between backend and frontend:** JSON throughout. The SSE stream pushes each scored **event** `{id, timestamp, source, final, metadata, flow (52 features), result (verdict + barriers), action}`. Stats, alerts and the blocked list are JSON polls.

## 10.2 Frontend

- **Technologies:** HTML5 + CSS3 (custom gradient theme, `app.css`) + **vanilla JavaScript** (`app.js`, no framework / no build step). Charts are drawn on `<canvas>` (`lineChart`, `barChart`); live updates arrive via `EventSource` (SSE).
- **Pages (6):** Overview, Live Traffic, Alerts, Sources & Blocking, Models, Settings.
- **Information displayed:**
  - **Total flows/packets**, **Normal**, **Suspicious**, **Attacks**, **Blocked IPs** metric cards; flows/min, uptime, attack-rate.
  - **Three-Barrier AI Decision** panel — live score / meter / state / latency per barrier.
  - **Threat timeline** and **protocol-mix** canvas charts; **model-health** cards.
  - **Live flow table** — Time, Status, Source, Destination, Protocol, **Packet count**, Threat, Reason, Action; interim (open) flows shown in italic; click a row → **flow drill-down modal** with the barrier-by-barrier history and a 52-feature breakdown.
  - **Alerts feed** (severity, source/destination, threat score, reason) — the prediction results.
  - **Sources & Blocking** — hot sources ranked by attacks; active **blocked-IP** list (auto + manual) with unblock buttons.
  - **Models** — barrier status, engine configuration (52 features, sequence length 16), active thresholds.
  - **Settings** — per-barrier thresholds + prevention policy (auto-block, dry-run, block-after-N, duration); **persisted** across restarts.
- **Real-time?** Yes — Server-Sent Events push every scored flow; toast notifications pop on new attacks; a live indicator shows the connection state, and the **logs / event feed** update continuously.

---

# 11. Evaluation and Results (Chapter 4)

## 11.1 Metrics computed by the code

- **XGBoost & Transformer:** Confusion matrix, Classification report (Precision, Recall, F1 per class + accuracy), **ROC-AUC**. Training time = wall-clock of `model.fit`.
- **Autoencoder:** normal reconstruction-error mean / p95 / p99, the chosen **threshold (p99)**, and the **% of attacks above threshold** (detection separation).
- **Live IDPS system:** live counters exposed by `/api/stats` — total analysed flows, detected attacks, normal, suspicious, blocked IPs, attack rate; per-barrier detection latency (`result.barriers.*.latency_ms`); response time (alert → block).

## 11.2 Per-model results (fill from the training runs)

| Model | Accuracy | Precision | Recall | F1-score | ROC-AUC | Training time |
|-------|----------|-----------|--------|----------|---------|---------------|
| XGBoost (Barrier 1) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| Transformer (Barrier 2) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| Autoencoder (Barrier 3) | — | _tbd_ | _tbd_ | _tbd_ | — | _tbd_ |

**Confusion matrix / classification report:** paste the stdout of each training script.

## 11.3 Live IDPS system results (fill from a live/replay session, via `/api/stats`)

| Metric | Value |
|--------|-------|
| Total analysed flows/packets | _tbd_ |
| Detected attacks | _tbd_ |
| Normal flows | _tbd_ |
| Suspicious | _tbd_ |
| Blocked IP addresses | _tbd_ |
| Attack rate | _tbd_ |
| Detection time (per-barrier latency, ms) | _tbd_ |
| Response time (alert → iptables block) | _tbd_ |
| False positives (normal-only session) | _tbd_ |

## 11.4 Reproduce the pipeline

```bash
cd IDPS
# PCAP → flows (normal wholesale; attacks windowed via meta.json)
python3 src/preprocessing/pcap_to_flows.py --pcap ../dataset/normal/*.pcap --label 0 --out data/flows/normal_flows.csv
for p in ../dataset/attack/attack_*.pcap; do \
  python3 src/preprocessing/pcap_to_flows.py --pcap "$p" --label 1 --meta "${p%.pcap}.meta.json" \
     --out "data/flows/$(basename ${p%.pcap}).csv"; done
# merge + sequences
python3 src/preprocessing/merge_flows.py --in data/flows/normal_flows.csv data/flows/attack_*.csv --out data/flows/all_flows.csv
python3 src/preprocessing/build_flow_sequences.py --in data/flows/all_flows.csv --out data/flows/flow_sequences.csv
# train the three barriers (each prints its metrics)
python3 src/training/train_xgboost.py     --data data/flows/all_flows.csv
python3 src/training/train_autoencoder.py --data data/flows/all_flows.csv
python3 src/training/train_transformer.py --data data/flows/flow_sequences.csv
# run the live dashboard (sudo for live capture + iptables)
sudo ./run.sh        # http://localhost:5000
```

---

# 12. Limitations and Future Work (Chapter 5)

## 12.1 Current limitations / weaknesses

- **Single-host, host-based sensor:** the system protects the machine it runs on (host `iptables` enforcement), not a whole network segment inline.
- **Focused 52-feature subset** (vs the full ~80 CICFlowMeter set) — cheaper to compute live, but not a one-to-one match to published 80-feature benchmark numbers.
- **Binary detection** (normal vs attack) at the decision layer; per-attack-type multi-class output is kept only as an analysis sub-label.
- **In-memory state and dev server:** events are kept in memory (last 2000); the Flask development server is used; there is no authentication by default.
- **Lab-generated attacks:** attacks are produced in a controlled single-box Docker lab, so real-world adversarial diversity is narrower than a production network.

## 12.2 Hardware / software constraints

- **CPU-only** training and inference (no GPU) — fine for these model sizes but slower for large-scale retraining.
- **Single-box lab** (attacker + Docker victim on one machine) rather than a multi-host testbed.

## 12.3 Future improvements

- Extend the feature set toward the **full ~80 CICFlowMeter** features for benchmark parity, and add **multi-class** (per-attack-type) detection heads.
- Add **persistent storage** (SQLite) for events/history, **authentication**, and a **production WSGI server** (gunicorn `gthread`) behind a reverse proxy for robust SSE.
- Broaden the dataset (more normal-traffic diversity, more attack variants and intensities) and periodically **retrain** the barriers.
- Explore **inline / gateway deployment** (e.g. NFQUEUE-based prevention) so the system can protect a network segment rather than a single host.

---

# 13. Source Code Submission

Full files live in the repository at the paths shown in §3. The key files are reproduced below in condensed form; open them directly in the repo for the complete listings (backend `app.py` ≈ 836 lines, frontend `app.js` ≈ 627 lines, `app.css` ≈ 303 lines).

## 13.1 Feature contract — `src/core/flow_features.py`
See §5.1 for the full 52-feature list. Constants: `SEQUENCE_LEN=16`, `IDLE_TIMEOUT=15.0`, `ACTIVE_TIMEOUT=120.0`, `LABEL_COLUMN="label"`, `NUM_FEATURES=52`.

## 13.2 Flow assembly — `src/core/flow_tracker.py` (core)
```python
# TCP flag masks: FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20
class FlowStats:                     # accumulates one bidirectional flow → 52-feature vector
    def add(self, pkt, forward):
        ts, length = float(pkt.get("ts",0)), float(pkt.get("length",0))
        if not self.started: self.first_ts, self.started = ts, True
        self.last_ts = ts; self.all_times.append(ts)
        (self.fwd_lengths if forward else self.bwd_lengths).append(length)
        (self.fwd_times   if forward else self.bwd_times).append(ts)
        flags = int(pkt.get("tcp_flags",0) or 0)
        if flags:
            self.fin += bool(flags & FIN); self.syn += bool(flags & SYN)
            self.rst += bool(flags & RST); self.psh += bool(flags & PSH)
            self.ack += bool(flags & ACK); self.urg += bool(flags & URG)
    def is_expired(self, now):
        return self.idle_for(now) >= IDLE_TIMEOUT or (now-self.first_ts) >= ACTIVE_TIMEOUT
    # to_features() → dict of all 52 features (durations, rates, IAT stats, flags, ...)

class FlowTracker:                   # keys packets to 5-tuple flows; expires idle/RST/FIN flows
    def add_packet(self, pkt): ...   # returns list of completed FlowStats
```

## 13.3 Data preprocessing — `src/preprocessing/pcap_to_flows.py` (essentials)
```python
def iter_packets(pcap_path):                       # scapy streaming reader → packet dicts
    from scapy.all import ICMP, IP, TCP, UDP, PcapReader
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if IP not in pkt: continue
            ip = pkt[IP]; proto = int(ip.proto); src_port=dst_port=tcp_flags=l4=0
            if TCP in pkt:  src_port,dst_port=int(pkt[TCP].sport),int(pkt[TCP].dport); tcp_flags=int(pkt[TCP].flags); l4=int(pkt[TCP].dataofs or 5)*4
            elif UDP in pkt: src_port,dst_port=int(pkt[UDP].sport),int(pkt[UDP].dport); l4=8
            elif ICMP in pkt: l4=8
            yield {"ts":float(pkt.time),"length":int(len(pkt)),"proto":proto,
                   "src_ip":str(ip.src),"dst_ip":str(ip.dst),"src_port":src_port,
                   "dst_port":dst_port,"header_len":int(getattr(ip,"ihl",5) or 5)*4+l4,
                   "tcp_flags":tcp_flags}

class AttackLabeler:                               # windowed signature labelling
    def label_for(self, flow):
        if not self.enabled: return self.attack_label
        if self.victim_ip not in {flow.src_ip, flow.dst_ip}: return 0
        if self.attacker_ip and self.attacker_ip not in {flow.src_ip, flow.dst_ip}: return 0
        if self.victim_ports and not (flow.src_port in self.victim_ports or flow.dst_port in self.victim_ports): return 0
        if self.window and (flow.last_ts < self.window[0] or flow.first_ts > self.window[1]): return 0
        return self.attack_label
# convert(): FlowTracker over all packets → rows: FLOW_FEATURES + [src_ip,dst_ip,attack_type,label]
```

## 13.4 Merge & sequences — `merge_flows.py`, `build_flow_sequences.py`
```python
# merge_flows.py: concat per-capture CSVs, shuffle (random_state=42), write all_flows.csv
df = pd.concat([pd.read_csv(p) for p in inp], ignore_index=True).fillna(0)
df = df.sample(frac=1.0, random_state=42).reset_index(drop=True); df.to_csv(out, index=False)

# build_flow_sequences.py: group by src_ip; sliding window seq_len=16, stride=4;
# window label = max(labels in window); short hosts zero-padded; flatten to 16*52 + label
```

## 13.5 XGBoost trainer — `src/training/train_xgboost.py`
```python
X = df[FLOW_FEATURES].to_numpy(float); y = df[LABEL_COLUMN].to_numpy(int)
X_tr,X_te,y_tr,y_te = train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)
scaler = StandardScaler(); X_tr_s=scaler.fit_transform(X_tr); X_te_s=scaler.transform(X_te)
spw = (y_tr==0).sum()/max((y_tr==1).sum(),1)
model = XGBClassifier(n_estimators=400,max_depth=7,learning_rate=0.05,subsample=0.9,
        colsample_bytree=0.9,reg_lambda=1.0,min_child_weight=2,scale_pos_weight=spw,
        objective="binary:logistic",eval_metric="aucpr",n_jobs=-1,random_state=42)
model.fit(X_tr_s,y_tr,eval_set=[(X_te_s,y_te)],verbose=False)
proba = model.predict_proba(X_te_s)[:,1]; pred = (proba>=0.5).astype(int)
print(confusion_matrix(y_te,pred)); print(classification_report(y_te,pred,digits=4))
print("ROC-AUC:", roc_auc_score(y_te,proba))
joblib.dump(model, OUT_DIR/"xgb_model.pkl"); joblib.dump(scaler, OUT_DIR/"xgb_scaler.pkl")
joblib.dump(list(FLOW_FEATURES), OUT_DIR/"xgb_features.pkl")
```

## 13.6 Autoencoder trainer — `src/training/train_autoencoder.py`
```python
def build_model(input_dim):
    return tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_dim,)),
        tf.keras.layers.Dense(48,activation="relu"), tf.keras.layers.Dense(24,activation="relu"),
        tf.keras.layers.Dense(12,activation="relu"),                       # bottleneck
        tf.keras.layers.Dense(24,activation="relu"), tf.keras.layers.Dense(48,activation="relu"),
        tf.keras.layers.Dense(input_dim,activation="sigmoid")])            # compile(adam, mse)
X_normal = df[df.label==0][FLOW_FEATURES].to_numpy(float)
X = MinMaxScaler().fit_transform(X_normal)
es = EarlyStopping("val_loss", patience=8, restore_best_weights=True)
model.fit(X,X,epochs=60,batch_size=128,validation_split=0.15,callbacks=[es])
err = np.mean(np.square(X-model.predict(X)),axis=1)
threshold = float(np.percentile(err, 99.0))        # persisted to ae_threshold.pkl
```

## 13.7 Transformer trainer — `src/training/train_transformer.py`
```python
def transformer_encoder(inputs, head_size, num_heads, ff_dim, dropout):
    x = LayerNormalization(epsilon=1e-6)(inputs)
    attn = MultiHeadAttention(key_dim=head_size, num_heads=num_heads, dropout=dropout)(x,x)
    x = Add()([attn, inputs])
    y = LayerNormalization(epsilon=1e-6)(x); y = Dense(ff_dim,activation="relu")(y)
    y = Dropout(dropout)(y); y = Dense(inputs.shape[-1])(y)
    return Add()([y, x])
def build_model(seq_len, n_features):              # seq_len=16, n_features=52
    inputs = Input(shape=(seq_len,n_features)); x = Dense(64)(inputs)
    for _ in range(2): x = transformer_encoder(x, head_size=32, num_heads=4, ff_dim=128, dropout=0.2)
    x = GlobalAveragePooling1D()(x); x = Dense(64,activation="relu")(x); x = Dropout(0.3)(x)
    outputs = Dense(1,activation="sigmoid")(x)
    m = Model(inputs,outputs); m.compile(Adam(1e-3),"binary_crossentropy",["accuracy",AUC(name="auc")])
    return m
# standardise per feature (train mean/std) → fit(epochs=40, batch=64, EarlyStopping val_auc)
```

## 13.8 Prediction / fusion — `src/core/decision_engine.py`
```python
def _decide(self, xgb, ae, tr, padded):
    th = settings.thresholds
    xgb_attack = xgb is not None and xgb >= th["xgb_attack"]      # 0.85
    xgb_susp   = xgb is not None and xgb >= th["xgb_suspicious"]  # 0.60
    ae_anom    = ae  is not None and ae  >= th["autoencoder"]
    session    = tr  is not None and tr  >= th["transformer"]     # 0.50
    if session and not padded: return "ATTACK","critical","Transformer confirmed hostile flow-sequence."
    if session and padded:     return "SUSPICIOUS","high","Transformer flagged host on early context."
    if xgb_attack and ae_anom: return "ATTACK","high","Routine + anomaly both crossed attack policy."
    if xgb_attack:             return "ATTACK","high","Routine XGBoost crossed attack threshold."
    if ae_anom and xgb_susp:   return "SUSPICIOUS","medium","Suspicious + outside normal reconstruction."
    if ae_anom:                return "SUSPICIOUS","medium","Autoencoder found out-of-ordinary flow."
    if xgb_susp:               return "SUSPICIOUS","medium","Routine XGBoost marked flow suspicious."
    if xgb is None and ae is None and tr is None: return "UNKNOWN","low","No model available."
    return "NORMAL","low","All barriers below thresholds."
```

## 13.9 Live detection + packet capture — `dashboard/backend/app.py`
```python
def capture_packets(interface, bpf_filter):
    global CAPTURE_SOURCE; CAPTURE_SOURCE = LiveFlowSource(protocol_name)
    from scapy.all import sniff
    sniff(iface=interface, filter=bpf_filter, prn=process_scapy_packet, store=False,
          stop_filter=lambda _: CAPTURE_STOP.is_set())

def process_scapy_packet(pkt):
    from scapy.all import ICMP, IP, TCP, UDP
    if IP not in pkt or CAPTURE_SOURCE is None: return
    ip = pkt[IP]  # build normalised packet dict (ts,length,proto,ips,ports,header,flags)
    for ev in CAPTURE_SOURCE.feed(packet):        # → flow assembly → scored events
        process_flow(ev["features"], metadata={**ev["metadata"], "interface":CAPTURE_INFO["interface"]},
                     source="capture", final=ev["final"])
```

## 13.10 IPS / iptables — `dashboard/backend/app.py`
```python
def block_ip(ip, reason):
    policy = settings.policy
    expires_at = time.time() + int(policy["block_duration_seconds"])    # default 300s
    entry = {"ip":ip,"reason":reason,"dry_run":bool(policy["dry_run"]),
             "blocked_at":..., "expires_at":..., "active":True}
    if not policy["dry_run"]:
        subprocess.run(["iptables","-A","INPUT","-s",ip,"-j","DROP"], check=True)
    BLOCKED[ip] = entry; return {"type":"block","entry":entry}

def unblock_ip(ip):
    entry = BLOCKED.pop(ip, None)
    if entry and not entry.get("dry_run"):
        subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"], check=True)
    return {"type":"unblock","ip":ip,"active":False}

def cleanup_expired_blocks():                     # auto-unblock when expires_at passes
    now = time.time()
    for ip, e in list(BLOCKED.items()):
        if datetime.fromisoformat(e["expires_at"]).timestamp() <= now: unblock_ip(ip)
```

## 13.11 Flask backend — `dashboard/backend/app.py`
Full file in the repo. Routes in §10.1; SSE stream at `/api/stream`; scoring in `process_flow()`; replay in `replay_packets()` / `_replay_from_csv()`; stats/alerts in `record_event()`.

## 13.12 HTML — `dashboard/frontend/index.html`
Full file in the repo: the 6-page SPA (sidebar nav; Overview metrics + three-barrier panel + charts; Live-Traffic capture/replay controls + live flow table; Alerts; Sources & Blocking; Models; Settings; flow drill-down modal). Loads `app.css` + `app.js`.

## 13.13 CSS — `dashboard/frontend/app.css`
Full file in the repo: custom gradient dark theme, CSS variables, responsive grid layouts (`.grid.two/.three/.even`), barrier cards, meters, tables, toggle switches, animated live-dot, modal, toasts.

## 13.14 JavaScript — `dashboard/frontend/app.js`
Full file in the repo. Key functions: `api()` (fetch wrapper), `connectStream()` (`EventSource` SSE → `ingest()`), hash router (`route`/`renderRoute`), canvas charts (`lineChart`, `barChart`), `renderBarriers`, `renderOverview/Live/Alerts/Sources/Blocked/Models/Settings`, `openFlow()` (drill-down modal + feature breakdown), `saveSettings()`, capture/replay/block button wiring, `toast()` notifications.

---

## Appendix A — Config quick reference (`src/core/config.py`)

| Setting | Value |
|---------|-------|
| `xgb_suspicious` threshold | 0.60 |
| `xgb_attack` threshold | 0.85 |
| `autoencoder` threshold | trained p99 (default 0.05) |
| `transformer` threshold | 0.50 |
| `SEQUENCE_LEN` | 16 |
| `TRANSFORMER_PAD_EARLY` | on |
| `TRANSFORMER_MIN_CONTEXT` | 3 |
| `auto_block` / `dry_run` | False / False |
| `block_threshold` / `block_duration_seconds` | 5 / 300 |
| `IDPS_PORT` / `IDPS_HOST` | 5000 / 0.0.0.0 |

## Appendix B — Environment variables

`IDPS_PORT`, `IDPS_HOST`, `IDPS_SEQUENCE_LEN`, `IDPS_TRANSFORMER_PAD_EARLY`, `IDPS_TRANSFORMER_MIN_CONTEXT`, `IDPS_MAX_FLOWS`, and the four threshold overrides (`IDPS_XGB_SUSPICIOUS_THRESHOLD`, `IDPS_XGB_ATTACK_THRESHOLD`, `IDPS_AE_THRESHOLD`, `IDPS_TRANSFORMER_THRESHOLD`).

*End of reference document.*
