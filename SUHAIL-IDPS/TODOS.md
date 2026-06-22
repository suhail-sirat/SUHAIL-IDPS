# TODOS — manual steps for you

The system is fully working in **surrogate mode** without any of these. They make
it *better* / *more accurate*. Ordered by impact.

---

## 1. Collect a real dataset and train the models (HIGH IMPACT)

This is the big one and it's now a clean, documented pipeline. Full instructions
with copy-paste `tcpdump` + attack commands are in **`DATA_COLLECTION.md`**.

Short version:

```bash
cd SUHAIL-IDPS

# 1. capture normal + attack PCAPs (see DATA_COLLECTION.md for the commands)
#    sudo tcpdump -i <iface> -nn -s 0 ip -w captures/normal.pcap        (normal)
#    sudo tcpdump ... + nmap/hping3/slowhttptest                        (attacks)

# 2. PCAP -> flow CSVs
python3 src/preprocessing/pcap_to_flows.py --pcap captures/normal.pcap  --label 0 --out data/flows/normal_flows.csv
python3 src/preprocessing/pcap_to_flows.py --pcap captures/attack_*.pcap --label 1 --out data/flows/attack_flows.csv

# 3. merge + build sequences
python3 src/preprocessing/merge_flows.py --in data/flows/normal_flows.csv data/flows/attack_flows.csv --out data/flows/all_flows.csv
python3 src/preprocessing/build_flow_sequences.py --in data/flows/all_flows.csv --out data/flows/flow_sequences.csv

# 4. train (needs xgboost + tensorflow — see step 2 below)
python3 src/training/train_xgboost.py     --data data/flows/all_flows.csv
python3 src/training/train_autoencoder.py --data data/flows/all_flows.csv
python3 src/training/train_transformer.py --data data/flows/flow_sequences.csv
```

Then **Models → Reload Models** in the dashboard (or restart). Barrier tags flip
from `surrogate` to `model`.

---

## 2. Install the training/serving model dependencies

The trained models need two libraries that aren't installed here (you asked me
not to install them):

```bash
cd SUHAIL-IDPS
python3 -m pip install xgboost tensorflow-cpu
```

- `xgboost` — Barrier 1 (routine). Without it the training script exits with a
  clear message and live serving uses the surrogate.
- `tensorflow-cpu` — Barriers 2 & 3 (transformer + autoencoder).

The surrogates are calibrated to the data and separate normal vs. attack cleanly,
but the real models will be sharper on subtle/novel patterns. The UI always shows
which mode each barrier is in.

---

## 3. Run live capture with the right privileges

Live capture + real `iptables` blocking need **root**:

```bash
cd SUHAIL-IDPS
sudo ./run.sh
```

On the **Live Traffic** page pick an interface, optionally set a source-IP /
protocol filter, and **Start Capture**. The capture assembles packets into
bidirectional flows in real time and scores each flow. Without `sudo`, capture
reports a permission error in the UI but replay + the rest still work.

---

## 4. Optional cleanup / polish (LOW priority)

- **Old datasets.** `data/raw/normal_processed.csv`, `attack_processed.csv` and
  `data/sequences/transformer_sequences.csv` are the *old per-packet* data, no
  longer used by anything (replay now uses flows). Safe to delete once you've got
  your own flow dataset — I left them in place rather than delete your data.
- **Old per-packet code** moved to `../legacy/old_per_packet_pipeline/`.
- **Production server.** `app.py` uses Flask's dev server; for deployment use
  `gunicorn -k gthread` (SSE needs a streaming-capable worker).
- **Persistent event store.** Events live in memory (last 2000). Add SQLite if
  you want history across restarts.
- **Auth.** No authentication. Bind to `127.0.0.1` (`IDPS_HOST=127.0.0.1`) or put
  it behind a reverse proxy if you expose it.
- **CICFlowMeter parity.** The flow schema is a focused ~50-feature subset. If you
  want to compare against published CIC-IDS2017 numbers, you can extend
  `flow_features.py` + `flow_tracker.py` toward the full 80-feature set.
