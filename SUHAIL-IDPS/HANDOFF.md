# SUHAIL-IDPS — Finish & Run

The dataset is already built. Only training + running is left. Run everything
from inside the `SUHAIL-IDPS/` folder (the one with `run.sh`).

Right now the 3 models are untrained, so the system runs in **surrogate mode** (a
fallback). Training them switches it to the real models.

> Deeper guides: **[GUIDE_SETUP_AND_TRAINING.md](GUIDE_SETUP_AND_TRAINING.md)**
> (training, attack types / Route A↔B, auto-block) and
> **[GUIDE_DASHBOARD.md](GUIDE_DASHBOARD.md)** (every page explained).

## 1. Train the models

```bash
python3 src/training/train_xgboost.py      --data data/flows/all_flows.csv
python3 src/training/train_autoencoder.py  --data data/flows/all_flows.csv
python3 src/training/train_transformer.py  --data data/flows/flow_sequences.csv
python3 src/training/train_attack_type.py  --data data/flows/all_flows.csv  # attack-type naming (Route B)
```

Each saves into `models/…` and **overwrites the old model automatically** — no
manual replacing needed. The last one is new: it names *which kind* of attack a
flow is. Until you train it, the system already names attacks with a built-in
heuristic (Route A) — training just upgrades that to a learned model (Route B),
picked up automatically on **Reload Models**.

## 2. Run

```bash
sudo ./run.sh                 # http://localhost:5000
```

Use `sudo` so it can block IPs (`iptables`) and sniff live traffic. Ctrl+C stops
it. (No sudo also works, but blocking + live capture are disabled.)

## 3. Confirm it's using the real models

Open the **Models** page — each barrier should tag **`model`** (not
`surrogate`). If any still says `surrogate`, click **Reload Models** or restart.

## 4. Use it

- **Live Traffic** → choose an interface → **Start Capture** (or **Start Replay**
  for demo traffic).
- **Sources & Blocking** → block/unblock IPs.
- **Settings** → to auto-block attackers: **Auto-block ON**, **Dry-run OFF**, Save.
  (Dry-run only simulates blocks.)
