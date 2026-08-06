# SUHAIL-IDPS — Setup, Training & Attack Types

This is the guide for the parts **you** run on the machine that has the ML stack
(XGBoost + TensorFlow). Claude has already wired everything on the code side; the
steps below are the human-only tasks: collecting/using data, training, and
flipping the system from the built-in fallbacks to the real trained models.

Run every command from inside the `SUHAIL-IDPS/` folder (the one with `run.sh`).

---

## 0. The mental model — models vs. fallbacks

The engine has **four AI jobs**. Each one runs the real trained model when it can
load it, and a **built-in fallback** otherwise, so the dashboard is never blank:

| Job | Barrier | Real model | Fallback when untrained |
|-----|---------|-----------|--------------------------|
| "Attack or not?" (per flow) | 1 · Routine | XGBoost | surrogate (distance-to-normal) |
| "Hostile flow *sequence*?" | 2 · Context | Transformer | surrogate (host drift) |
| "Never-seen / zero-day?" | 3 · Zero-day | Autoencoder | surrogate (reconstruction energy) |
| **"Which *kind* of attack?"** | Attack typing | XGBoost multi-class (**Route B**) | **heuristic rules (Route A)** |

The first three are the detection barriers. The fourth — **naming the attack
type** — is the new piece, and it has two routes explained below.

You know which is live from the **Models** page: each barrier is tagged
`model` (real) or `surrogate` (fallback), and "Attack typing" shows
`Route A (heuristic)` or `Route B (multi-class model)`.

---

## 1. Attack types — Route A vs. Route B

When a flow is flagged ATTACK/SUSPICIOUS the dashboard now names the archetype
(portscan, synflood, udpflood, httpflood, slowloris, icmpflood, …) in the toast,
the Live table, and the Alerts table.

### Route A — heuristic (already on, no training)
Rule-based labeler in [`src/core/attack_types.py`](src/core/attack_types.py). It
reads a single flow's features and matches the well-known signatures. It needs
no ML stack, works on **live captured traffic** (which has no label), and is the
reason attack types appear *today*, before any training. Measured ~98% top-1
against the bundled labelled dataset and 100% on the synthetic archetypes.

### Route B — trained multi-class model (the "correct" upgrade)
A real classifier trained on the `attack_type` column of your dataset. It learns
the true feature distribution instead of hand rules, and returns a genuine
per-class **confidence**. Use it when you want the most accurate typing and can
train on the ML machine.

> Per-flow, some archetypes are genuinely ambiguous (e.g. a SYN flood vs. a port
> scan differ mainly in *how many ports* they hit, which one flow can't show).
> Route A guesses well; **Route B is what to trust** once trained.

### Switching Route A → Route B
There is nothing to change in code. The engine automatically prefers Route B the
moment its artifacts exist and XGBoost is importable:

```bash
python3 src/training/train_attack_type.py --data data/flows/all_flows.csv
```

This writes `models/xgboost/xgb_type_model.pkl`, `xgb_type_scaler.pkl`,
`xgb_type_labels.pkl`. Then either restart the backend or click **Reload Models**
on the dashboard. The Models page will flip "Attack typing" to
`Route B (multi-class model)`. To go back to Route A, delete those three files
and Reload.

---

## 2. Train the models

Install the stack once on the ML machine:

```bash
pip install xgboost tensorflow scikit-learn pandas joblib
```

Then train (each script overwrites its old artifacts automatically):

```bash
# Detection barriers
python3 src/training/train_xgboost.py      --data data/flows/all_flows.csv
python3 src/training/train_autoencoder.py  --data data/flows/all_flows.csv
python3 src/training/train_transformer.py  --data data/flows/flow_sequences.csv

# Attack typing (Route B) — the new one
python3 src/training/train_attack_type.py  --data data/flows/all_flows.csv
```

`train_attack_type.py` uses only the labelled attack rows (`label == 1` with a
named `attack_type`), drops classes with fewer than 10 samples, and prints a
per-class precision/recall report + confusion matrix so you can see where it
struggles.

---

## 3. Run & confirm

```bash
sudo ./run.sh                 # http://localhost:5000
```

`sudo` enables live capture (sniffing) and real blocking (`iptables`). Without it
the system still runs, but those two are disabled.

Open **Models** and confirm each barrier says `model` (not `surrogate`) and
"Attack typing" says `Route B`. If anything still says the fallback, click
**Reload Models** or restart.

---

## 4. Auto-block ("block after N alerts")

The prevention policy is on the **Settings** page:

- **Auto-block offenders** — turn ON to let the system block sources by itself.
- **Dry-run (simulate)** — ON = registers the block but does **not** touch
  `iptables` (safe for demos). OFF = real enforcement (needs `sudo`).
- **Block after N alerts** — a source is blocked once it has raised **N**
  ATTACK/SUSPICIOUS alerts. Each hostile flow from a source increments its
  counter; the Live-table Action column shows the climb (`2/5 alerts …`), and a
  distinct **AUTO-BLOCKED** toast fires when it trips.
- **Block duration (sec)** — how long the block stays before it auto-expires.

Behaviour hardened so an already-blocked source isn't re-added to `iptables` on
every subsequent alert (no duplicate rules). Blocks also appear on
**Sources & Blocking**, where you can block/unblock by hand.

Quick test without root: Settings → Auto-block ON, Dry-run ON, Block after 3 →
Save → Live → Start Replay (Attack profile). You'll see the counter climb and the
AUTO-BLOCKED toast, with the entry listed under Sources & Blocking.

---

## 5. Reading the numbers (percentages)

- **Threat / barrier scores** are shown as **percentages** in the UI. XGBoost and
  Transformer are probabilities (0–1 → 0–100%). The **Autoencoder** is a
  reconstruction **error** (MSE), not a probability, so its card shows an
  *anomaly level* normalised against its threshold; hover any barrier score to
  see the raw value. On the Models page, thresholds show as % except the
  autoencoder, which stays in raw MSE (labelled).

---

## 6. Rebuilding the dataset (optional)

If you re-collect PCAPs, regenerate flows so the `attack_type` column is
populated (Route B needs it). See [`DATA_COLLECTION.md`](DATA_COLLECTION.md) and
the scripts in [`src/preprocessing/`](src/preprocessing/). Keep the flow feature
schema in [`src/core/flow_features.py`](src/core/flow_features.py) unchanged, or
retrain **all** models against the new schema.
