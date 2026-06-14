# TODOS — manual steps for you

These are things I (the assistant) could **not** do in this environment, or that
are optional improvements. The system is fully working without them — they make
it *better* or *more accurate*. Ordered by impact.

---

## 1. Install the real model dependencies (HIGH IMPACT, recommended)

**Why it matters.** Right now the three barriers run in **surrogate mode** —
lightweight, dependency-free approximations I built so the whole system works on
this machine today (you asked me not to install TensorFlow / XGBoost). The real
trained models (`xgb_model.pkl`, `transformer_model.h5`, `autoencoder.h5`) are
present on disk but **can't be loaded** because their runtime libraries aren't
installed:

- `xgboost` — needed to unpickle and run `xgb_model.pkl` (Barrier 1).
- `tensorflow` (or `tensorflow-cpu`) — needed to load both `.h5` Keras models
  (Barrier 2 transformer + Barrier 3 autoencoder).

**What to do** (when you have a good connection / the downloads available):

```bash
cd SUHAIL-IDPS
python3 -m pip install xgboost tensorflow-cpu
```

Then either restart the backend, or just open the dashboard → **Models** page →
click **Reload Models**. The barrier tags will flip from `surrogate` to `model`.

> Note: the surrogates are calibrated against the real data and separate normal
> vs. attack traffic cleanly, but the genuine neural models will be more
> accurate on subtle / novel patterns. Surrogate vs. model is always shown in
> the UI so you know which is active.

---

## 2. Retrain the models (OPTIONAL — only if you want fresh metrics)

You said you don't want to retrain right now (no TensorFlow yet). When you do,
the training scripts now resolve their own paths correctly (I fixed them — they
used to assume the CSVs were in the current directory):

```bash
cd SUHAIL-IDPS
python3 src/preprocessing/build_transformer_sequences.py   # rebuild sequences
python3 src/training/train_xgboost.py
python3 src/training/train_autoencoder.py
python3 src/training/train_transformer.py
```

**Data issue worth fixing before retraining (I left the data as-is):**
The processed CSVs contain several columns that were **mean-imputed with a single
constant value** (e.g. `tcp.srcport = 20977.03…` on every normal row, hex
`tcp.flags`). That's the "averaging/accumulation" preprocessing. It works, but it
means those columns carry almost no per-packet signal and inflate anomaly scores
on live traffic. If you re-run your capture→CSV preprocessing, prefer keeping
**real per-packet port/flag values** (impute only truly-missing cells, per row,
not with a global mean). The serving pipeline already handles raw values.

There are also **4 malformed rows** in `normal_processed.csv` (blank `label`).
They're harmless (coerced to 0) but you may want to drop them at the source.

---

## 3. Run live capture with the right privileges (when you want LIVE sniffing)

Live capture and real `iptables` blocking need **root**:

```bash
cd SUHAIL-IDPS
sudo ./run.sh
```

Then on the **Live Traffic** page pick an interface from the dropdown (it lists
this machine's real interfaces), optionally set a source-IP / protocol filter,
and hit **Start Capture**. Without `sudo`, capture will report a permission
error in the UI but everything else (replay, dashboard) still works.

> `iptables` is Linux-only. On this machine it's available; if you ever move to
> a host without it, set **Settings → Dry-run = on** so blocks are simulated.

---

## 4. Optional polish (LOW priority)

- **Production server:** `app.py` uses Flask's dev server. For real deployment
  put it behind `gunicorn`/`waitress` (note: SSE needs a worker model that
  supports streaming, e.g. `gunicorn -k gthread`).
- **Persistent event store:** events live in memory (last 2000) and reset on
  restart. Add SQLite if you want history across restarts.
- **`src/preprocessing/verify_data.py` & `advanced_data_check.py`** still use
  bare relative paths (`pd.read_csv("attack_processed.csv")`). They're just
  diagnostics; run them from `data/raw/` or update the paths if you use them.
- **Authentication:** the dashboard has no auth. Bind it to `127.0.0.1`
  (`IDPS_HOST=127.0.0.1`) or put it behind a reverse proxy if exposing it.
