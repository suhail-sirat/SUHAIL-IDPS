# Legacy prototypes (archived)

These are the **early, superseded** prototypes kept for reference only. They are
**not** part of the running system and are not wired into anything.

| File | What it was | Why it's archived |
|------|-------------|-------------------|
| `ID&PS.py` | First single-model (XGBoost only) live IDS with a Tkinter GUI. | Hardcoded `/home/kali/...` paths; single barrier, not the three-barrier design; replaced by `SUHAIL-IDPS/src/core/decision_engine.py` + the web dashboard. |
| `RF_MODEL.py` | A Random-Forest training experiment. | Hardcoded `/home/maihan/...` paths; RF is not one of the three production barriers (XGBoost / Transformer / Autoencoder). |

The real system lives in [`../SUHAIL-IDPS/`](../SUHAIL-IDPS/). See the top-level
[`../README.md`](../README.md) and [`../SUHAIL-IDPS/SUMMARY.md`](../SUHAIL-IDPS/SUMMARY.md).
