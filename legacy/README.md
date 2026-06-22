# Legacy prototypes (archived)

These are the **early, superseded** prototypes kept for reference only. They are
**not** part of the running system and are not wired into anything.

| File | What it was | Why it's archived |
|------|-------------|-------------------|
| `ID&PS.py` | First single-model (XGBoost only) live IDS with a Tkinter GUI. | Hardcoded `/home/kali/...` paths; single barrier, not the three-barrier design; replaced by `SUHAIL-IDPS/src/core/decision_engine.py` + the web dashboard. |
| `RF_MODEL.py` | A Random-Forest training experiment. | Hardcoded `/home/maihan/...` paths; RF is not one of the three production barriers (XGBoost / Transformer / Autoencoder). |

## `old_per_packet_pipeline/`

The original **per-packet** feature pipeline, superseded by the flow-based one
(`SUHAIL-IDPS/src/core/flow_features.py` + `flow_tracker.py`):

| File | Was | Replaced by |
|------|-----|-------------|
| `features.py` | Per-packet 13-field feature extraction. | `flow_features.py` (bidirectional flow features). |
| `build_transformer_sequences.py` | Per-packet sequence builder. | `build_flow_sequences.py` (per-host flow sequences). |
| `verify_data.py`, `advanced_data_check.py` | Quick data-quality checks for the old per-packet CSVs. | (general utilities; not part of the flow pipeline). |

The real system lives in [`../SUHAIL-IDPS/`](../SUHAIL-IDPS/). See the top-level
[`../README.md`](../README.md) and [`../SUHAIL-IDPS/SUMMARY.md`](../SUHAIL-IDPS/SUMMARY.md).
