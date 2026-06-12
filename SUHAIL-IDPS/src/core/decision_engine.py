import os
import numpy as np
import joblib
import tensorflow as tf


# =========================
# PROJECT ROOT
# =========================

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

# XGBoost
XGB_MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "xgboost",
    "xgb_model.pkl"
)

XGB_SCALER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "xgboost",
    "xgb_scaler.pkl"
)

XGB_FEATURES_PATH = os.path.join(
    BASE_DIR,
    "models",
    "xgboost",
    "xgb_features.pkl"
)

# Autoencoder
AE_MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "autoencoder",
    "autoencoder.h5"
)

AE_SCALER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "autoencoder",
    "ae_scaler.pkl"
)

# Transformer
TRANSFORMER_MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "transformer",
    "transformer_model.h5"
)


# =========================
# LOAD MODELS
# =========================
xgb_model = joblib.load(XGB_MODEL_PATH)
xgb_scaler = joblib.load(XGB_SCALER_PATH)
xgb_features = joblib.load(XGB_FEATURES_PATH)

autoencoder = tf.keras.models.load_model(
    AE_MODEL_PATH,
    compile=False
)
ae_scaler = joblib.load(AE_SCALER_PATH)

transformer = tf.keras.models.load_model(
    TRANSFORMER_MODEL_PATH,
    compile=False
)
# =========================
# THRESHOLDS
# =========================
AE_THRESHOLD = 0.02
XGB_THRESHOLD = 0.6


# =========================
# STEP 1: XGBOOST CHECK
# =========================
def xgb_check(packet_df):
    packet_df = packet_df[xgb_features]
    X = xgb_scaler.transform(packet_df)

    prob = xgb_model.predict_proba(X)[0][1]

    return prob


# =========================
# STEP 2: AUTOENCODER CHECK
# =========================
def ae_check(packet_df):
    X = ae_scaler.transform(packet_df)

    recon = autoencoder.predict(X, verbose=0)
    error = np.mean(np.power(X - recon, 2))

    return error


# =========================
# STEP 3: TRANSFORMER CHECK
# =========================
def transformer_check(sequence_array):
    # shape: (1, 50, features)
    pred = transformer.predict(sequence_array, verbose=0)[0][0]
    return pred


# =========================
# FINAL DECISION ENGINE
# =========================
def analyze_packet(packet_df, sequence=None):

    xgb_score = xgb_check(packet_df)
    ae_score = ae_check(packet_df)

    # Step 1: fast rejection
    if xgb_score < XGB_THRESHOLD and ae_score < AE_THRESHOLD:
        return {
            "status": "NORMAL",
            "xgb": xgb_score,
            "ae": ae_score,
            "transformer": None
        }

    # Step 2: suspicious → deep analysis
    transformer_score = None

    if sequence is not None:
        transformer_score = transformer_check(sequence)

    # Step 3: final decision
    if transformer_score is not None and transformer_score > 0.5:
        status = "ATTACK (SESSION)"
    elif xgb_score > XGB_THRESHOLD or ae_score > AE_THRESHOLD:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    return {
        "status": status,
        "xgb": float(xgb_score),
        "ae": float(ae_score),
        "transformer": transformer_score
    }
