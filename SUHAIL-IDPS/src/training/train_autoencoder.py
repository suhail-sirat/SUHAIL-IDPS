import os
import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler
import joblib

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
RAW = os.path.join(BASE_DIR, "data", "raw")
AE_OUT = os.path.join(BASE_DIR, "models", "autoencoder")
os.makedirs(AE_OUT, exist_ok=True)

# =========================
# LOAD NORMAL DATA ONLY
# =========================
df = pd.read_csv(os.path.join(RAW, "normal_processed.csv"))
df = df.fillna(0)

if df["tcp.flags"].dtype == "object":
    df["tcp.flags"] = df["tcp.flags"].apply(
        lambda x: int(str(x), 16) if str(x).startswith("0x") else 0
    )

df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

X = df.drop("label", axis=1).values

# =========================
# SCALE
# =========================
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# =========================
# MODEL
# =========================
input_dim = X.shape[1]

model = tf.keras.Sequential([
    tf.keras.layers.Dense(32, activation="relu", input_shape=(input_dim,)),
    tf.keras.layers.Dense(16, activation="relu"),
    tf.keras.layers.Dense(32, activation="relu"),
    tf.keras.layers.Dense(input_dim, activation="sigmoid")
])

model.compile(optimizer="adam", loss="mse")

# =========================
# TRAIN
# =========================
model.fit(
    X_scaled, X_scaled,
    epochs=20,
    batch_size=256,
    validation_split=0.1
)

# =========================
# SAVE
# =========================
model.save(os.path.join(AE_OUT, "autoencoder.h5"))
joblib.dump(scaler, os.path.join(AE_OUT, "ae_scaler.pkl"))

print("\nAutoencoder trained and saved")
