import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler
import joblib

# =========================
# LOAD NORMAL DATA ONLY
# =========================
df = pd.read_csv("normal_processed.csv")
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
model.save("autoencoder.h5")
joblib.dump(scaler, "ae_scaler.pkl")

print("\nAutoencoder trained and saved")
