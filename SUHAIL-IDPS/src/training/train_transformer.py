import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split

# =========================
# LOAD SEQUENCE DATA
# =========================
df = pd.read_csv("transformer_sequences.csv")

y = df["label"].values
X = df.drop("label", axis=1).values

# =========================
# RESHAPE BACK TO SEQUENCES
# =========================
SEQ_LEN = 50
FEATURES = 13

X = X.reshape(-1, SEQ_LEN, FEATURES)

# =========================
# TRAIN TEST SPLIT
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# =========================
# TRANSFORMER BLOCK
# =========================
def transformer_encoder(inputs, head_size=64, num_heads=4, ff_dim=128):
    x = tf.keras.layers.MultiHeadAttention(
        key_dim=head_size,
        num_heads=num_heads
    )(inputs, inputs)

    x = tf.keras.layers.Add()([x, inputs])
    x = tf.keras.layers.LayerNormalization()(x)

    ff = tf.keras.layers.Dense(ff_dim, activation="relu")(x)
    ff = tf.keras.layers.Dense(inputs.shape[-1])(ff)

    x = tf.keras.layers.Add()([x, ff])
    x = tf.keras.layers.LayerNormalization()(x)

    return x

# =========================
# MODEL
# =========================
inputs = tf.keras.Input(shape=(SEQ_LEN, FEATURES))

x = transformer_encoder(inputs)
x = tf.keras.layers.GlobalAveragePooling1D()(x)
x = tf.keras.layers.Dense(64, activation="relu")(x)
x = tf.keras.layers.Dropout(0.3)(x)
outputs = tf.keras.layers.Dense(1, activation="sigmoid")(x)

model = tf.keras.Model(inputs, outputs)

model.compile(
    optimizer="adam",
    loss="binary_crossentropy",
    metrics=["accuracy"]
)

# =========================
# TRAIN
# =========================
model.fit(
    X_train, y_train,
    validation_data=(X_test, y_test),
    epochs=15,
    batch_size=64
)

# =========================
# SAVE
# =========================
model.save("transformer_model.h5")

print("\nTransformer model saved")
