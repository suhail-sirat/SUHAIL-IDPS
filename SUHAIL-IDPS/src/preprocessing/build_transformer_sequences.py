import pandas as pd
import numpy as np

# =========================
# CONFIG
# =========================
ATTACK_FILE = "attack_processed.csv"
NORMAL_FILE = "normal_processed.csv"

SEQ_LEN = 50        # packets per sequence
STRIDE = 10         # sliding window step

OUTPUT_FILE = "transformer_sequences.csv"

# =========================
# LOAD DATA
# =========================
attack_df = pd.read_csv(ATTACK_FILE)
normal_df = pd.read_csv(NORMAL_FILE)

# =========================
# CLEAN FUNCTION
# =========================
def clean_df(df):
    df = df.fillna(0)

    # convert tcp.flags if needed
    if "tcp.flags" in df.columns and df["tcp.flags"].dtype == "object":
        df["tcp.flags"] = df["tcp.flags"].apply(
            lambda x: int(str(x), 16) if str(x).startswith("0x") else 0
        )

    # ensure numeric
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

    return df

attack_df = clean_df(attack_df)
normal_df = clean_df(normal_df)

# =========================
# SPLIT FEATURES / LABELS
# =========================
attack_X = attack_df.drop(columns=["label"]).values
attack_y = attack_df["label"].values

normal_X = normal_df.drop(columns=["label"]).values
normal_y = normal_df["label"].values

# =========================
# BUILD SEQUENCES FUNCTION
# =========================
def create_sequences(X, y, seq_len, stride):
    X_seq = []
    y_seq = []

    for start in range(0, len(X) - seq_len, stride):
        end = start + seq_len

        window = X[start:end]
        labels = y[start:end]

        # sequence label logic
        # if ANY attack in window → attack sequence
        seq_label = 1 if np.any(labels == 1) else 0

        X_seq.append(window)
        y_seq.append(seq_label)

    return np.array(X_seq), np.array(y_seq)

# =========================
# CREATE SEQUENCES
# =========================
X_attack_seq, y_attack_seq = create_sequences(
    attack_X, attack_y, SEQ_LEN, STRIDE
)

X_normal_seq, y_normal_seq = create_sequences(
    normal_X, normal_y, SEQ_LEN, STRIDE
)

# =========================
# COMBINE DATASETS
# =========================
X = np.concatenate([X_attack_seq, X_normal_seq], axis=0)
y = np.concatenate([y_attack_seq, y_normal_seq], axis=0)

# =========================
# SHUFFLE DATA
# =========================
indices = np.arange(len(X))
np.random.shuffle(indices)

X = X[indices]
y = y[indices]

# =========================
# SAVE OPTION 1: FLATTENED CSV (simple use)
# =========================
flat_data = X.reshape(X.shape[0], -1)

df_out = pd.DataFrame(flat_data)
df_out["label"] = y

df_out.to_csv(OUTPUT_FILE, index=False)

# =========================
# STATS
# =========================
print("\n=== TRANSFORMER DATASET READY ===")
print("Attack sequences:", len(X_attack_seq))
print("Normal sequences:", len(X_normal_seq))
print("Total sequences:", len(X))
print("Attack ratio:", np.mean(y))
print("Saved file:", OUTPUT_FILE)
print("Sequence shape:", X.shape)
