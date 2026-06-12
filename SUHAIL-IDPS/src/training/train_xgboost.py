import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix

# =========================
# LOAD DATA
# =========================
df = pd.read_csv("attack_processed.csv")
df2 = pd.read_csv("normal_processed.csv")

df = pd.concat([df, df2], ignore_index=True)

# =========================
# CLEAN
# =========================
df = df.fillna(0)

if df["tcp.flags"].dtype == "object":
    df["tcp.flags"] = df["tcp.flags"].apply(
        lambda x: int(str(x), 16) if str(x).startswith("0x") else 0
    )

df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

X = df.drop("label", axis=1)
y = df["label"]

# =========================
# SPLIT
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# =========================
# SCALE
# =========================
scaler = MinMaxScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# =========================
# MODEL
# =========================
model = XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="logloss"
)

model.fit(X_train, y_train)

# =========================
# EVALUATION
# =========================
pred = model.predict(X_test)

print("\nCONFUSION MATRIX")
print(confusion_matrix(y_test, pred))

print("\nCLASSIFICATION REPORT")
print(classification_report(y_test, pred))

# =========================
# SAVE
# =========================
joblib.dump(model, "xgb_model.pkl")
joblib.dump(scaler, "xgb_scaler.pkl")
joblib.dump(list(X.columns), "xgb_features.pkl")

print("\nXGBoost model saved")
