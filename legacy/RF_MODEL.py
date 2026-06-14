import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib

file_attack = '/home/maihan/Desktop/live_traffic_project/attack_processed.csv'
file_normal = '/home/maihan/Desktop/live_traffic_project/normal_processed.csv'

df_attack = pd.read_csv(file_attack)
df_normal = pd.read_csv(file_normal)
df = pd.concat([df_attack, df_normal], ignore_index=True)

if 'tcp.flags' in df.columns:
    df['tcp.flags'] = df['tcp.flags'].fillna('0x0')
    df['tcp.flags'] = df['tcp.flags'].apply(
        lambda x: int(str(x), 16) if str(x).startswith('0x') else int(x)
    )

if 'mqtt.msgtype' in df.columns:
    df['mqtt.msgtype'] = df['mqtt.msgtype'].fillna(0)

for col in df.columns:
    if df[col].dtype == 'object':
        df[col] = df[col].astype(str).str.replace(',', '.').astype(float)

X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

for col in X_train.columns:
    if X_train[col].dtype == 'object':
        train_mode = X_train[col].mode()[0]
        X_train[col] = X_train[col].fillna(train_mode)
        X_test[col] = X_test[col].fillna(train_mode)
    else:
        train_mean = X_train[col].mean()
        X_train[col] = X_train[col].fillna(train_mean)
        X_test[col] = X_test[col].fillna(train_mean)

scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

le = LabelEncoder()
y_train_enc = le.fit_transform(y_train)
y_test_enc = le.transform(y_test)

model_rf = RandomForestClassifier(n_estimators=100, random_state=42)
model_rf.fit(X_train_scaled, y_train_enc)

y_pred = model_rf.predict(X_test_scaled)

print('confusion matrix', confusion_matrix(y_test_enc, y_pred))
print('\nclassification report', classification_report(y_test_enc, y_pred))

joblib.dump(model_rf, '/home/maihan/Desktop/live_traffic_project/random_forest_model.pkl')
joblib.dump(scaler, '/home/maihan/Desktop/live_traffic_project/scaler_rf.pkl')
joblib.dump(list(X.columns), '/home/maihan/Desktop/live_traffic_project/feature_list_rf.pkl')

print("Training finished.")