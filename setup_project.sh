#!/bin/bash

echo "Creating SUHAIL-IDPS structure..."

mkdir -p SUHAIL-IDPS/data/raw
mkdir -p SUHAIL-IDPS/data/sequences

mkdir -p SUHAIL-IDPS/models/xgboost
mkdir -p SUHAIL-IDPS/models/autoencoder
mkdir -p SUHAIL-IDPS/models/transformer

mkdir -p SUHAIL-IDPS/src/training
mkdir -p SUHAIL-IDPS/src/preprocessing
mkdir -p SUHAIL-IDPS/src/core
mkdir -p SUHAIL-IDPS/src/live_ids

mkdir -p SUHAIL-IDPS/dashboard/backend
mkdir -p SUHAIL-IDPS/dashboard/frontend

mkdir -p SUHAIL-IDPS/logs

echo "Moving existing files..."

# data
mv attack_processed.csv SUHAIL-IDPS/data/raw/
mv normal_processed.csv SUHAIL-IDPS/data/raw/
mv transformer_sequences.csv SUHAIL-IDPS/data/sequences/

# models
mv xgb_model.pkl SUHAIL-IDPS/models/xgboost/
mv xgb_scaler.pkl SUHAIL-IDPS/models/xgboost/
mv xgb_features.pkl SUHAIL-IDPS/models/xgboost/

mv autoencoder.h5 SUHAIL-IDPS/models/autoencoder/
mv ae_scaler.pkl SUHAIL-IDPS/models/autoencoder/

mv transformer_model.h5 SUHAIL-IDPS/models/transformer/

# scripts
mv train_xgboost.py SUHAIL-IDPS/src/training/
mv train_autoencoder.py SUHAIL-IDPS/src/training/
mv train_transformer.py SUHAIL-IDPS/src/training/

mv build_transformer_sequences.py SUHAIL-IDPS/src/preprocessing/
mv verify_data.py SUHAIL-IDPS/src/preprocessing/
mv advanced_data_check.py SUHAIL-IDPS/src/preprocessing/

mv decision_engine.py SUHAIL-IDPS/src/core/

# dashboard
mv app.py SUHAIL-IDPS/dashboard/backend/ 2>/dev/null

echo "DONE ✔ Project structured successfully"
