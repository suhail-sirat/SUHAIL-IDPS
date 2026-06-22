# data_quality_check.py

import pandas as pd

files = [
    "attack_processed.csv",
    "normal_processed.csv"
]

for file in files:

    print("\n" + "="*60)
    print("FILE:", file)
    print("="*60)

    df = pd.read_csv(file)

    print("\nRows:", df.shape[0])
    print("Columns:", df.shape[1])

    print("\nColumn Names:")
    print(df.columns.tolist())

    print("\nData Types:")
    print(df.dtypes)

    print("\nMissing Values:")
    print(df.isnull().sum())

    print("\nDuplicate Rows:")
    print(df.duplicated().sum())

    print("\nBasic Statistics:")
    print(df.describe(include='all'))

    print("\nUnique Values Per Column:")
    for col in df.columns:
        print(f"{col}: {df[col].nunique()}")

    print("\nInfinite Values:")
    numeric = df.select_dtypes(include=['number'])

    inf_count = (
        numeric.isin([float('inf'), float('-inf')])
        .sum()
        .sum()
    )

    print("Infinity Count:", inf_count)

print("\nDataset Quality Check Finished")
