# advanced_data_check.py

import pandas as pd
import numpy as np

df1 = pd.read_csv("attack_processed.csv")
df2 = pd.read_csv("normal_processed.csv")

df = pd.concat([df1, df2])

print("Total Records:", len(df))

print("\nMissing Values %")
print((df.isnull().sum()/len(df))*100)

print("\nDuplicate Rows")
print(df.duplicated().sum())

print("\nConstant Columns")
for col in df.columns:
    if df[col].nunique() == 1:
        print(col)

print("\nHighly Correlated Columns")

corr = df.select_dtypes(include=np.number).corr()

for i in corr.columns:
    for j in corr.columns:
        if i != j:
            if abs(corr.loc[i,j]) > 0.95:
                print(i, "<->", j,
                      "=", round(corr.loc[i,j],3))
