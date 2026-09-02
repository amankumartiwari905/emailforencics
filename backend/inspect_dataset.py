import pandas as pd

# Load dataset
df = pd.read_csv("data/CEAS_08.csv")

# Basic information
print("\n--- DATASET SHAPE ---")
print(df.shape)

print("\n--- COLUMNS ---")
print(df.columns.tolist())

print("\n--- FIRST 5 ROWS ---")
print(df.head())

print("\n--- MISSING VALUES ---")
print(df.isnull().sum())

print("\n--- LABEL DISTRIBUTION ---")
print(df["label"].value_counts())

print("\n--- LABEL PERCENTAGE ---")
print(df["label"].value_counts(normalize=True) * 100)