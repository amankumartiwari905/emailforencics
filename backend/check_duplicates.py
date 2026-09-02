import pandas as pd

df = pd.read_csv("data/CEAS_08.csv")

df["subject"] = df["subject"].fillna("")
df["body"] = df["body"].fillna("")

df["email_text"] = (
    "Subject: " + df["subject"].astype(str)
    + "\n"
    + df["body"].astype(str)
)

print("--- DUPLICATE CHECK ---")

print("Total emails:", len(df))

print("Exact duplicate emails:", df["email_text"].duplicated().sum())

print("Unique emails:", df["email_text"].nunique())