import pandas as pd

# Load dataset
df = pd.read_csv("data/CEAS_08.csv")

# Replace missing subjects with empty text
df["subject"] = df["subject"].fillna("")

# Replace missing bodies with empty text
df["body"] = df["body"].fillna("")

# Combine subject and body
df["email_text"] = (
    "Subject: " + df["subject"].astype(str)
    + "\n"
    + df["body"].astype(str)
)

# Keep only the columns needed for our text classifier
df = df[["email_text", "label"]]

# Remove emails where there is no actual text
df = df[df["email_text"].str.strip().str.len() > 0]

# Reset row numbers
df = df.reset_index(drop=True)

# Display results
print("\n--- PREPARED DATASET ---")
print("Number of emails:", len(df))

print("\n--- COLUMNS ---")
print(df.columns.tolist())

print("\n--- LABEL DISTRIBUTION ---")
print(df["label"].value_counts())

print("\n--- SAMPLE EMAIL ---")
print(df.iloc[0]["email_text"])

print("\n--- SAMPLE LABEL ---")
print(df.iloc[0]["label"])