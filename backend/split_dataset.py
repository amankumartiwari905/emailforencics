import pandas as pd
from sklearn.model_selection import train_test_split

# Load the prepared dataset
df = pd.read_csv("data/CEAS_08.csv")

# Handle missing text
df["subject"] = df["subject"].fillna("")
df["body"] = df["body"].fillna("")

# Combine subject + body
df["email_text"] = (
    "Subject: " + df["subject"].astype(str)
    + "\n"
    + df["body"].astype(str)
)

# Input and target
X = df["email_text"]
y = df["label"]

# Split: 80% training, 20% testing
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\n--- DATA SPLIT ---")
print("Total emails:", len(df))
print("Training emails:", len(X_train))
print("Testing emails:", len(X_test))

print("\n--- TRAINING LABEL DISTRIBUTION ---")
print(y_train.value_counts())

print("\n--- TESTING LABEL DISTRIBUTION ---")
print(y_test.value_counts())