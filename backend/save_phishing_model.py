import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# -----------------------------------
# 1. Load dataset
# -----------------------------------

df = pd.read_csv("data/CEAS_08.csv")


# -----------------------------------
# 2. Handle missing values
# -----------------------------------

df["subject"] = df["subject"].fillna("")
df["body"] = df["body"].fillna("")


# -----------------------------------
# 3. Combine subject + body
# -----------------------------------

df["email_text"] = (
    "Subject: " + df["subject"].astype(str)
    + "\n"
    + df["body"].astype(str)
)


# -----------------------------------
# 4. Input and target
# -----------------------------------

X = df["email_text"]
y = df["label"]


# -----------------------------------
# 5. Train/test split
# -----------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# -----------------------------------
# 6. Create TF-IDF vectorizer
# -----------------------------------

vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    min_df=2,
    max_features=100000
)


# Learn vocabulary from training data
X_train_tfidf = vectorizer.fit_transform(X_train)


# -----------------------------------
# 7. Train Logistic Regression
# -----------------------------------

model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

model.fit(X_train_tfidf, y_train)


# -----------------------------------
# 8. Create models directory
# -----------------------------------

os.makedirs("models", exist_ok=True)


# -----------------------------------
# 9. Save TF-IDF vectorizer
# -----------------------------------

joblib.dump(
    vectorizer,
    "models/phishing_tfidf.pkl"
)


# -----------------------------------
# 10. Save ML model
# -----------------------------------

joblib.dump(
    model,
    "models/phishing_model.pkl"
)


# -----------------------------------
# 11. Display result
# -----------------------------------

print("\n--- MODEL SAVED SUCCESSFULLY ---")

print("Vectorizer:")
print("models/phishing_tfidf.pkl")

print("\nPhishing classifier:")
print("models/phishing_model.pkl")

print("\nTraining emails:", len(X_train))
print("Testing emails:", len(X_test))

print("\nModel is ready for prediction.")