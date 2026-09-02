import pandas as pd

from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# Load dataset
df = pd.read_csv("data/CEAS_08.csv")


# Handle missing values
df["subject"] = df["subject"].fillna("")
df["body"] = df["body"].fillna("")


# Combine subject and body
df["email_text"] = (
    "Subject: " + df["subject"].astype(str)
    + "\n"
    + df["body"].astype(str)
)


# Input and target
X = df["email_text"]
y = df["label"]


# TF-IDF + Logistic Regression
pipeline = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_features=100000
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            random_state=42
        )
    )
])


# 5-fold stratified cross-validation
cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)


# Evaluate multiple metrics
scores = cross_validate(
    pipeline,
    X,
    y,
    cv=cv,
    scoring=["accuracy", "precision", "recall", "f1"],
    n_jobs=-1
)


print("\n--- 5-FOLD CROSS-VALIDATION ---")

print("\nAccuracy:")
print(scores["test_accuracy"])

print("\nPrecision:")
print(scores["test_precision"])

print("\nRecall:")
print(scores["test_recall"])

print("\nF1-score:")
print(scores["test_f1"])


print("\n--- AVERAGE SCORES ---")

print(
    "Mean Accuracy:",
    scores["test_accuracy"].mean()
)

print(
    "Mean Precision:",
    scores["test_precision"].mean()
)

print(
    "Mean Recall:",
    scores["test_recall"].mean()
)

print(
    "Mean F1-score:",
    scores["test_f1"].mean()
)