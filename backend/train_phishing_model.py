import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


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


# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# TF-IDF
vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    min_df=2,
    max_features=100000
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)


# Train Logistic Regression
model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

model.fit(X_train_tfidf, y_train)


# Make predictions
y_pred = model.predict(X_test_tfidf)


# Evaluate model
accuracy = accuracy_score(y_test, y_pred)

print("\n--- MODEL RESULTS ---")
print("Accuracy:", accuracy)

print("\n--- CLASSIFICATION REPORT ---")
print(classification_report(
    y_test,
    y_pred,
    target_names=["Legitimate", "Phishing"]
))

print("\n--- CONFUSION MATRIX ---")
print(confusion_matrix(y_test, y_pred))