import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

# Load dataset
df = pd.read_csv("data/CEAS_08.csv")

# Handle missing values
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

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Create TF-IDF vectorizer
vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    min_df=2,
    max_features=100000
)

# Learn vocabulary ONLY from training data
X_train_tfidf = vectorizer.fit_transform(X_train)

# Transform test data using the same vocabulary
X_test_tfidf = vectorizer.transform(X_test)

print("\n--- TF-IDF RESULTS ---")
print("Training emails:", X_train.shape[0])
print("Testing emails:", X_test.shape[0])

print("\nTraining TF-IDF shape:", X_train_tfidf.shape)
print("Testing TF-IDF shape:", X_test_tfidf.shape)

print("\nNumber of vocabulary features:", len(vectorizer.vocabulary_))

print("\n--- SAMPLE FEATURES ---")
print(vectorizer.get_feature_names_out()[:20])