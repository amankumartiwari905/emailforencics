import os
import time
import joblib


# ==========================================
# BASE DIRECTORY
# ==========================================

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)


# ==========================================
# MODEL PATHS
# ==========================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_tfidf.pkl"
)


# ==========================================
# LOAD MODEL + VECTORIZER
# ==========================================

_start_time = time.perf_counter()

vectorizer = joblib.load(
    VECTORIZER_PATH
)

model = joblib.load(
    MODEL_PATH
)

_load_time = time.perf_counter() - _start_time

print(
    f"ML model loading time: {_load_time:.2f} seconds"
)


# ==========================================
# EMAIL CLASSIFICATION
# ==========================================

def classify_email(
    subject: str,
    body: str
) -> dict:
    """
    Classify an email as phishing or legitimate.

    Returns:
        prediction:
            "phishing" or "legitimate"

        phishing_probability:
            Probability predicted by the ML model.
    """

    # Handle missing values
    subject = subject or ""
    body = body or ""

    # Combine subject and body
    # using the same format used during training
    email_text = (
        "Subject: "
        + str(subject)
        + "\n"
        + str(body)
    )

    # Convert email text into TF-IDF features
    email_tfidf = vectorizer.transform(
        [email_text]
    )

    # Make prediction
    prediction = model.predict(
        email_tfidf
    )[0]

    # Get probabilities
    probabilities = model.predict_proba(
        email_tfidf
    )[0]

    # Class 1 = phishing
    phishing_probability = float(
        probabilities[1]
    )

    return {
        "prediction": (
            "phishing"
            if prediction == 1
            else "legitimate"
        ),
        "phishing_probability": round(
            phishing_probability,
            4
        )
    }