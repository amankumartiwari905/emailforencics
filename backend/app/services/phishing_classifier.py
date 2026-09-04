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
# LOAD TF-IDF VECTORIZER
# ==========================================

print("\n==========================================")
print("Loading ML phishing detection system...")
print("==========================================")

vectorizer_start = time.perf_counter()

vectorizer = joblib.load(
    VECTORIZER_PATH
)

vectorizer_load_time = (
    time.perf_counter() - vectorizer_start
)

print(
    f"TF-IDF vectorizer loaded in: "
    f"{vectorizer_load_time:.2f} seconds"
)


# ==========================================
# LOAD PHISHING MODEL
# ==========================================

model_start = time.perf_counter()

model = joblib.load(
    MODEL_PATH
)

model_load_time = (
    time.perf_counter() - model_start
)

print(
    f"Phishing model loaded in: "
    f"{model_load_time:.2f} seconds"
)


# ==========================================
# TOTAL LOAD TIME
# ==========================================

total_load_time = (
    vectorizer_load_time
    + model_load_time
)

print(
    f"Total ML loading time: "
    f"{total_load_time:.2f} seconds"
)

print("ML phishing detection system ready.")
print("==========================================\n")


# ==========================================
# EMAIL CLASSIFICATION
# ==========================================

def classify_email(
    subject: str,
    body: str
) -> dict:
    """
    Classify an email as phishing or legitimate.

    Parameters:
        subject:
            Email subject.

        body:
            Email body.

    Returns:
        prediction:
            "phishing" or "legitimate"

        phishing_probability:
            Probability predicted by the ML model.
    """

    # --------------------------------------
    # HANDLE MISSING VALUES
    # --------------------------------------

    subject = subject or ""
    body = body or ""


    # --------------------------------------
    # COMBINE SUBJECT + BODY
    # --------------------------------------

    # This format MUST remain the same
    # as the format used during training.

    email_text = (
        "Subject: "
        + str(subject)
        + "\n"
        + str(body)
    )


    # --------------------------------------
    # CONVERT TEXT TO TF-IDF
    # --------------------------------------

    email_tfidf = vectorizer.transform(
        [email_text]
    )


    # --------------------------------------
    # MAKE PREDICTION
    # --------------------------------------

    prediction = model.predict(
        email_tfidf
    )[0]


    # --------------------------------------
    # GET MODEL PROBABILITIES
    # --------------------------------------

    probabilities = model.predict_proba(
        email_tfidf
    )[0]


    # --------------------------------------
    # PHISHING PROBABILITY
    # --------------------------------------

    # Class 1 = Phishing

    phishing_probability = float(
        probabilities[1]
    )


    # --------------------------------------
    # RETURN RESULT
    # --------------------------------------

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