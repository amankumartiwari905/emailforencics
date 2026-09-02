import joblib


# -----------------------------------
# 1. Load saved model and vectorizer
# -----------------------------------

vectorizer = joblib.load("models/phishing_tfidf.pkl")
model = joblib.load("models/phishing_model.pkl")


# -----------------------------------
# 2. Test emails
# -----------------------------------

test_emails = [
    {
        "subject": "Urgent: Verify your account",
        "body": """
        Your account will be suspended unless you verify your information
        immediately. Click the link below to confirm your account.
        """
    },
    {
        "subject": "Team meeting tomorrow",
        "body": """
        Hi everyone,

        Just a reminder that our team meeting is scheduled for tomorrow
        at 10 AM. Please bring your project updates.

        Thanks.
        """
    }
]


# -----------------------------------
# 3. Make predictions
# -----------------------------------

for i, email in enumerate(test_emails, start=1):

    email_text = (
        "Subject: " + email["subject"]
        + "\n"
        + email["body"]
    )

    # Convert email text to TF-IDF
    email_tfidf = vectorizer.transform([email_text])

    # Prediction
    prediction = model.predict(email_tfidf)[0]

    # Probability
    probabilities = model.predict_proba(email_tfidf)[0]

    phishing_probability = probabilities[1]

    print("\n------------------------------")
    print("EMAIL", i)
    print("------------------------------")

    print("Prediction:", "PHISHING" if prediction == 1 else "LEGITIMATE")

    print(
        "Phishing probability:",
        round(phishing_probability * 100, 2),
        "%"
    )