from app.services.phishing_classifier import classify_email


# Test phishing email
result1 = classify_email(
    "Urgent: Verify your account",
    """
    Your account will be suspended unless you verify
    your information immediately. Click the link below
    to confirm your account.
    """
)

print("\n--- TEST 1 ---")
print(result1)


# Test legitimate email
result2 = classify_email(
    "Team meeting tomorrow",
    """
    Hi everyone,

    Just a reminder that our team meeting is scheduled
    for tomorrow at 10 AM. Please bring your project updates.

    Thanks.
    """
)

print("\n--- TEST 2 ---")
print(result2)