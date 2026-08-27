from app.services.email_parser import parse_email


def test_parse_email():
    email_data = b"""From: attacker@example.com
To: victim@example.com
Subject: Test Email
Date: Wed, 26 Aug 2026 10:00:00 +0000
Reply-To: reply@example.com
Return-Path: bounce@example.com

Hello, this is a test email.
"""

    result = parse_email(email_data)

    assert result["from"] == "attacker@example.com"
    assert result["to"] == "victim@example.com"
    assert result["subject"] == "Test Email"
    assert result["reply_to"] == "reply@example.com"