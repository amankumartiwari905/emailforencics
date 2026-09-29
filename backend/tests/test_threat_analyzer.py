from app.services.threat_analyzer import _num, analyze_threat


def test_num_coerces_numeric_strings():
    assert _num("42.5") == 42.5
    assert _num("  8 ") == 8.0
    assert _num("") == 0.0


def test_analyze_threat_handles_string_booleans_and_numbers():
    result = analyze_threat({
        "from": "sender@example.com",
        "reply_to": "noreply@evil-example.com",
        "url_analysis": [{"suspicious": "true", "url": "https://paypaI-login.example.com"}],
        "nlp_analysis": {
            "threat_score": "0.9",
            "tactics": ["urgent action required"],
            "pattern_layer": {"matched_categories": ["financial_fraud"]},
            "nlp_signal_tier": "phishing",
        },
        "attachment_analysis": [{"filename": "invoice.pdf", "risk_score": "60", "reasons": ["malware"]}],
        "domain_intelligence": {"example.com": {"risk": {"risk_score": "80"}}},
        "lookalike_analysis": [{"reason": "Lookalike domain detected"}],
        "ip_intelligence": [{"ip": "8.8.8.8", "risk_score": "15", "proxy": "true"}],
    })

    assert result["fraud_score"] > 0
    assert result["classification"] in {"SUSPICIOUS", "HIGH", "CRITICAL"}
