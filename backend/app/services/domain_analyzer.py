def extract_domain(email_address: str):
    if not email_address:
        return None

    if "@" not in email_address:
        return None

    return email_address.split("@")[-1].strip().lower()


def analyze_domains(email_data):
    sender = email_data.get("from")
    reply_to = email_data.get("reply_to")
    return_path = email_data.get("return_path")

    sender_domain = extract_domain(sender)
    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    reply_to_mismatch = False
    return_path_mismatch = False

    if sender_domain and reply_to_domain:
        reply_to_mismatch = sender_domain != reply_to_domain

    if sender_domain and return_path_domain:
        return_path_mismatch = sender_domain != return_path_domain

    return {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch
    }