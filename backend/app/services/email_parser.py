from email import policy
from email.parser import BytesParser
import re

from app.services.ip_extractor import extract_ip_addresses

from app.services.ip_validator import validate_ip
from app.services.ip_geolocation import get_ip_location
from app.services.header_parser import parse_authentication_results
def parse_email(email_data: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(email_data)
    authentication = parse_authentication_results(msg)
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                body = part.get_content()
                break
    else:
        if msg.get_content_type() == "text/plain":
            body = msg.get_content()

    links = re.findall(r'https?://[^\s<>"\']+', body)

    received_headers = msg.get_all("Received", [])

    ip_addresses = extract_ip_addresses(received_headers)
    validated_ips = []

    for ip in ip_addresses:
        validated_ips.append(validate_ip(ip))
    attachments = []
    ip_locations = []

    for ip in ip_addresses:
        validation = validate_ip(ip)
        location = get_ip_location(ip)

        ip_locations.append({
            "validation": validation,
            "location": location
        })

    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "filename": part.get_filename(),
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b"")
            })

    return {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path"),
        "body": body,
        "links": links,
        "attachments": attachments,
        "ip_addresses": ip_addresses,
        "received_headers": received_headers,
        "validated_ips": validated_ips,
        "ip_locations": ip_locations,
        "authentication": authentication,
    }