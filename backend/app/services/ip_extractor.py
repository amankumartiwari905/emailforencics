import re


def extract_ip_addresses(headers):
    ip_addresses = []

    for header in headers:
        matches = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            header
        )

        for ip in matches:
            if ip not in ip_addresses:
                ip_addresses.append(ip)

    return ip_addresses