import ipaddress
import os

import requests
from dotenv import load_dotenv

load_dotenv()

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


def get_ip_location(ip: str):
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Private IP
        if ip_obj.is_private:
            return {
                "ip": ip,
                "country": None,
                "country_code": None,
                "continent": None,
                "continent_code": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "asn": None,
                "as_name": None,
                "as_domain": None,
                "status": "private_ip",
            }

        # IPinfo Lite lookup
        url = f"https://api.ipinfo.io/lite/{ip}"

        response = requests.get(
            url,
            params={"token": IPINFO_TOKEN},
            timeout=10,
        )

        response.raise_for_status()

        data = response.json()

        return {
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "continent": data.get("continent"),
            "continent_code": data.get("continent_code"),
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": data.get("asn"),
            "as_name": data.get("as_name"),
            "as_domain": data.get("as_domain"),
            "status": "public_ip",
        }

    except ValueError:
        return {
            "ip": ip,
            "status": "invalid_ip",
        }

    except requests.RequestException as e:
        return {
            "ip": ip,
            "status": "lookup_error",
            "reason": str(e),
        }