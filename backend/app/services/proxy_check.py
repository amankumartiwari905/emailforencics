import os
import ipaddress
import requests
from dotenv import load_dotenv
load_dotenv()


def check_proxy(ip: str):
    """
    Check an IP address for VPN, proxy, TOR, hosting,
    and other network intelligence using ProxyCheck.io v3.
    """

    # Skip private/non-routable IPs -- ProxyCheck's API returns a
    # 400 Bad Request for these since there's nothing to look up.
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return {
                "ip": ip,
                "asn": None,
                "organization": None,
                "provider": None,
                "hostname": None,
                "connection_type": None,
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "postal_code": None,
                "latitude": None,
                "longitude": None,
                "vpn": None,
                "proxy": None,
                "tor": None,
                "hosting": None,
                "anonymous": None,
                "compromised": None,
                "scraper": None,
                "risk_score": None,
                "confidence": None,
                "status": "private_ip",
                "error": None
            }
    except ValueError:
        return {
            "ip": ip,
            "error": "invalid_ip"
        }

    api_key = os.getenv("PROXYCHECK_API_KEY")

    if not api_key:
        return {
            "ip": ip,
            "error": "PROXYCHECK_API_KEY is not configured"
        }

    url = f"https://proxycheck.io/v3/{ip}"

    params = {
        "key": api_key
    }

    try:
        response = requests.get(
            url,
            params=params,
            timeout=5
        )

        response.raise_for_status()

        data = response.json()

        result = data.get(ip, {})

        network = result.get("network", {})
        location = result.get("location", {})
        detections = result.get("detections", {})

        return {
            "ip": ip,

            # Network information
            "asn": network.get("asn"),
            "organization": network.get("organisation"),
            "provider": network.get("provider"),
            "hostname": network.get("hostname"),
            "connection_type": network.get("type"),

            # Location information
            "country": location.get("country_name"),
            "country_code": location.get("country_code"),
            "region": location.get("region_name"),
            "city": location.get("city_name"),
            "postal_code": location.get("postal_code"),
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),

            # VPN / Proxy / TOR detection
            "vpn": detections.get("vpn", False),
            "proxy": detections.get("proxy", False),
            "tor": detections.get("tor", False),
            "hosting": detections.get("hosting", False),
            "anonymous": detections.get("anonymous", False),
            "compromised": detections.get("compromised", False),
            "scraper": detections.get("scraper", False),

            # Risk information
            "risk_score": result.get("risk"),
            "confidence": result.get("confidence"),

            "status": "public_ip",
            "error": None
        }

    except requests.RequestException as e:
        return {
            "ip": ip,
            "error": f"ProxyCheck request failed: {str(e)}"
        }

    except ValueError:
        return {
            "ip": ip,
            "error": "Invalid JSON response from ProxyCheck"
        }