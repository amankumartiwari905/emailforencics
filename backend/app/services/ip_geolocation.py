import ipaddress
import requests


def get_ip_location(ip: str):

    try:
        ip_obj = ipaddress.ip_address(ip)

        # Private IP
        if ip_obj.is_private:
            return {
                "ip": ip,
                "country": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "asn": None,
                "organization": None,
                "status": "private_ip"
            }

        # Real IP geolocation lookup
        url = f"https://ipapi.co/{ip}/json/"

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "EmailThreatDetection/1.0"
            }
        )

        response.raise_for_status()

        data = response.json()

        # ipapi can return HTTP 200 with an error object
        if data.get("error"):
            return {
                "ip": ip,
                "country": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "asn": None,
                "organization": None,
                "status": "lookup_failed",
                "reason": data.get("reason")
            }

        return {
            "ip": ip,
            "country": data.get("country_name"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "asn": data.get("asn"),
            "organization": data.get("org"),
            "status": "public_ip"
        }

    except ValueError:
        return {
            "ip": ip,
            "status": "invalid_ip"
        }

    except requests.RequestException as e:
        return {
            "ip": ip,
            "status": "lookup_error",
            "reason": str(e)
        }