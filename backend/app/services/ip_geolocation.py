import requests


def get_ip_location(ip: str):
    url = f"https://ipapi.co/{ip}/json/"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        data = response.json()

        return {
            "ip": ip,
            "country": data.get("country_name"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude")
        }

    except requests.RequestException:
        return {
            "ip": ip,
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None
        }