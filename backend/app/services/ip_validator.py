import ipaddress


def validate_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        return {
            "ip": ip,
            "valid": True,
            "version": ip_obj.version,
            "public": not ip_obj.is_private,
        }

    except ValueError:
        return {
            "ip": ip,
            "valid": False,
        }