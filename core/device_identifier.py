
import socket
import urllib.request
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor


COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    5555: "Android ADB",
    8000: "HTTP service",
    8080: "Alternative HTTP service",
    8554: "RTSP alternative",
    3389: "Remote Desktop",
    62078: "Apple device service"
}


@lru_cache(maxsize=256)
def get_mac_vendor(mac_address):
    """Retrieve and cache manufacturer information."""

    try:
        url = f"https://api.macvendors.com/{mac_address}"

        request = urllib.request.Request(
            url,
            headers={"User-Agent": "NetworkSecurityScanner"}
        )

        with urllib.request.urlopen(request, timeout=1) as response:
            return response.read().decode("utf-8").strip()

    except Exception:
        return "Unknown"


def get_hostname(ip_address):
    """Retrieve the hostname of a device."""

    try:
        return socket.gethostbyaddr(ip_address)[0]

    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


def check_port(ip_address, port):
    """Check whether a TCP port is accessible."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(0.3)

            if sock.connect_ex((ip_address, port)) == 0:
                return port

    except OSError:
        pass

    return None


def scan_common_ports(ip_address):
    """Check common TCP ports concurrently."""

    with ThreadPoolExecutor(max_workers=13) as executor:

        results = executor.map(
            lambda port: check_port(ip_address, port),
            COMMON_PORTS
        )

    return [
        port for port in results
        if port is not None
    ]


def identify_device(mac_address, ip_address, gateway):
    """Estimate device type using network observations."""

    vendor = get_mac_vendor(mac_address)
    hostname = get_hostname(ip_address)
    open_ports = scan_common_ports(ip_address)

    vendor_lower = vendor.lower()
    hostname_lower = hostname.lower()

    device_type = "Unknown Device"
    confidence = "Low"
    indicators = []

    if ip_address == gateway:

        device_type = "Router / Gateway"
        confidence = "High"
        indicators.append("Matches the detected default gateway")

    elif "apple" in vendor_lower:

        device_type = "Possible Apple Device"
        confidence = "Medium"
        indicators.append("MAC manufacturer identifies Apple")

    elif any(name in vendor_lower for name in [
        "samsung", "xiaomi", "oppo", "vivo",
        "oneplus", "motorola", "realme", "google"
    ]):

        device_type = "Possible Android Device"
        confidence = "Medium"
        indicators.append(
            "Manufacturer is associated with Android devices"
        )

    elif (
        any(name in hostname_lower for name in [
            "desktop-", "laptop-", "win-"
        ])
        or 3389 in open_ports
        or 445 in open_ports
    ):

        device_type = "Possible Windows Device"
        confidence = "Low"
        indicators.append(
            "Hostname or network services suggest Windows"
        )

    elif 22 in open_ports:

        device_type = "Possible Linux / Server Device"
        confidence = "Low"
        indicators.append("SSH service is accessible")

    if not indicators:

        indicators.append(
            "Insufficient information for reliable classification"
        )

    return {
        "vendor": vendor,
        "hostname": hostname,
        "device_type": device_type,
        "confidence": confidence,
        "indicators": indicators,
        "open_ports": open_ports
    }
