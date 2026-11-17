
import socket
import ipaddress
import subprocess
import re


def get_local_ip():
    """Detect the local IPv4 address."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]

    except OSError:
        return None

    finally:
        sock.close()


def get_wifi_ssid():
    """Detect the currently connected Wi-Fi network name on Windows."""

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5
        )

        for line in result.stdout.splitlines():

            # Match the connected Wi-Fi SSID.
            match = re.match(
                r"^\s*SSID\s*:\s*(.+?)\s*$",
                line
            )

            if match and match.group(1):
                return match.group(1)

    except Exception:
        pass

    return "Unavailable"


def get_network_details():
    """Retrieve local network configuration on Windows."""

    local_ip = get_local_ip()

    if not local_ip:
        return {
            "error": "Unable to detect local IP address"
        }

    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        output = result.stdout

        subnet_mask = None
        gateway = None

        # Locate the section containing the detected local IP.
        lines = output.splitlines()
        found_ip = False

        for index, line in enumerate(lines):

            if local_ip in line:
                found_ip = True

            if found_ip and "Subnet Mask" in line:

                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)",
                    line
                )

                if match:
                    subnet_mask = match.group(1)

            if found_ip and "Default Gateway" in line:

                for gateway_line in lines[index:index + 3]:

                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)",
                        gateway_line
                    )

                    if match:
                        gateway = match.group(1)
                        break

                break

        if not subnet_mask:
            return {
                "error": "Unable to detect subnet mask"
            }

        network = ipaddress.IPv4Network(
            f"{local_ip}/{subnet_mask}",
            strict=False
        )

        # Detect connected Wi-Fi network.
        ssid = get_wifi_ssid()

        return {
            "local_ip": local_ip,
            "subnet_mask": subnet_mask,
            "network": str(network),
            "gateway": gateway,
            "ssid": ssid
        }

    except Exception as error:

        return {
            "error": str(error)
        }
