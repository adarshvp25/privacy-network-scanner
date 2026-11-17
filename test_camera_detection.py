
from unittest.mock import patch

from core.device_identifier import identify_device


test_cases = [
    {
        "name": "Camera with RTSP port 554",
        "hostname": "Unknown",
        "vendor": "Unknown",
        "ports": [554]
    },
    {
        "name": "Camera with RTSP port 8554",
        "hostname": "Unknown",
        "vendor": "Unknown",
        "ports": [8554]
    },
    {
        "name": "Camera identified by hostname",
        "hostname": "IPCAM-01",
        "vendor": "Unknown",
        "ports": []
    },
    {
        "name": "Camera identified by manufacturer",
        "hostname": "Unknown",
        "vendor": "Hikvision",
        "ports": []
    },
    {
        "name": "Ordinary unknown device",
        "hostname": "Unknown",
        "vendor": "Unknown",
        "ports": []
    }
]


for test in test_cases:

    with (
        patch(
            "core.device_identifier.get_mac_vendor",
            return_value=test["vendor"]
        ),
        patch(
            "core.device_identifier.get_hostname",
            return_value=test["hostname"]
        ),
        patch(
            "core.device_identifier.scan_common_ports",
            return_value=test["ports"]
        )
    ):

        result = identify_device(
            "00:11:22:33:44:55",
            "192.168.1.100",
            "192.168.1.1"
        )

    print("\nTest:", test["name"])
    print("Detected Type:", result["device_type"])
    print("Confidence:", result["confidence"])
    print("Indicators:", result["indicators"])
