
"""
Router management module.

Uses detected network information to identify the
currently connected network.

Selective device blocking is disabled until
router compatibility and management support are verified.
"""


def get_blocking_capability(network=None):
    """
    Return device-blocking capabilities based on
    the currently detected network information.
    """

    network = network or {}

    ssid = network.get("ssid", "Unavailable")
    gateway = network.get("gateway", "Unavailable")

    return {
        "supported": False,
        "router_type": "Not Verified",
        "network_name": ssid,
        "gateway": gateway,
        "method": None,
        "can_block": False,
        "can_unblock": False,
        "message": (
            "Router compatibility has not been verified. "
            "Selective device blocking is currently unavailable."
        )
    }


def block_device(ip_address, mac_address):
    """
    Block a device through the router.

    This operation is unavailable until a supported
    router management interface is implemented.
    """

    return {
        "success": False,
        "action": "block",
        "ip_address": ip_address,
        "mac_address": mac_address,
        "message": (
            "Device blocking is unavailable because "
            "router compatibility has not been verified."
        )
    }


def unblock_device(ip_address, mac_address):
    """
    Unblock a device through the router.

    This operation is unavailable until a supported
    router management interface is implemented.
    """

    return {
        "success": False,
        "action": "unblock",
        "ip_address": ip_address,
        "mac_address": mac_address,
        "message": (
            "Device unblocking is unavailable because "
            "router compatibility has not been verified."
        )
    }
