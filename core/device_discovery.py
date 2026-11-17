
from scapy.all import ARP, Ether, srp


def discover_devices(network_range):
    """
    Discover active devices on the specified local network.
    Returns each device's IP and MAC address.
    """

    devices = []

    try:
        arp_request = ARP(pdst=network_range)

        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

        packet = broadcast / arp_request

        answered = srp(
            packet,
            timeout=1,
            retry=0,
            verbose=False
        )[0]

        for sent, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })

    except Exception as error:
        return {
            "error": str(error)
        }

    return devices
