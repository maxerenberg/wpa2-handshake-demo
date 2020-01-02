import functools
from scapy.packet import Packet
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
from scapy.sendrecv import sniff


def ssid_filter(ssid: str, pkt: Packet) -> bool:
    """
    Returns true if a pkt is a beacon frame for the given SSID,
    false otherwise.

    :param ssid: SSID of the wireless network
    :param pkt: raw 802.11 frame
    """
    if not pkt.haslayer(Dot11Beacon):
        return False
    layer = pkt.getlayer(Dot11Elt)
    while layer is not None and layer.ID != 0:
        layer = layer.getlayer(Dot11Elt, 2)
    if layer is not None:
        return layer.info.decode() == ssid
    return False


def capture(ssid: str, iface: str, timeout=3) -> Packet:
    """
    Returns a beacon frame for the given SSID, or None if no such
    frames were captured.

    :param ssid: SSID of the wireless network
    :param iface: name of the network interface to listen on
                  (must be in monitor mode)
    :param timeout: timeout for listening to frames
    """
    results = sniff(
        lfilter=functools.partial(ssid_filter, ssid),
        iface=iface,
        count=1,
        timeout=timeout
    )
    return None if len(results) == 0 else results[0]