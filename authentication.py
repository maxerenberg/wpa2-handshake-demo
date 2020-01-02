import logging
from scapy.packet import Packet
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Auth
from scapy.sendrecv import srp1


def request(bssid: str, sta: str, iface: str, timeout=3) -> Packet:
    """
    Sends an authentication request and returns an authentication response.

    :param bssid: BSSID of the BSS to authenticate to
    :param sta: MAC address of the station sending the request
    :param iface: name of the network interface to listen on
                  (must be in monitor mode)
    :param timeout: timeout for listening to frames
    """
    dot11 = Dot11(
        type='Management',
        subtype=11,
        addr1=bssid,
        addr2=sta,
        addr3=bssid
    )
    auth = Dot11Auth(
        algo='open',
        seqnum=1,
        status='success'
    )
    frame = RadioTap() / dot11 / auth
    logging.info(f'Authenticating to {bssid}:')
    logging.info(repr(frame))
    return srp1(frame, iface=iface, timeout=timeout)