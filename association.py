import logging
from scapy.packet import Packet
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11AssoReq, \
    Dot11Elt, Dot11EltRates, Dot11EltRSN, RSNCipherSuite, AKMSuite
from scapy.sendrecv import srp1


def get_elt(pkt: Packet, ID: int) -> Dot11Elt:
    """Returns the information element for a given ID"""
    layer = pkt.getlayer(Dot11Elt)
    while layer is not None and layer.ID != ID:
        layer = layer.getlayer(Dot11Elt, 2)
    return layer


def get_ssid(pkt: Packet) -> str:
    """Returns the SSID in a beacon frame."""
    ssid_elt = get_elt(pkt, 0)
    if ssid_elt is not None:
        return ssid_elt.info.decode()
    raise Exception('SSID not found in beacon frame')


def request(beacon_frame: Packet, sta: str, iface: str, timeout=3) -> Packet:
    """
    Sends an association request and returns an association response.

    :param beacon_frame: a beacon frame from the AP to which the association
                         request will be sent
    :param sta: MAC address of the station sending the request
    :param iface: name of the network interface (must be in monitor mode)
    :param timeout: timeout for waiting for a response
    """
    SSID = get_ssid(beacon_frame)
    bssid = beacon_frame.getlayer(Dot11).addr2
    capabilities = beacon_frame.getlayer(Dot11Beacon).cap
    dot11 = Dot11(
        type='Management',
        subtype=0,
        addr1=bssid,
        addr2=sta,
        addr3=bssid
    )
    assoc = Dot11AssoReq(
        cap=capabilities,
        listen_interval=20
    )
    ssid_elt = Dot11Elt(
        ID='SSID',
        len=len(SSID),
        info=SSID
    )
    rates = Dot11EltRates(
        ID=1,
        rates=beacon_frame.getlayer(Dot11EltRates).rates
    )
    es_rates = get_elt(beacon_frame, 50)
    if es_rates is not None:
        es_rates = Dot11Elt(
            ID='ESRates',
            info=es_rates.info
        )
    rsn = Dot11EltRSN(    
        ID=48,    
        len=20,    
        version=1,    
        group_cipher_suite=RSNCipherSuite(cipher='TKIP'),    
        nb_pairwise_cipher_suites=1,    
        pairwise_cipher_suites=RSNCipherSuite(cipher='CCMP'),    
        nb_akm_suites=1,    
        akm_suites=AKMSuite(suite='PSK')    
    )
    frame = RadioTap() / dot11 / assoc / ssid_elt / rates
    if es_rates is not None:
        frame /= es_rates
    frame /= rsn
    logging.info(f'Associating with {SSID}:')
    logging.info(repr(frame))
    return srp1(frame, iface=iface, timeout=timeout)