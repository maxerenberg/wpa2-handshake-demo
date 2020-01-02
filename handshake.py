import random
import hmac
import logging
from hashlib import pbkdf2_hmac
from scapy.packet import Packet, Raw
from scapy.compat import raw
from scapy.layers.dot11 import RadioTap, Dot11, Dot11EltRSN, RSNCipherSuite, \
    AKMSuite
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import LLC, SNAP
from scapy.sendrecv import sendp, AsyncSniffer

# For implementation details on the PRF512 function and the PTK calculation,
# refer to "IEEE Standard for Information Technology - Telecommunications
# and Information Exchange Between Systems - Local and Metropolitan Networks
# - Specific Requirements, Part 11: Wireless LAN Medium Access Control (MAC)
# and Physical Layer (PHY) Specifications"


def PRF512(K: bytes, A: bytes, B: bytes) -> bytes:
    """
    Implementation of PRF-512, as defined in IEEE Std 802.11-2007 Part 11,
    section 8.5.1.1. Returns a 512-bit value.

    :param K: key
    :param A: a unique label for each different purpose of the PRF
    :param B: binary input to the PRF
    """
    num_bytes = 64
    R = b''
    Y = b'\x00'
    for i in range((num_bytes * 8 + 159) // 160 + 1):
        R += hmac.new(K, A + Y + B + bytes([i]), 'sha1').digest()
    return R[:num_bytes]


def send_message_2(message_1: Packet, SSID: str,
        password: str, iface: str, timeout=3) -> Packet:
    """
    Sends Message 2 of the 4-way handshake for WPA2. Returns two values:
    Message 3 from the AP (or None if not received), and the KCK required 
    to calculate the MIC.

    :param message_1: message 1 of the 4-way handshake
    :param SSID: SSID of the network
    :param password: password (WPA2-PSK) for the network
    :param iface: network interface in monitor mode
    :param timeout: timeout for waiting for Message 3 from the AP
    """
    sta = message_1.getlayer(Dot11).addr1
    bssid = message_1.getlayer(Dot11).addr2
    # number of bytes to skip: key descriptor type (1) + key information (2) +
    # key length (2) = 5
    key_replay_counter = message_1.getlayer(Raw).load[5:5 + 8]
    AA = bytes.fromhex(bssid.replace(':', ''))
    SPA = bytes.fromhex(sta.replace(':', ''))
    # ANONCE follows the replay counter in the raw load, so 5 + 8 = 13
    ANONCE = message_1.getlayer(Raw).load[13:13 + 32]
    SNONCE = bytes([random.randrange(256) for i in range(32)])
    PMK = pbkdf2_hmac('sha1', password.encode(), SSID.encode(), 4096, 32)
    # see IEEE Std 802.11-2007 Part 11, section 8.5.1.2, for 
    # reference on PTK calculation
    PTK = PRF512(PMK, b'Pairwise key expansion', min(AA, SPA) + max(AA, SPA) +
        min(ANONCE, SNONCE) + max(ANONCE, SNONCE))
    KCK = PTK[:16]
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
    rsn_length = int.to_bytes(len(raw(rsn)), length=2, byteorder='big')
    eapol = EAPOL(
        version='802.1X-2004',
        type='EAPOL-Key'
    )
    eapol_data = Raw(load=b''.join([
        b'\x02',        # Key Descriptor Type: EAPOL RSN Key
        b'\x01\x0a',    # Key MIC: set, Key Type: Pairwise key,
                        #   Key Descriptor Version: AES HMAC-SHA1
        b'\x00\x10',    # Key Length: 16
        key_replay_counter,  # Replay Counter
        SNONCE,         # WPA Key Nonce
        b'\x00'*16,     # Key IV
        b'\x00'*8,      # WPA Key RSC
        b'\x00'*8,      # WPA Key Id
        b'\x00'*16,     # WPA Key MIC, set to 0 for now
        rsn_length,     # WPA Key Data Length
        raw(rsn)        # WPA Key Data
    ]))
    MIC = hmac.new(KCK, raw(eapol / eapol_data), 'sha1').digest()[:16]
    # now insert the real MIC
    eapol_data.load = eapol_data.load[:77] + MIC + eapol_data.load[77 + 16:]
    dot11 = Dot11(
        type='Data',
        subtype=0,      # Data
        FCfield='to-DS',
        ID=14849,       # duration: 314 microseconds
        addr1=bssid,
        addr2=sta,
        addr3=bssid
    )
    # from https://en.wikipedia.org/wiki/Subnetwork_Access_Protocol:
    # The 5-octet SNAP header follows the 802.2 LLC header if the destination SAP (DSAP)
    # and the source SAP (SSAP) contain hexadecimal values of AA or AB.
    llc = LLC(
        dsap=0xaa,
        ssap=0xaa,
        ctrl=3      # Unnumbered information frame
    )
    snap = SNAP(
        OUI=0,
        code='PAE'  # 0x88ee, 802.1X Port Access Entity
    )
    message_2 = RadioTap() / dot11 / llc / snap / eapol / eapol_data
    logging.info('Sending EAPOL Message 2:')
    logging.info(repr(message_2))
    # need to use the sniffer here as well since EAPOL 3 isn't 
    # captured by srp1 for some reason
    key_info = b'\x13\xca'
    # Key Information should be 0x13ca because
    # .... .... .... .010 = Key Descriptor Version: AES Cipher, HMAC-SHA1 MIC
    # .... .... .... 1... = Key Type: Pairwise
    # .... .... ..00 .... = Key Index: 0
    # .... .... .1.. .... = Install: Set
    # .... .... 1... .... = Key ACK: Set
    # .... ...1 .... .... = Key MIC: Set
    # .... ..1. .... .... = Secure: Set
    # .... .0.. .... .... = Error: Not set
    # .... 0... .... .... = Request: Not set
    # ...1 .... .... .... = Encrypted Key Data: Set
    # ..0. .... .... .... = SMK Message: Not set
    sniffer = AsyncSniffer(
        lfilter=lambda pkt: pkt.haslayer(EAPOL) and 
            pkt.getlayer(Dot11).addr1 == sta and
            pkt.getlayer(Dot11).addr2 == bssid,
        stop_filter=lambda pkt: pkt.getlayer(Raw).load[1:3] == key_info,
        iface=iface,
        timeout=timeout
    )
    sniffer.start()
    sendp(message_2, iface=iface)
    sniffer.join()
    try:
        message_3 = sniffer.results.filter(
            lambda pkt: pkt.getlayer(Raw).load[1:3] == key_info)[0]
    except IndexError:
        message_3 = None
    return message_3, KCK


def send_message_4(message_3: Packet, KCK: bytes, iface: str) -> None:
    """
    Sends Message 4 of the 4-way handshake for WPA2. Returns None since
    this is the last message of the handshake.

    :param message_3: Message 3 of the 4-way handshake
    :param KCK: key confirmation key required to compute the MIC
    :param iface: wireless network interface in monitor mode
    """
    sta = message_3.getlayer(Dot11).addr1
    bssid = message_3.getlayer(Dot11).addr2
    key_replay_counter = message_3.getlayer(Raw).load[5:5 + 8]
    eapol = EAPOL(
        version='802.1X-2004',
        type='EAPOL-Key'
    )
    eapol_data = Raw(load=b''.join([
        b'\x02',        # Key Descriptor Type: EAPOL RSN Key
        b'\x03\x0a',    # Secure: set, Key MIC: set, Key Type: Pairwise key,
                        #   Key Descriptor Version: AES HMAC-SHA1
        b'\x00\x00',    # Key Length: 0
        key_replay_counter,  # Replay Counter
        b'\x00'*32,     # WPA Key Nonce
        b'\x00'*16,     # Key IV
        b'\x00'*8,      # WPA Key RSC
        b'\x00'*8,      # WPA Key Id
        b'\x00'*16,     # WPA Key MIC, set to 0 for now
        b'\x00\x00'     # WPA Key Data Length: 0
    ]))
    MIC = hmac.new(KCK, raw(eapol / eapol_data), 'sha1').digest()[:16]
    # now insert the real MIC
    eapol_data.load = eapol_data.load[:77] + MIC + eapol_data.load[77 + 16:]
    dot11 = Dot11(
        type='Data',
        subtype=0,      # Data
        FCfield='to-DS',
        ID=14849,       # duration: 314 microseconds
        addr1=bssid,
        addr2=sta,
        addr3=bssid
    )
    llc = LLC(
        dsap=0xaa,
        ssap=0xaa,
        ctrl=3      # Unnumbered information frame
    )
    snap = SNAP(
        OUI=0,
        code='PAE'  # 0x88ee, 802.1X Port Access Entity
    )
    message_4 = RadioTap() / dot11 / llc / snap / eapol / eapol_data
    logging.info('Sending EAPOL Message 4:')
    logging.info(repr(message_4))
    sendp(message_4, iface=iface)