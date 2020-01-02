import logging
import random
import argparse
import getpass
import sys
from scapy.layers.dot11 import Dot11, Dot11AssoResp, \
    Dot11Auth, Dot11EltRSN
from scapy.layers.eap import EAPOL
from scapy.sendrecv import AsyncSniffer
import beacon
import authentication as auth
import association as assoc
import handshake

logging.basicConfig(level='INFO')

parser = argparse.ArgumentParser(description='WPA2 Handshake Demo')
parser.add_argument('-s', '--ssid', help='SSID of the network', required=True)
parser.add_argument('-i', '--iface', help='wireless network interface ' +
    'in monitor mode', required=True)
parser.add_argument('-a', '--address', help='MAC address of the sender')
parser.add_argument('-t', '--timeout', type=int, default=3,
    help='timeout in seconds when waiting for a response')
parser.add_argument('-p', '--password', help='password for the network')
args = parser.parse_args()

if args.password is None:
    password = getpass.getpass('WiFi password: ')
else:
    password = args.password
if args.address is None:
    # I think a real OUI needs to be used for the AP to recognize it as valid
    # So let's just use the Intel OUI
    sender = '88:b1:11:' + ':'.join(map(lambda n: bytes([n]).hex(),
        (random.randrange(256) for i in range(3))))
else:
    sender = args.address
SSID = args.ssid
iface = args.iface
timeout = args.timeout

# capture a beacon frame for the given SSID
beacon_frame = beacon.capture(SSID, iface, timeout)
if beacon_frame is None:
    logging.error('Beacon frame not found for ' + SSID)
    sys.exit(1)
bssid = beacon_frame.getlayer(Dot11).addr2
rsn = beacon_frame.getlayer(Dot11EltRSN)
if rsn is None:
    logging.error(f'Beacon frame for {SSID} did not have an RSN element')
    sys.exit(1)
# make sure that the AP is configured for WPA2-PSK
if not any(suite.cipher == 4 for suite in rsn.pairwise_cipher_suites):
    logging.error(SSID + ' does not support CCMP')
    sys.exit(1)
elif not any(suite.suite == 2 for suite in rsn.akm_suites):
    logging.error(SSID + ' does not support PSK')
    sys.exit(1)

logging.info('Captured beacon frame for ' + SSID)
logging.info(repr(beacon_frame))

# authentication request/response
resp = auth.request(bssid, sender, iface=iface, timeout=timeout)
if resp is None or resp.getlayer(Dot11Auth).status != 0:
    logging.error('Could not authenticate to ' + SSID)
    sys.exit(1)
logging.info(f'Successfully authenticated to {SSID}:')
logging.info(repr(resp))

# association request/response
# need to start listening for the EAPOL frame now because
# the first message is initiated by the AP
sniffer = AsyncSniffer(
    lfilter=lambda pkt: pkt.haslayer(EAPOL) and
        #pkt.getlayer(EAPOL).type == 2 and
        pkt.getlayer(Dot11).addr1 == sender and
        pkt.getlayer(Dot11).addr2 == bssid,
    iface=iface,
    timeout=timeout,
    count=1)
sniffer.start()
resp = assoc.request(beacon_frame, sender, iface, timeout)
if resp is None or resp.getlayer(Dot11AssoResp).status != 0:
    logging.error('Could not associate with ' + SSID)
    sys.exit(1)
logging.info(f'Successfully associated with {SSID}:')
logging.info(repr(resp))

# EAPOL Message 1
sniffer.join()
try:
    eapol_msg_1 = sniffer.results[0]
except IndexError:
    logging.error('Did not receive EAPOL Message 1')
    sys.exit(1)
logging.info('Received EAPOL Message 1:')
logging.info(repr(eapol_msg_1))

# EAPOL Message 2 and 3
eapol_msg_3, KCK = handshake.send_message_2(eapol_msg_1, SSID, password,
    iface, timeout)
if eapol_msg_3 is None:
    logging.error('Did not receive EAPOL Message 3')
    sys.exit(1)
logging.info('Received EAPOL Message 3:')
logging.info(repr(eapol_msg_3))

# EAPOL MESSAGE 4
handshake.send_message_4(eapol_msg_3, KCK, iface)

logging.info('WPA2-PSK handshake complete.')