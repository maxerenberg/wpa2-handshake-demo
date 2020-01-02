# wpa2-handshake-demo
A simple demonstration of the WPA2-PSK handshake.

### What's this for?
This is a live demonstration of the 4-way handshake which occurs every time a station joins a WPA2-PSK wireless network. Each 802.11 frame is logged to stdout so you can see what is happening in real time. 

### Dependencies
Must be running Python 3.6+.

This program requires [Scapy](https://github.com/secdev/scapy). As of 01/02/2019, the version in PyPI (2.4.3) has an issue with reading the country element in beacon frames. This issue was fixed in version 2.4.3.dev203, so I recommend installing Scapy directly from Github:
```
$ git clone https://github.com/secdev/scapy
$ cd scapy
$ pip3 install .
```

### Warnings
Since this program sends raw packets, root permissions are needed (i.e. run as root user or with `sudo`).

### Usage
You will need to know the frequency over which the AP is sending and receiving frames (e.g. 2.437 GHz). If you are currently connected to the AP, this can be found using the `iw` utility, e.g.
```
$ iw wlan0 link
Connected to 00:fc:8d:45:67:ab (on wlan0)
	SSID: Max's wifi
	freq: 2437
	signal: -44 dBm
	tx bitrate: 144.4 MBit/s

	bss flags:	short-slot-time
	dtim period:	0
	beacon int:	100
```
One wireless interface in monitor mode is required. The interface must be set to the frequency of the AP. This can be configured using the `iw` utility, e.g.
```
$ ip link set wlan0 down
$ iw dev wlan0 set type monitor
$ iw dev wlan0 set freq 2437
$ ip link set wlan0 up
```
At minimum, the SSID and interface name must be specified when running the program:
```
# python3 main.py -i wlan0 -s "Max's wifi"
```
If the MAC address is not specified (with `-a`), a random address will be generated. The WiFi password can be specified with `-p` or entered interactively.

A sample output is provided in sample_output.txt.