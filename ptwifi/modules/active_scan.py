"""
modules/active_scan.py
Author: Martin Živný

Description
-----------
This module implements active Wi-Fi scanning and analysis in the PTWiFi tool.

It utilizes the Scapy library to craft and inject specific 802.11 management 
frames, such as Authentication and Association Requests. By analyzing the 
responses from Access Points, it identifies device capabilities, verifies 
security configurations, and collects data for role detection.
"""

import time
from datetime import datetime
from scapy.volatile import RandMAC
from scapy.all import (
    RadioTap, 
    Dot11, 
    Dot11Auth, 
    Dot11AssoReq, 
    Dot11AssoResp,
    Dot11Elt, 
    srp1,     
    wrpcap,   
)
from helpers.classes import AP, Style

MAX_RETRIES = 10
TIMEOUT_TIME = 0.3

def analyze_capabilities(cap_value: int) -> dict[str, bool]:
    """
    Analyzes the 16-bit Capability Information field using bitmasks.
    Fixes endianness to correctly interpret 802.11 Little-Endian format.

    Args:
        cap_value (int): The raw capability integer extracted from the frame.

    Returns:
        dict[str, bool]: A dictionary mapping capability names to boolean values.
    """
    try:
        cap_int = int(cap_value)
        cap_swapped = ((cap_int & 0xFF) << 8) | ((cap_int >> 8) & 0xFF)
    except (ValueError, TypeError):
        return {}

    return {
        "ESS (Access Point)": bool(cap_swapped & 0x0001),
        "IBSS (Ad-Hoc)": bool(cap_swapped & 0x0002),
        "Privacy (Encryption)": bool(cap_swapped & 0x0010),
        "Short Preamble": bool(cap_swapped & 0x0020),
        "Spectrum Management": bool(cap_swapped & 0x0100),
        "Short Slot Time": bool(cap_swapped & 0x0400),
        "Radio Measurement": bool(cap_swapped & 0x1000)
    }

def print_capabilities(capabilities: dict[str, bool]) -> None:
    """
    Prints a formatted summary of extracted AP capabilities to the terminal.

    Args:
        capabilities (dict[str, bool]): The dictionary mapping capability names to support status.
    """
    print(f"\n{Style.BOLD}[+] Extracted Capability Information:{Style.RESET}")
    for feature, is_supported in capabilities.items():
        status = "\033[32m[YES]\033[0m" if is_supported else "\033[31m[NO]\033[0m"
        print(f"    {feature:<25} {status}")

def create_auth_frame(target_bssid: str, client_mac: str) -> RadioTap:
    """
    Constructs an 802.11 Authentication frame (Open System) using Scapy.

    Args:
        target_bssid (str): The MAC address of the target Access Point.
        client_mac (str): The spoofed or real MAC address of the client sending the request.

    Returns:
        RadioTap: The fully constructed Scapy packet ready for injection.
    """
    dot11 = Dot11(
        type=0, 
        subtype=11, 
        addr1=target_bssid, 
        addr2=client_mac, 
        addr3=target_bssid
    )
    auth = Dot11Auth(algo=0, seqnum=1, status=0)
    return RadioTap() / dot11 / auth

def create_assoc_req_frame(target_bssid: str, client_mac: str, essid: str) -> RadioTap:
    """
    Constructs an 802.11 Association Request frame using Scapy.

    Args:
        target_bssid (str): The MAC address of the target Access Point.
        client_mac (str): The MAC address of the client sending the request.
        essid (str): The network name the client is attempting to associate with.

    Returns:
        RadioTap: The fully constructed Scapy packet ready for injection.
    """
    dot11 = Dot11(
        type=0, 
        subtype=0, 
        addr1=target_bssid, 
        addr2=client_mac, 
        addr3=target_bssid
    )
    assoc_req = Dot11AssoReq(cap=0x0421, listen_interval=0x00c8)
    
    essid_ie = Dot11Elt(ID=0, info=essid)
    rates_ie = Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96')
    ext_rates_ie = Dot11Elt(ID=50, info=b'\x0c\x12\x18\x24\x30\x48\x60\x6c')
    ht_cap_ie = Dot11Elt(ID=45, info=b'\xef\x01\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    
    return RadioTap() / dot11 / assoc_req / essid_ie / rates_ie / ext_rates_ie / ht_cap_ie

def run(interface: str, target_ap: AP) -> None:
    """
    Executes the active scanning phase against a specific target Access Point.
    Injects authentication and association frames, parses responses, and logs results.

    Args:
        interface (str): The name of the wireless interface in monitor mode.
        target_ap (AP): The Access Point object representing the test target.
    """
    timestamp = datetime.now().strftime("[%Y-%m-%d_%H-%M]")
    export_path = f"output/active_scan/{timestamp}_{target_ap.bssid.replace(':', '')}.pcap"

    print(f"\n{Style.BOLD}--- ACTIVE AP TEST ---{Style.RESET}")
    print(f"Target: {target_ap.essid} ({target_ap.bssid})")
    print(f"Channel: {target_ap.channel}")

    captured_packets = []
    auth_resp = None
    
    # Phase 1: Authentication
    for attempt in range(1, MAX_RETRIES + 1):
        client_mac = str(RandMAC())
        auth_req = create_auth_frame(target_ap.bssid, client_mac)
        captured_packets.append(auth_req)

        print(f"\r[*] Testing Authentication (Attempt {attempt}/{MAX_RETRIES})...", end="", flush=True)

        auth_resp = srp1(auth_req, iface=interface, timeout=TIMEOUT_TIME, verbose=False)

        if auth_resp and auth_resp.haslayer(Dot11Auth):
            print() 
            break
        time.sleep(0.5)

    if not auth_resp or not auth_resp.haslayer(Dot11Auth):
        print("\n[-] AP did not respond to Authentication Request.")
        target_ap.test_results['auth_status'] = "Timeout"
        wrpcap(export_path, captured_packets)
        time.sleep(2)
        return

    captured_packets.append(auth_resp)
    auth_status = auth_resp[Dot11Auth].status
    print(f"[+] Auth Response Status: {auth_status}")
    target_ap.test_results['auth_status'] = auth_status 

    if auth_status != 0:
        print("[-] Authentication failed. Aborting.")
        wrpcap(export_path, captured_packets)
        time.sleep(2)
        return

    # Phase 2: Association
    assoc_resp = None
    for attempt in range(1, MAX_RETRIES + 1):
        assoc_req = create_assoc_req_frame(target_ap.bssid, client_mac, target_ap.essid)
        captured_packets.append(assoc_req)

        print(f"\r[*] Testing Association (Attempt {attempt}/{MAX_RETRIES})...", end="", flush=True)
        
        assoc_resp = srp1(assoc_req, iface=interface, timeout=TIMEOUT_TIME, verbose=False)
        
        if assoc_resp and assoc_resp.haslayer(Dot11AssoResp):
            print() 
            break

    if not assoc_resp or not assoc_resp.haslayer(Dot11AssoResp):
        print("\n[-] AP did not respond to Association Request.")
        target_ap.test_results['assoc_status'] = "Timeout"
        wrpcap(export_path, captured_packets)
        time.sleep(2)
        return

    captured_packets.append(assoc_resp)
    assoc_status = assoc_resp[Dot11AssoResp].status
    print(f"[+] Association Response Status: {assoc_status}")
    target_ap.test_results['assoc_status'] = assoc_status

    # Phase 3: Capability analysis
    raw_cap_int = assoc_resp[Dot11AssoResp].cap
    parsed_caps = analyze_capabilities(raw_cap_int)
    
    if parsed_caps:
        print("[+] Capabilities successfully extracted.")
    else:
        print("[-] Failed to extract capabilities.")
    
    target_ap.test_results['capabilities'] = parsed_caps

    wrpcap(export_path, captured_packets)
    print(f"\n[*] Session saved to: {export_path}")
    time.sleep(5)