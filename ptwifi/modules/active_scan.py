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

import time, os, json
from datetime import datetime
from scapy.all import (
    RandMAC,
    RadioTap, 
    Dot11, 
    Dot11Auth, 
    Dot11AssoReq, 
    Dot11AssoResp,
    Dot11Elt, 
    srp1,     
)
from helpers.classes import AP, Style

MAX_RETRIES = 10
TIMEOUT_TIME = 0.3

def analyze_capabilities(cap_value) -> dict[str, bool]:
    """
    Analyzes the Capability Information field.
    Leverages Scapy's internal parsing of FlagsField into a string representation.
    """
    cap_str = str(cap_value).lower()
    
    return {
        "ESS (Access Point)": "ess" in cap_str,
        "IBSS (Ad-Hoc)": "ibss" in cap_str,
        "Privacy (Encryption)": "privacy" in cap_str,
        "Short Preamble": "short-preamble" in cap_str,
        "Spectrum Management": "spectrum-mgmt" in cap_str,
        "Short Slot Time": "short-slot" in cap_str,
        "Radio Measurement": "radio-measurement" in cap_str
    }

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

    vendor_ie = Dot11Elt(
    ID=221,
    info=b'\x00\x17\xf2\x0a\x00\x01\x04\x00\x00\x00\x00'
)

    return RadioTap() / dot11 / auth / vendor_ie

def create_assoc_req_frame(target_bssid: str, client_mac: str, essid: str) -> RadioTap:
    """Constructs an 802.11 Association Request frame using Scapy.

    This function builds a structured Association Request packet containing
    the necessary Information Elements (IEs) such as SSID, supported rates,
    extended supported rates, HT capabilities, and an RSN IE to prevent
    'Invalid RSNE capabilities' rejection on WPA2 networks.

    Args:
        target_bssid: The MAC address of the target Access Point.
        client_mac: The MAC address of the client sending the request.
        essid: The network name (SSID) the client is attempting to associate with.

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
    
    # Capability info: Privacy bit set (0x1431) to match WPA2 requirements
    assoc_req = Dot11AssoReq(cap=0x1431, listen_interval=0x00c8)
    
    # IE 0: SSID
    essid_ie = Dot11Elt(ID=0, info=essid)
    
    # IE 1: Supported Rates (1, 2, 5.5, 11 Mbps as Basic; 6, 9, 12, 18 Mbps as Supported)
    rates_ie = Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
    
    # IE 50: Extended Supported Rates (24, 36, 48, 54 Mbps)
    ext_rates_ie = Dot11Elt(ID=50, info=b'\x30\x48\x60\x6c')
    
    # IE 45: HT Capabilities (802.11n support configuration)
    ht_cap_ie = Dot11Elt(ID=45, info=b'\xef\x01\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    
    # IE 48: RSN IE configured for standard WPA2-PSK (AES/CCMP)
    rsn_ie = Dot11Elt(ID=48, info=b'\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00')
    
    return RadioTap() / dot11 / assoc_req / essid_ie / rates_ie / ext_rates_ie / ht_cap_ie / rsn_ie

def run(interface: str, target_ap: AP) -> None:
    timestamp = datetime.now().strftime("[%Y-%m-%d_%H-%M]")
    json_export_path = f"output/active_scan/{timestamp}_{target_ap.bssid.replace(':', '')}.json"

    print("\n")
    print(f"[***] Target: {target_ap.essid} ({target_ap.bssid})")
    print(f"[**] Channel: {target_ap.channel}")

    auth_resp = None
    
    # Phase 1: Authentication
    for attempt in range(1, MAX_RETRIES + 1):
        client_mac = str(RandMAC("AE:*:*:*:*:*"))
        auth_req = create_auth_frame(target_ap.bssid, client_mac)

        print(f"\r[*] Testing Authentication (Attempt {attempt}/{MAX_RETRIES})...", end="", flush=True)

        auth_resp = srp1(auth_req, iface=interface, timeout=TIMEOUT_TIME, verbose=False)

        if auth_resp and auth_resp.haslayer(Dot11Auth):
            print() 
            break
        time.sleep(0.5)

    if not auth_resp or not auth_resp.haslayer(Dot11Auth):
        print("\n[-] AP did not respond to Authentication Request.")
        target_ap.test_results['auth_status'] = "Timeout"
        time.sleep(2)
        return

    auth_status = auth_resp[Dot11Auth].status
    print(f"[+] Auth Response Status: {auth_status}")
    target_ap.test_results['auth_status'] = auth_status 

    if auth_status != 0:
        print("[-] Authentication failed. Aborting.")
        time.sleep(2)
        return

    # Phase 2: Association
    assoc_resp = None
    for attempt in range(1, MAX_RETRIES + 1):
        assoc_req = create_assoc_req_frame(target_ap.bssid, client_mac, target_ap.essid)

        print(f"\r[*] Testing Association (Attempt {attempt}/{MAX_RETRIES})...", end="", flush=True)
        
        assoc_resp = srp1(assoc_req, iface=interface, timeout=TIMEOUT_TIME, verbose=False)
        
        if assoc_resp and assoc_resp.haslayer(Dot11AssoResp):
            print() 
            break

    if not assoc_resp or not assoc_resp.haslayer(Dot11AssoResp):
        print("\n[-] AP did not respond to Association Request.")
        target_ap.test_results['assoc_status'] = "Timeout"
        time.sleep(2)
        return

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

    # Export JSON
    with open(json_export_path, 'w', encoding='utf-8') as f:
        json.dump({
            "ESSID": target_ap.essid,
            "BSSID": target_ap.bssid,
            "Channel": target_ap.channel,
            "Test Results": target_ap.test_results
        }, f, indent=4)
    print(f"[*] JSON Results saved to: {json_export_path}")
    
    time.sleep(5)