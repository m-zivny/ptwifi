"""
modules/decision.py

This module performs the final correlation of data from scanning modules 
(passive, active, deauth) and evaluates the roles of L2/L3 devices, 
including the security status of access points.
"""

from helpers.classes import Station, AP

def evaluate_station_role(station: Station) -> str:
    """
    Evaluates the network role of a station based on L2 and L3 indicators.

    Args:
        station (Station): The station object populated with passively captured data.

    Returns:
        str: A string describing the likely role of the device.
    """
    if "11" in station.observed_ds_states:
        return "WDS Bridge / Master (4-address format)"
    
    # MAC NAT (Proxy ARP) detection
    if hasattr(station, 'sent_arps') and len(station.sent_arps) > 1:
        return "Pseudobridge (ClientBridge with MAC translation)"
    
    return "Standard client station"

def evaluate_ap_security(ap: AP) -> list[str]:
    """
    Correlates cryptographic parameters from the passive scan with active test results
    to identify security vulnerabilities and misconfigurations.

    Args:
        ap (AP): The access point object containing aggregated scan data.

    Returns:
        list[str]: A list of formatted strings describing identified security findings.
    """
    findings = []
    
    # 1. Basic encryption evaluation
    if ap.encryption_mode in ["Open", "WEP"]:
        findings.append(f"[Critical] Unsecured mode detected: {ap.encryption_mode}.")

    # 2. PMF (802.11w) evaluation based on deauth attack
    pmf_active = False
    pmf_inactive = False
    
    if hasattr(ap, 'test_results'):
        for key, result in ap.test_results.items():
            if key.startswith("802.11w"):
                if "Disconnected" in result:
                    pmf_inactive = True
                elif "Active/Ignored" in result:
                    pmf_active = True

        if ap.encryption_mode == "WPA2":
            if pmf_inactive:
                findings.append("[Vulnerability] WPA2 does not enforce PMF. The network is susceptible to deauth (DoS) attacks.")
            elif pmf_active:
                findings.append("[Info] WPA2 correctly implements and enforces PMF protection.")
                
        elif ap.encryption_mode == "WPA3" and pmf_inactive:
            findings.append("[Anomaly] WPA3 network failed to prevent client disconnection. Severe violation of the IEEE 802.11 standard.")

        # 3. L2 availability evaluation from active scan
        auth_status = ap.test_results.get('auth_status')
        assoc_status = ap.test_results.get('assoc_status')
        
        if auth_status == 0 and assoc_status == 0 and ap.encryption_mode == "Open":
            findings.append("[Critical] Open network is fully accessible at the L2 layer. Association successful.")
        elif (isinstance(auth_status, int) and auth_status != 0) or (isinstance(assoc_status, int) and assoc_status != 0):
            findings.append(f"[Info] Active L2 protection detected. Rejected by AP (Auth: {auth_status}, Assoc: {assoc_status}).")

    return findings

def run(aps: list[AP], stas: list[Station]) -> None:
    """
    Main execution function for the decision engine. Processes all captured devices
    and prints a final formatted evaluation report to the terminal.

    Args:
        aps (list[AP]): The final list of analyzed Access Points.
        stas (list[Station]): The final list of analyzed Stations.
    """
    print("\n" + "="*50)
    print("FINAL NETWORK EVALUATION (DECISION ENGINE)")
    print("="*50)
    
    print("\n--- STATION ROLE ANALYSIS (L2/L3) ---")
    if not stas:
        print("No stations were provided for analysis.")
    
    for sta in stas:
        if sta.data_frames_num > 0:
            role = evaluate_station_role(sta)
            ip_addresses = ", ".join(sta.sent_arps) if hasattr(sta, 'sent_arps') and sta.sent_arps else "Not captured"
            print(f"MAC: {sta.mac}")
            print(f"  └─ Role: {role}")
            print(f"  └─ IP Addresses (ARP): {ip_addresses}")

    print("\n--- ACCESS POINT SECURITY ANALYSIS ---")
    if not aps:
        print("No access points were provided for analysis.")
        
    for ap in aps:
        print(f"\nBSSID: {ap.bssid} | ESSID: {ap.essid} | Encryption: {ap.encryption_mode}")
        
        findings = evaluate_ap_security(ap)
        if not findings:
            print("  └─ No obvious vulnerabilities were detected from the performed tests.")
        else:
            for finding in findings:
                print(f"  └─ {finding}")
    
    print("\n" + "="*50 + "\n")