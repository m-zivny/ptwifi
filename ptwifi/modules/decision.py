"""
modules/decision.py

This module performs the final correlation of data from scanning modules 
(passive, active, deauth) and evaluates the roles of L2/L3 devices, 
including the security status of access points.
"""

from helpers.classes import Station, AP, Style


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


def evaluate_ap_security_and_role(ap: AP) -> list[str]:
    """
    Correlates parameters from the passive scan with active test results
    to identify security vulnerabilities and misconfigurations.

    Args:
        ap (AP): The access point object containing aggregated scan data.

    Returns:
        list[str]: A list of formatted strings describing identified security findings.
    """
    findings = []

    if "11" in ap.observed_ds_states:
        findings.append(f"{Style.GREEN}[Info] This access point works as a Bridge in WDS.{Style.RESET}")
    
    # 1. Basic encryption evaluation
    if ap.encryption_mode in ["Open", "WEP"]:
        findings.append(f"{Style.RED}[Vulnerability] Unsecured encryption mode detected: {ap.encryption_mode}! {Style.RESET}")

    # 2. Cipher & Auth evaluation
    if hasattr(ap, 'cipher') and "TKIP" in ap.cipher:
        findings.append(f"{Style.RED}[Vulnerability] Obsolete TKIP cipher detected. TKIP contains known cryptographic flaws. Recommend disabling TKIP and using different cipher.{Style.RESET}")

    if hasattr(ap, 'auth_method') and ap.auth_method == "PSK" and ap.encryption_mode == "WPA2":
        findings.append(f"[Info] WPA2-PSK is used. Ensure the passphrase is long and complex to prevent offline dictionary/brute-force attacks.")

    # 3. PMF evaluation
    pmf_active = False
    pmf_inactive = False
    
    if hasattr(ap, 'test_results'):
        for key, result in ap.test_results.items():
            if key.startswith("PMF"):
                if "Disconnected" in result:
                    pmf_inactive = True
                elif "Active/Ignored" in result:
                    pmf_active = True

        if ap.encryption_mode == "WPA2":
            findings.append("[Info] WPA2 encryption detected. Consider upgrading to WPA3.")
            
            if pmf_inactive:
                findings.append(f"{Style.RED}[Vulnerability] WPA2 network does not enforce PMF and is susceptible to deauthentication attacks. Recommend enabling PMF in the AP settings or migrating to WPA3.{Style.RESET}")
                
        elif ap.encryption_mode == "WPA3":
            if pmf_inactive:
                findings.append(f"{Style.RED}[Vulnerability] WPA3 network failed to prevent client disconnection.{Style.RESET}")

        # 4. L2 availability evaluation from active scan
        auth_status = ap.test_results.get('auth_status')
        assoc_status = ap.test_results.get('assoc_status')
        
        if auth_status is not None:
            if auth_status == 0 and assoc_status == 0 and ap.encryption_mode == "Open":
                findings.append(f"{Style.RED}[Vulnerability] Open network is fully accessible at the L2 layer. Association successful.{Style.RESET}")
            elif auth_status != 0 or assoc_status != 0:
                findings.append(f"[Info] Association or Authentication was not successful. Rejected/Ignored by AP (Auth: {auth_status}, Assoc: {assoc_status}).")

    return findings


def run(aps: list[AP], stas: list[Station]) -> None:
    """
    Main execution function for the decision engine. Processes all captured devices
    and prints a final formatted evaluation report to the terminal.

    Args:
        aps (list[AP]): The final list of analyzed Access Points.
        stas (list[Station]): The final list of analyzed Stations.
    """

    print("\n\n\n")
    print(f"{Style.BOLD}[*] TEST RESULTS{Style.RESET}")

    
    print(f"\n{Style.BOLD}[*] STATION ROLE ANALYSIS {Style.RESET} \n")
    if not stas:
        print("No stations were provided for analysis.")
    
    for sta in stas:
        if sta.data_frames_num > 0:
            role = evaluate_station_role(sta)
            ip_addresses = ", ".join(sta.sent_arps) if hasattr(sta, 'sent_arps') and sta.sent_arps else "Not captured"
            print(f"{Style.BOLD}MAC: {sta.mac}{Style.RESET}")
            print(f"  └─ Role: {role}")
            print(f"  └─ IP Addresses (ARP): {ip_addresses}")

    print(f"\n{Style.BOLD}[*] ACCESS POINT ANALYSIS{Style.RESET} \n")
    if not aps:
        print("No access points were provided for analysis.")
        
    for ap in aps:
        print(f"{Style.BOLD}BSSID: {ap.bssid} | ESSID: {ap.essid} {Style.RESET}")
        
        findings = evaluate_ap_security_and_role(ap)
        if not findings:
            print("  └─[Info] No obvious vulnerabilities were detected from the performed tests.")
        else:
            for finding in findings:
                print(f"  └─ {finding}")
        print("\n")