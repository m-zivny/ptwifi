"""
main.py
Author: Martin Živný

Description
-----------
This script serves as the main entry point of the "ptwifi" tool. It handles
command-line argument parsing, validates runtime conditions, prepares the
wireless interface for operation, and executes the selected analysis modules.

The script ensures that the selected wireless interface supports monitor mode,
switches the interface into monitor mode if necessary, optionally sets the
requested WiFi channel, and executes the requested tool modes sequentially.

Responsibilities
---------------
- Parse and validate command-line arguments
- Verify privileges for running dependent tools
- Check availability of the specified wireless interface
- Enable monitor mode on the interface
- Set the working WiFi channel if specified
- Execute the selected tool modes sequentially
- Restore the wireless interface back to managed mode after execution
"""

import argparse
import os
from datetime import datetime
import time

from helpers import interface_setup as setup
from helpers.classes import PTModes, InterfaceModes
from helpers.classes import StrengthColors as Sc
from modules import active_scan, passive_scan, deauth_attack
from helpers import helper_functions as helper

KNOWN_PT_MODES = [_mode for _mode in dir(PTModes) if not _mode.startswith("__")]

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('interface', type=str, help='Name of the wireless interface to be used, must support at least monitor mode.')
    parser.add_argument('modes', type=str, nargs='+', help='Tool modes to be executed sequentially. Example: "passive active deauth"')
    parser.add_argument('--channel', '-c', type=str, help="Channel to be worked in.")
    parser.add_argument('--BSSID', '-b', type=str, help="BSSID (MAC Address) of the targeted AP.")
    parser.add_argument('--MAC', '-a', type=str, help="MAC Address of the targeted STA.")
    parser.add_argument('--time_period', '-t', type=int, help="Time period between deauth packets in ms, 500 ms is default.")
    parser.add_argument('--number', '-n', type=int, help="Number of deauth packets to be sent. -1 is default, means indefinitely.")
    parser.add_argument('--burst_number', '-bn', type=int, help="Number of deauth packets to be sent at once. 1 is default")
    parser.add_argument('--sta_off', action="store_false", help="Turn off showing STA.")
    parser.add_argument('--hidden_off', action="store_false", help="Turn off showing APs with hidden SSID.")
    parser.add_argument('--json', type=str, help="Name of the json file to output.")

    args = parser.parse_args()
    interface_name = args.interface
    
    # Process sequential modes
    raw_modes = " ".join(args.modes).lower()
    tool_modes = raw_modes.split()

    target_channels = args.channel
    if target_channels is not None:
        target_channels = target_channels.split(',')

    target_bssid = args.BSSID
    target_station_mac = args.MAC
    time_period_ms = args.time_period
    packet_count = args.number
    burst_size = args.burst_number
    sta_filter = args.sta_off if args.sta_off is not None else True
    hidden_filter = args.hidden_off if args.hidden_off is not None else True
    filename_json = args.json

    if not helper.is_sudo():
        print("Script needs to be run with sudo privileges.")
        exit(1)

    if interface_name == "show" and "ifaces" in tool_modes:
       print(f"{Sc.BOLD}Name\t \tVendor{Sc.RESET}")
       wireless_interfaces = [[x[0]] for x in setup.get_wireless_interfaces() if x[1] == "wifi"]
       for interface in wireless_interfaces:
           interface.append(helper.merge_list_to_string(setup.get_interface_product(interface[0])))
           print(interface[0] + "\t \t"+ interface[1])
       exit(0)

    if not setup.wireless_interface_exists(interface_name):
       print(f"Interface {interface_name} not found.")
       exit(1)

    if not setup.interface_supports_monitor(interface_name):
       print(f"Interface {interface_name} does not support monitor mode.")
       exit(1)

    phy_index = setup.get_phy_index(interface_name)
    if not setup.interface_in_mode(interface_name, InterfaceModes.MONITOR):
        setup.set_monitor(interface_name, phy_index)
    interface_name = f"{interface_name}mon"

    if target_channels is not None:
        setup.set_channel(interface_name, target_channels[0])

    discovered_aps = []
    discovered_stas = []
    tested_aps = []

    try:
        # 1. PASSIVE SCAN PHASE
        if "passive" in tool_modes:
            print(f"\n{Sc.BOLD}[*] PHASE: PASSIVE SCAN{Sc.RESET}")
            print("Stop the scan using Ctrl+C to proceed to the next phase.")
            time.sleep(5)
            discovered_aps, discovered_stas = passive_scan.run(
                interface_name, 
                target_channels[0] if target_channels else None, 
                sta_filter, 
                hidden_filter, 
                filename_json 
            )

        # 2. ACTIVE SCAN PHASE
        if "active" in tool_modes and discovered_aps:
            print(f"\n{Sc.BOLD}[*] PHASE: ACTIVE AP TESTING{Sc.RESET}")
            for ap in discovered_aps:
                if target_bssid and ap.bssid.upper() != target_bssid.upper():
                    continue
                if ap.channels:
                    setup.set_channel(interface_name, str(ap.channels[0]))
                
                active_scan.run(interface_name, ap)
                if ap not in tested_aps:
                    tested_aps.append(ap)

        # 3. DEAUTH ATTACK PHASE (802.11w Test)
        if "deauth" in tool_modes:
            if discovered_aps:
                print(f"\n{Sc.BOLD}[*] PHASE: DEAUTH TEST (802.11w){Sc.RESET}")
                aps_to_check = tested_aps if tested_aps else discovered_aps
                for ap in aps_to_check:
                    if target_bssid and ap.bssid.upper() != target_bssid.upper():
                        continue
                    if ap.channels:
                        setup.set_channel(interface_name, str(ap.channels[0]))
                    
                    deauth_attack.run(interface_name, ap, time_period_ms, packet_count, burst_size)
                    if ap not in tested_aps:
                        tested_aps.append(ap)
            else:
                print(f"\n{Sc.BOLD}[-] PHASE: DEAUTH TEST (802.11w) aborted.{Sc.RESET}")
                print("No Access Points were discovered during the passive scan.")

        # 4. FINAL RESULTS AND EXPORT
        if "active" in tool_modes or ("deauth" in tool_modes and discovered_aps):
            print(f"\n{Sc.BOLD}========================================={Sc.RESET}")
            print(f"{Sc.BOLD}          FINAL TEST RESULTS             {Sc.RESET}")
            print(f"{Sc.BOLD}========================================={Sc.RESET}")
            
            for ap in tested_aps:
                if hasattr(ap, 'test_results') and ap.test_results:
                    print(f"\n[AP] {ap.essid} ({ap.bssid})")
                    for test, result in ap.test_results.items():
                        if isinstance(result, dict):
                            print(f"  - {test}:")
                            for k, v in result.items():
                                print(f"      {k}: {v}")
                        else:
                            print(f"  - {test}: {result}")

            """ 
            Before exporting test results to json, file permissions needs to be fixed

            if filename_json is not None:
                os.makedirs("output/scan_results", exist_ok=True)
                timestamp = datetime.now().strftime("[%Y-%m-%d_%H-%M]")
                export_path = f"output/scan_results/{timestamp}_{filename_json}.json"

                export_data = {'Access Points': []}

                for ap in tested_aps:
                    export_data['Access Points'].append({
                        'ESSID': ap.essid,
                        'BSSID': ap.bssid,
                        'Channel': helper.format_array(ap.channels),
                        'Encryption': ap.encryption_mode,
                        'Active Results': ap.test_results if hasattr(ap, 'test_results') else {}
                    })
                    
                helper.append_json(export_path, export_data)
                print(f"\n[*] Results successfully saved to: {export_path}") """

    except Exception as e:
        print(f"\nRuntime Error: {e}")
        exit(1)
    finally:
        # Guarantee interface state reset
        setup.set_managed(interface_name, phy_index)