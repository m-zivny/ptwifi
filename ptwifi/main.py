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
"""

import argparse
import time

from modules import decision
from helpers import interface_setup as setup
from helpers.classes import StrengthColors as Sc
from modules import active_scan, passive_scan, deauth_attack
from helpers import helper_functions as helper

if __name__ == '__main__':
    interface_name = None
    phy_index = None
    interface_in_monitor = False
    
    try: 
        # PARSER INIT FOR COMMAND LINE ARGUMENTS
        parser = argparse.ArgumentParser()
        parser.add_argument('interface', type=str, help='Name of the wireless interface to be used, must support at least monitor mode.')
        parser.add_argument('modes', type=str, nargs='+', help='Tool modes to be executed sequentially. Example: "passive active deauth decision"')
        parser.add_argument('--channel', '-c', type=str, help="Channel to be worked in.")
        parser.add_argument('--BSSID', '-b', type=str, help="BSSID (MAC Address) of the targeted AP.")
        parser.add_argument('--time_period', '-t', type=int, help="Time period between deauth packets in ms, 0.05 ms is default.")
        parser.add_argument('--number', '-n', metavar="<number", type=int, help="Number of deauth packets to be sent.")
        parser.add_argument('--sta_off', action="store_false", help="Turn off showing STA.")
        parser.add_argument('--hidden_off', action="store_false", help="Turn off showing APs with hidden SSID.")
        parser.add_argument('--exportf', metavar="<filename>", type=str, help="Name of the json file to output.")
        parser.add_argument('--importf', metavar="<filename>", type=str, help="Name of the json file to input.")

        
        args = parser.parse_args()
        interface_name = args.interface
        
        raw_modes = " ".join(args.modes).lower()
        tool_modes = raw_modes.split()

        target_channels = args.channel
        if target_channels is not None:
            target_channels = target_channels.split(',')

        target_bssid = args.BSSID
        time_period_ms = args.time_period
        packet_count = args.number
        sta_filter = args.sta_off if args.sta_off is not None else True
        hidden_filter = args.hidden_off if args.hidden_off is not None else True
        export_filename = args.exportf
        import_filename = args.importf

        if not helper.is_sudo():
            print("Script needs to be run with sudo privileges.")
            exit(0)

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

        if not setup.interface_in_mode(interface_name, "monitor") and "managed" not in tool_modes:
            setup.set_monitor(interface_name, phy_index)
            interface_name = f"{interface_name}mon"
        interface_in_monitor = True

        if target_channels:
            setup.set_channel(interface_name,target_channels[0])


        if import_filename is not None:

            imported_aps = helper.import_ap_from_json(import_filename)
            imported_stas = helper.import_sta_from_json(import_filename)

            if imported_aps is None or len(imported_aps) == 0:
                print(f"{Sc.BOLD}[!] AP import failed - none or corrupted data. Check file.{Sc.RESET}")
                discovered_aps = []
            else:
                discovered_aps = imported_aps
            
            if  imported_stas is None or len(imported_stas) == 0:
                print(f"{Sc.BOLD}[!] Station import failed - none or corrupted data. Check file.{Sc.RESET}")
                discovered_aps = []
            else:
                discovered_stas = imported_stas
        else:
            discovered_aps = []


        # 1. PASSIVE SCAN PHASE
        if "passive" in tool_modes:
            print(f"\n{Sc.BOLD}[*] PHASE: PASSIVE SCAN{Sc.RESET}")
            print("Stop the scan using Ctrl+C to proceed to the next phase.")
            time.sleep(5)
            discovered_aps, discovered_stas = passive_scan.run(
                interface_name, 
                filename_json=export_filename, 
                channels_to_hop=target_channels,
                sta_filter=sta_filter,
                hidden_filter=hidden_filter
            )

        # 2. ACTIVE SCAN PHASE
        if "active" in tool_modes and discovered_aps:
            print(f"\n{Sc.BOLD}[*] PHASE: ACTIVE SCAN{Sc.RESET}")
            for ap in discovered_aps:
                if target_bssid and ap.bssid.upper() != target_bssid.upper():
                    continue
                if ap.channel:
                    setup.set_channel(interface_name, str(ap.channel))                

                active_scan.run(interface_name, ap)

        # 3. DEAUTH ATTACK PHASE (802.11w Test)
        if "deauth" in tool_modes:
            if discovered_aps:
                print(f"\n{Sc.BOLD}[*] PHASE: DEAUTH ATTACK{Sc.RESET}")
                for ap in discovered_aps:
                    if target_bssid and ap.bssid.upper() != target_bssid.upper():
                        continue    
                    
                    setup.set_channel(interface_name, str(ap.channel))
                    
                    deauth_attack.run(interface_name, ap, time_period_ms, packet_count)
            else:
                print(f"\n{Sc.BOLD}[-] DEAUTH ATTACK aborted.{Sc.RESET}")
                print("No Access Points were discovered during the passive scan.")

        if "decision" in tool_modes:
            decision.run(discovered_aps, discovered_stas)

    except KeyboardInterrupt:
        print("Test canceled by user.")
    except Exception as e:
        print(e)
    finally:
        if interface_in_monitor and "monitor" not in tool_modes:
            setup.set_managed(interface_name, phy_index)
        else:
            exit(0)