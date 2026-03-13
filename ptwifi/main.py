"""
main.py
Author: Martin Živný

Description
-----------
This script serves as the main entry point of the "ptwifi" tool. It handles
command-line argument parsing, validates runtime conditions, prepares the
wireless interface for operation, and executes the selected analysis module.

The script ensures that the selected wireless interface supports monitor mode,
switches the interface into monitor mode if necessary, optionally sets the
requested WiFi channel, and executes the right module.

Responsibilities
---------------
- Parse and validate command-line arguments
- Verify privileges for running dependent tools
- Check availability  of the specified wireless interface
- Enable monitor mode on the interface
- Set the working WiFi channel if specified
- Execute the selected tool mode (passive scan, active scan, or deauthentication)
- Restore the wireless interface back to managed mode after execution

Supported Modes
---------------
* passive   - Launches passive WiFi scanning implemented in modules.passive_scan.
* active    - Launches active WiFi scanning implemented in modules.active_scan.
* deauth    - Launches a deauthentication test implemented in modules.deauth_attack.

Inputs
------

mandatory arguments

* interface - Name of the wireless interface to be used.
* mode      - Operational mode of the tool (passive | active | deauth).

optional arguments

* channel (-c)          - Specifies the Wi-Fi channel(s) to operate on.
* BSSID (-b)            - BSSID (MAC address) of the target Access Point.
* MAC (-a)              - MAC address of the target client station.
* time_period (-t)      - Interval in milliseconds between deauthentication packets.
* number (-n)           - Total number of deauthentication packets to send (-1 means indefinitely).
* burst_number (-bn)    - Number of deauthentication packets sent in a single burst.
* sta_off               - Disables displaying detected client stations during passive scanning.
* hidden_off            - Disables displaying Access Points with hidden SSIDs during passive scanning.
* json                  - Name of the JSON file where scan results will be saved.

"""

import argparse

from helpers import interface_setup as setup
from helpers.classes import PTModes, InterfaceModes
from helpers.classes import StrengthColors as Sc
from modules import active_scan, passive_scan, deauth_attack
from helpers import helper_functions as helper

known_pt_modes = [_mode for _mode in dir(PTModes) if not _mode.startswith("__")]

if __name__ == '__main__':

    # Prepare parser for user-defined arguments. Describe every argument by help parameter.
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', type=str, help='Name of the wireless interface to be used may support atleast monitor mode.')
    parser.add_argument('mode', type=str, help='Tool mode to be executed. Possible values: passive|active|deauth')
    parser.add_argument('--channel', '-c', type=str, help="Channel to be worked in.")
    parser.add_argument('--BSSID', '-b', type=str, help="BSSID (MAC Address) of the targeted AP.")
    parser.add_argument('--MAC', '-a', type=str, help="MAC Address of the targeted STA.")
    parser.add_argument('--time_period', '-t', type=int, help="Time period between deauth packets in ms, 500 ms is default.")
    parser.add_argument('--number', '-n', type=int, help="Number of deauth packets to be sent. -1 is default, means indefinitely.")
    parser.add_argument('--burst_number', '-bn', type=int, help="Number of deauth packets to be sent at once. 1 is default")
    parser.add_argument('--sta_off', action="store_false", help="Turn off showing STA.")
    parser.add_argument('--hidden_off', action="store_false", help="Turn off showing APs with hidden SSID.")
    parser.add_argument('--json', type=str, help="Name of the json file to output.")

    # Parse user defined arguments
    args = parser.parse_args()
    _interface = args.interface
    _mode = args.mode.lower()

    _channel = args.channel
    if _channel is not None:
        # Check if optional channel argument has been used. If so, make possible to define more channels at once, separated by comma.
        _channel = _channel.split(',')

    _bssid = args.BSSID
    _mac = args.MAC
    _time_period = args.time_period
    _number = args.number
    _burst_number = args.burst_number
    _sta_filter = args.sta_off
    _hidden_filter = args.hidden_off
    _json_name = args.json

    # Show stations by default unless explicitly disabled.
    if _sta_filter is None:
        _sta_filter = True

    # Show hidden SSIDs by default unless explicitly disabled.
    if _hidden_filter is None:
        _hidden_filter = True

    # Validate use of sudo privileges, if not, end run.
    if not helper.is_sudo():
        print("Script needs to be run with sudo privileges.")
        exit(1)

    # Special mode for listing detected wireless interfaces and vendors.
    if _interface == "show" and args.mode == "ifaces":
       print(f"{Sc.bold}Name\t \tVendor{Sc.reset}")
       wireless_interfaces = [[x[0]] for x in setup.get_wireless_interfaces() if x[1] == "wifi"]
       for interface in wireless_interfaces:
           interface.append(helper.merge_list_to_string(setup.get_interface_product(interface[0])))
           print(interface[0] + "\t \t"+ interface[1])
       exit(0)

    # Ensure that defined interface exists.
    if not setup.wireless_interface_exists(_interface):
       print(f"Interface {_interface} not found.")
       exit(1)

    # Ensure that defined interface supports monitor mode.
    if not setup.interface_supports_monitor(_interface):
       print(f"Interface {_interface} does not support monitor mode.")
       exit(1)

    # Enable monitor mode on defined interface.
    phy_index = setup.get_phy_index(_interface)
    if not setup.interface_in_mode(_interface, InterfaceModes.monitor):
        setup.set_monitor(_interface, phy_index)
    _interface = f"{_interface}mon"

    # Set interface channel to first parsed channel if a channel list is provided.
    if _channel is not None:
        setup.set_channel(_interface, _channel[0])

    # Try to execute the requested module after the interface has been prepared.
    try:
        match _mode:
            case "passive":
                if _channel is None:
                    passive_scan.run(_interface, None, _sta_filter, _hidden_filter, _json_name)
                else:
                    passive_scan.run(_interface, _channel[0], _sta_filter, _hidden_filter, _json_name)
            case "active":
                active_scan.run(_interface, _channel, _json_name)
            case "deauth":
                if _bssid is not None:
                    deauth_attack.run(_interface, _bssid, _mac, _time_period, _number, _burst_number)
                else:
                    print("For this attack please define target BSSID.")
            case _:
                print("Unknown mode")

    except Exception as e:
        print(e)
        # Restore the interface to managed mode if module run ends in exception.
        setup.set_managed(_interface, phy_index)
        exit(0)

    # Restore the interface to managed mode before the script exits normally.
    setup.set_managed(_interface, phy_index)
