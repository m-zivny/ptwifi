"""
helpers/interface_setup.py
Author: Martin Živný

Description
-----------
This module provides helper functions for querying and configuring wireless
network interfaces used by the PTWiFi tool.

It retrieves information about available wireless interfaces, checks their
capabilities, and switches interfaces between managed and monitor mode using
Linux networking utilities.

Responsibilities
----------------
- Query wireless interface information
- Validate interface capabilities
- Manage interface modes
- Configure wireless parameters
- Integrate with system networking tools

Dependencies
------------
* helpers.helper_functions  - Utility functions for string formatting and processing.
* helpers.classes           - Definitions of interface modes and terminal output styles.

External Tools
--------------
* iw            - Queries wireless interface information and changes interface type.
* ip            - Brings network interfaces up and down.
* nmcli         - NetworkManager interface management and discovery.
* systemctl     - Restarts wpa_supplicant when restoring managed mode.
"""

from helpers.helper_functions import *
from helpers.classes import *

# suppress subprocess output to command line
stdout = subprocess.DEVNULL

def wireless_interface_exists(interface_name: str) -> bool:
    # Check whether the specified wireless interface exists in the system.
    # The function queries interface information using the "iw" utility.
    try:
        _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr = subprocess.DEVNULL)
        if _interface_status.__contains__("wiphy"):
            return True
        return False
    except subprocess.CalledProcessError:
        return False

def interface_in_mode(interface_name: str, mode: str) -> bool:
    # Check whether the interface currently operates in the specified mode (e.g. managed or monitor).
    _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr=subprocess.DEVNULL)

    for line in _interface_status.splitlines():
        if f"type {mode}" in line:
            return True
    return False

def get_interface_channel(interface_name: str) -> int:
    # Retrieve the currently configured WiFi channel of the interface.
    _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr=subprocess.DEVNULL)
    for line in _interface_status.splitlines():
        if f"channel " in line:
            line = line.split(" ")
            return int(line[1])
    return 0

def get_phy_index(interface_name: str)-> str:
    # Retrieve the PHY index associated with the wireless interface.
    _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True,
                                               stderr=subprocess.DEVNULL)
    for line in _interface_status.splitlines():
        if "wiphy" in line:
            phy_index = line.split()[-1]
            return phy_index
    return ""

def interface_supports_monitor(interface_name: str) -> bool:
    # Check whether the interface supports monitor mode.
    # Monitor mode capability is listed in the PHY information.
    phy_index = get_phy_index(interface_name)
    _interface_info = subprocess.check_output(["iw", f"phy{phy_index}", "info"], text=True, stderr = subprocess.DEVNULL)
    _start = None
    _end = None
    for line in _interface_info.splitlines():
        if "Supported interface modes" in line:
            _start = _interface_info.splitlines().index(line)
        if "Band" in line:
            _end = _interface_info.splitlines().index(line)

    if _start is None or _end is None:
        return False

    _interface_modes = _interface_info.splitlines()[_start+1 : _end]
    for mode in _interface_modes:
        _index = _interface_modes.index(mode)
        _interface_modes[_index] = mode[5:]

    if "monitor" not in _interface_modes:
        return False
    return True

def get_wireless_interfaces():
    # Retrieve wireless interfaces detected by NetworkManager.
    _interface_list = subprocess.check_output(["nmcli", "device"], text=True).splitlines()[1:]
    for _interface in _interface_list:
        _index = _interface_list.index(_interface)
        _interface_list[_index] = strip_whitespaces(_interface)
    return _interface_list

def get_interface_product(interface_name: str) -> list:
    # Retrieve the hardware product name of the specified interface.
    _interface_info = strip_whitespaces(subprocess.check_output(["nmcli", "-f", "GENERAL.PRODUCT", "device", "show", interface_name], text=True))
    return _interface_info[1:len(_interface_info)-1]



def set_channel(interface_name: str, channel_num: str) -> bool:
    # Set the wireless interface to the specified channel.
    channel_num = int(channel_num)
    if channel_num > 13 or channel_num < 1:
        print("Channel number out of range.")
        return False
    else:
        subprocess.check_call(["iw", "dev", interface_name, "set", "channel", str(channel_num)])
        return True

def set_managed(interface_name: str, phy_index: str) -> bool:
    # Restore the interface to managed mode.
    # The interface must be deleted and recreated because monitor interfaces
    # cannot be directly converted back to managed mode.
    subprocess.check_output(["ip", "link", "set", interface_name, "down"])
    subprocess.check_output(["iw", "dev", interface_name, "del"])
    interface_name = interface_name[0:len(interface_name)-3]
    subprocess.check_output(["iw", "phy", f"phy{phy_index}", "interface", "add", interface_name, "type", "managed"])
    subprocess.check_output(["ip", "link", "set", interface_name, "up"])
    subprocess.check_output(["systemctl", "start", f"wpa_supplicant@{interface_name}"])
    subprocess.check_output(["nmcli", "device", "set", interface_name, "managed", "yes"])

    if interface_in_mode(interface_name, InterfaceModes.managed):
        print(
            f"Interface {Style.bold}{interface_name}{Style.reset} has been set to {Style.bold}{InterfaceModes.managed}{Style.reset} mode."
        )
        return True
    return False

def set_monitor(interface_name: str, phy_index: str)-> bool:
    # Switch the interface to monitor mode.
    # The interface is recreated with the monitor type and a "mon" suffix.
    subprocess.check_output(["nmcli", "device", "set", interface_name, "managed", "no"])
    subprocess.check_output(["ip", "link", "set", interface_name, "down"])
    subprocess.check_output(["iw", "dev", interface_name, "del"])
    subprocess.check_output(["iw","phy", f"phy{phy_index}", "interface", "add", f"{interface_name}mon", "type", "monitor"])
    interface_name = f"{interface_name}mon"
    subprocess.check_call(["ip", "link", "set", interface_name, "up"])

    if interface_in_mode(interface_name, InterfaceModes.monitor):
        print(
            f"Interface {Style.bold}{interface_name}{Style.reset} has been set to {Style.bold}{InterfaceModes.monitor}{Style.reset} mode."
        )
        return True
    return False
