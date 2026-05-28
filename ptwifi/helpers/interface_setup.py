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

import subprocess
from helpers.helper_functions import strip_whitespaces
from helpers.classes import Style, channels_2g, channels_5g

# Suppress subprocess output to command line
stdout = subprocess.DEVNULL

def wireless_interface_exists(interface_name: str) -> bool:
    """
    Checks whether the specified wireless interface exists in the system.

    Args:
        interface_name (str): The name of the interface.

    Returns:
        bool: True if the interface exists, False otherwise.
    """
    try:
        _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr=subprocess.DEVNULL)
        if _interface_status.__contains__("wiphy"):
            return True
        return False
    except subprocess.CalledProcessError:
        return False

def interface_in_mode(interface_name: str, mode: str) -> bool:
    """
    Checks whether the interface currently operates in the specified mode.

    Args:
        interface_name (str): The name of the interface.
        mode (str): The target mode (e.g., "managed", "monitor").

    Returns:
        bool: True if the interface is in the specified mode, False otherwise.
    """
    _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr=subprocess.DEVNULL)

    for line in _interface_status.splitlines():
        if f"type {mode}" in line:
            return True
    return False

def get_phy_index(interface_name: str) -> str:
    """
    Retrieves the PHY index associated with the wireless interface.

    Args:
        interface_name (str): The name of the interface.

    Returns:
        str: The PHY index as a string, or an empty string if not found.
    """
    _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr=subprocess.DEVNULL)
    for line in _interface_status.splitlines():
        if "wiphy" in line:
            phy_index = line.split()[-1]
            return phy_index
    return ""

def interface_supports_monitor(interface_name: str) -> bool:
    """
    Checks whether the interface supports monitor mode by querying PHY capabilities.

    Args:
        interface_name (str): The name of the interface.

    Returns:
        bool: True if monitor mode is supported, False otherwise.
    """
    phy_index = get_phy_index(interface_name)
    _interface_info = subprocess.check_output(["iw", f"phy{phy_index}", "info"], text=True, stderr=subprocess.DEVNULL)
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

def get_wireless_interfaces() -> list[list[str]]:
    """
    Retrieves a list of wireless interfaces detected by NetworkManager.

    Returns:
        list[list[str]]: A list of parsed interface details.
    """
    _interface_list = subprocess.check_output(["nmcli", "device"], text=True).splitlines()[1:]
    for _interface in _interface_list:
        _index = _interface_list.index(_interface)
        _interface_list[_index] = strip_whitespaces(_interface)
    return _interface_list

def get_interface_product(interface_name: str) -> str:
    """
    Retrieves the hardware product name of the specified interface via NetworkManager.

    Args:
        interface_name (str): The name of the interface.

    Returns:
        str: The joined string representing the hardware product name.
    """
    _interface_info = strip_whitespaces(subprocess.check_output(["nmcli", "-f", "GENERAL.PRODUCT", "device", "show", interface_name], text=True))
    return " ".join(_interface_info[1:len(_interface_info)-1])

def set_channel(interface_name: str, channel_num: str) -> bool:
    """
    Sets the wireless interface to the specified operational channel.

    Args:
        interface_name (str): The name of the interface.
        channel_num (str): The desired channel number.

    Returns:
        bool: True if successful, False if the channel is out of valid ranges.
    """
    channel_num = int(channel_num)
    if channel_num in channels_2g or channel_num in channels_5g:
        subprocess.check_call(["iw", "dev", interface_name, "set", "channel", str(channel_num)])
        return True
    else:
        print("Channel number out of range.")
        return False
        
def set_managed(interface_name: str, phy_index: str) -> bool:
    """
    Restores the interface to managed mode. Deletes the monitor interface and recreates it.

    Args:
        interface_name (str): The name of the interface (currently in monitor mode).
        phy_index (str): The PHY index of the interface.

    Returns:
        bool: True if successfully set to managed mode, False otherwise.
    """
    subprocess.check_output(["ip", "link", "set", interface_name, "down"])
    subprocess.check_output(["iw", "dev", interface_name, "del"])
    interface_name = interface_name[0:len(interface_name)-3]
    subprocess.check_output(["iw", "phy", f"phy{phy_index}", "interface", "add", interface_name, "type", "managed"])
    subprocess.check_output(["ip", "link", "set", interface_name, "up"])
    subprocess.check_output(["systemctl", "start", f"wpa_supplicant@{interface_name}"])
    subprocess.check_output(["nmcli", "device", "set", interface_name, "managed", "yes"])

    if interface_in_mode(interface_name, "managed"):
        print(
            f"Interface {Style.BOLD}{interface_name}{Style.RESET} has been set to {Style.BOLD}managed{Style.RESET} mode."
        )
        return True
    return False

def set_monitor(interface_name: str, phy_index: str) -> bool:
    """
    Switches the interface to monitor mode. Recreates the interface with a 'mon' suffix.

    Args:
        interface_name (str): The name of the current managed interface.
        phy_index (str): The PHY index of the interface.

    Returns:
        bool: True if successfully set to monitor mode, False otherwise.
    """
    subprocess.check_output(["nmcli", "device", "set", interface_name, "managed", "no"])
    subprocess.check_output(["ip", "link", "set", interface_name, "down"])
    subprocess.check_output(["iw", "dev", interface_name, "del"])
    subprocess.check_output(["iw","phy", f"phy{phy_index}", "interface", "add", f"{interface_name}mon", "type", "monitor"])
    interface_name = f"{interface_name}mon"
    subprocess.check_call(["ip", "link", "set", interface_name, "up"])

    if interface_in_mode(interface_name, "monitor"):
        print(
            f"Interface {Style.BOLD}{interface_name}{Style.RESET} has been set to {Style.BOLD}monitor{Style.RESET} mode."
        )
        return True
    return False