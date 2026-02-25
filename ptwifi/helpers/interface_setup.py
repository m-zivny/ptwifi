from helpers.helper_functions import *
from helpers.classes import *
stdout = subprocess.DEVNULL

"""
###########################################
            INFO GETTERS
###########################################
"""
def wireless_interface_exists(interface_name: str) -> bool:
    try:
        _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr = subprocess.DEVNULL)
        if _interface_status.__contains__("wiphy"):
            return True
        return False
    except subprocess.CalledProcessError:
        return False

def interface_in_mode(interface_name: str, mode: str) -> bool:
    _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr=subprocess.DEVNULL)

    for line in _interface_status.splitlines():
        if f"type {mode}" in line:
            return True
    return False

def get_interface_channel(interface_name: str) -> int:
    _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True, stderr=subprocess.DEVNULL)
    for line in _interface_status.splitlines():
        if f"channel " in line:
            line = line.split(" ")
            return int(line[1])
    return 0

def get_phy_index(interface_name: str)-> str:
    _interface_status = subprocess.check_output(["iw", "dev", interface_name, "info"], text=True,
                                               stderr=subprocess.DEVNULL)
    for line in _interface_status.splitlines():
        if "wiphy" in line:
            phy_index = line.split()[-1]
            return phy_index
    return ""

def interface_supports_monitor(interface_name: str) -> bool:
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
    _interface_list = subprocess.check_output(["nmcli", "device"], text=True).splitlines()[1:]
    for _interface in _interface_list:
        _index = _interface_list.index(_interface)
        _interface_list[_index] = strip_whitespaces(_interface)
    return _interface_list

def get_interface_product(interface_name: str) -> list:
    _interface_info = strip_whitespaces(subprocess.check_output(["nmcli", "-f", "GENERAL.PRODUCT", "device", "show", interface_name], text=True))
    return _interface_info[1:len(_interface_info)-1]

"""
###########################################
            SETTERS
###########################################
"""

def set_channel(interface_name: str, channel_num: str) -> bool:
    channel_num = int(channel_num)
    if channel_num > 13 or channel_num < 1:
        print("Channel number out of range.")
        return False
    else:
        subprocess.check_call(["iw", "dev", interface_name, "set", "channel", str(channel_num)])
        return True

def set_managed(interface_name: str, phy_index: str) -> bool:
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
