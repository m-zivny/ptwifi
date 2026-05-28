"""
helpers/helper_functions.py
Author: Martin Živný

Description
-----------
This module provides helper functions used across the ptwifi tool.

It contains utility routines for formatting terminal output, processing
strings and arrays, exporting scan results, estimating distance from
signal strength, and resolving vendor information from MAC addresses.

Responsibilities
----------------
- Provide utility functions used across ptwifi modules
- Format and align terminal output
- Process and normalize strings and arrays
- Estimate approximate distance from RSSI values
- Resolve vendor information from MAC addresses
- Export scan results to JSON format
"""

import os
import re
import subprocess
import pandas as pd
import numpy as np
import json


def visible_len(s: str) -> int:
    """
    Calculates the visible string length, excluding ANSI escape sequences.

    Args:
        s (str): The string to evaluate.

    Returns:
        int: The visible length of the string.
    """
    return len(re.sub(r'\x1b\[[0-9;]*m', '', s))

def pad_ansi(s: str, width: int) -> str:
    """
    Pads a string to the required width while preserving ANSI formatting.

    Args:
        s (str): The string to pad.
        width (int): The desired total width.

    Returns:
        str: The padded string.
    """
    return s + ' ' * (width - visible_len(s))

def print_ap_header() -> None:
    """
    Prints the formatted table header used for Access Point output.
    """
    from helpers.classes import PRINT_WIDTH 
    print(
        f"{'ESSID':<{PRINT_WIDTH['essid']}}"
        f"{'BSSID':<{PRINT_WIDTH['bssid']}}"
        f"{'Channel':<{PRINT_WIDTH['channel']}}"
        f"{'Power':<{PRINT_WIDTH['signal_strength']}}"
        f"{'Encryption':<{PRINT_WIDTH['encryption']}}"
        f"{'Cipher':<{PRINT_WIDTH['cipher']}}"
        f"{'Auth':<{PRINT_WIDTH['auth']}}"
        f"{'Beacons':<{PRINT_WIDTH['beacons']}}"
        f"{'Data Frames':<{PRINT_WIDTH['data_frames']}}"
        f"{'Vendor':<{PRINT_WIDTH['vendor']}}"
        f"{'Approx. distance [m]':<{PRINT_WIDTH['distance']}}"
    )

def print_station_header() -> None:
    """
    Prints the formatted table header used for station output.
    """
    from helpers.classes import PRINT_WIDTH 
    print(
        f"{'Station MAC':<{PRINT_WIDTH['station_mac']}}"
        f"{'Connected BSSID':<{PRINT_WIDTH['connected_bssid']}}"
        f"{'Data Frames':<{PRINT_WIDTH['sta_data_frames']}}"
        f"{'Last Probed':<{PRINT_WIDTH['last_probed']}}"
    )

def format_color_strength(strength: int) -> str:
    """
    Formats the RSSI value using predefined color categories.

    Args:
        strength (int): The RSSI value in dBm.

    Returns:
        str: The ANSI color-formatted string representing the signal strength.
    """
    from helpers.classes import StrengthColors 
    sc = StrengthColors()
    if strength >= -5:
        return "?"
    if strength > 0:
        return "?"

    if strength >= -30:
        end_format = sc.EXCELLENT
    elif strength >= -50:
        end_format  = sc.GREAT
    elif strength >= -60:
        end_format = sc.VERY_GOOD
    elif strength >= -67:
        end_format = sc.GOOD
    elif strength >= -70:
        end_format = sc.RELIABLE
    elif strength >= -80:
        end_format = sc.UNRELIABLE
    else:
        end_format = sc.POOR

    return sc.BOLD + end_format[0] + end_format[1] +" (" + str(strength) + ")" + sc.RESET


def is_sudo() -> bool:
    """
    Checks whether the script is running with sudo (root) privileges.

    Returns:
        bool: True if running as root, False otherwise.
    """
    if os.getuid() == 0:
        return True
    else:
        return False

def is_file_open(filepath: str) -> bool:
    """
    Checks whether the specified file is currently opened by any process.

    Args:
        filepath (str): The absolute or relative path to the file.

    Returns:
        bool: True if the file is open, False otherwise.
    """
    result = subprocess.run(['lsof', filepath], capture_output=True, text=True)
    return bool(result.stdout.strip())

def find_vendor(bssid: str) -> str:
    """
    Resolves the device vendor using the OUI prefix of the BSSID from a local CSV database.

    Args:
        bssid (str): The MAC address to resolve.

    Returns:
        str: The full vendor name, or "Unknown" if not found.
    """
    vendors = pd.read_csv("helpers/manuf.csv", sep=';')
    vendors['oui'] = vendors['oui'].str.replace(' ',  '')
    vendors['vendor'] = vendors['vendor'].str.replace(' ', '')
    try:
        return vendors['vendor_full'][vendors['oui'] == bssid[0:8].upper()].item()
    except ValueError:
        return "Unknown"

def format_array(raw_list: list) -> str:
    """
    Converts a list of values into a comma-separated string.

    Args:
        raw_list (list): The list of items to format.

    Returns:
        str: The formatted comma-separated string.
    """
    formatted_string_array = ""
    for item in raw_list:
        if raw_list.index(item) != raw_list.index(raw_list[-1]):
            formatted_string_array += str(item) + ","
        else:
            formatted_string_array += str(item)
    return formatted_string_array

def get_frequency_from_channel(channel: int) -> float:
    """
    Calculates the center frequency based on the Wi-Fi channel number.

    Args:
        channel (int): The operational Wi-Fi channel.

    Returns:
        float: The corresponding frequency in MHz, or 0.0 if invalid.
    """
    if channel in range(1, 14):
        return 2412 + 5 * (channel - 1)
    elif channel in range(36, 65):
        return 5180 + 5 * (channel - 36)
    elif channel in range(100, 141):
        return 5500 + 5 * (channel - 100)
    elif 149 <= channel <= 165 and channel % 4 == 0:
        return 5745.0 + 5 * (channel - 149)
    else:
        return 0.0

def get_channel_from_frequency(frequency: int) -> int:
    """
    Determines the Wi-Fi channel number from a given center frequency.

    Args:
        frequency (int): The center frequency in MHz.

    Returns:
        int: The corresponding Wi-Fi channel, or 0 if out of bounds.
    """
    if 2412.0 <= frequency <= 2472.0:
        return int((frequency - 2412) // 5 + 1)
    elif frequency == 2484.0:
        return 14
    elif 5180.0 <= frequency <= 5320.0:
        return int((frequency - 5180) // 5 + 36)
    elif 5500.0 <= frequency <= 5720.0:
        return int((frequency - 5500) // 5 + 100)
    elif 5745.0 <= frequency <= 5825.0:
        return int((frequency - 5745) // 5 + 149)
    else:
        return 0

def calculate_approx_distance(rssi: float, channel: int) -> float:
    """
    Estimates the approximate distance from the source using the Log-Distance Path Loss model.

    Args:
        rssi (float): The Received Signal Strength Indicator (RSSI) in dBm.
        channel (int): The operational channel.

    Returns:
        float: The estimated distance in meters, rounded to two decimal places.
    """
    DEFAULT_AP_POWER = 20.0
    PATH_LOSS_EXPONENT = 4.0 

    frequency = get_frequency_from_channel(channel)

    l_1m = 20 * np.log10(frequency) - 27.55
    exponent = (DEFAULT_AP_POWER - rssi - l_1m) / (10 * PATH_LOSS_EXPONENT)
    distance = np.power(10, exponent)
    
    return round(distance, 2)


def strip_whitespaces(input_string: str) -> list[str]:
    """
    Strips leading/trailing whitespaces and splits the string by multiple spaces.

    Args:
        input_string (str): The raw input string.

    Returns:
        list[str]: A list of clean string segments.
    """
    return input_string.strip().split()

def merge_list_to_string(string_list: list[str]) -> str:
    """
    Merges a list of strings into a single space-separated string.

    Args:
        string_list (list[str]): The list of strings to merge.

    Returns:
        str: The combined string.
    """
    return " ".join(string_list)

def append_json(filename: str, new_object: dict) -> None:
    """
    Appends a new JSON object to an array stored in a file.
    Creates the file if it does not exist.

    Args:
        filename (str): The path to the JSON file.
        new_object (dict): The dictionary object to append.
    """
    if not os.path.exists(filename):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump([], f)

    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    data.append(new_object)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def import_ap_from_json(filename: str) -> list['AP'] | None:
    """
    Loads a list of Access Points from a JSON file and parses them into AP objects.

    Args:
        filename (str): The base name of the JSON file located in the 'input' directory.

    Returns:
        list['AP'] | None: A list of instantiated AP objects, or None if parsing fails.
    """
    from helpers.classes import AP    

    file_path = f"input/{filename}.json"
    if not os.path.exists(file_path):
        return None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return None

    ap_objects = []
    imported_aps = data.get("ap_list", [])

    for ap_data in imported_aps:
        _essid = ap_data.get("essid")
        print(_essid)
        _bssid = ap_data.get("bssid")
        _channel = int(ap_data.get("channel"))
        _signal_strength  = ap_data.get("signal_strength")
        _encryption = ap_data.get("encryption")
        _cipher = ap_data.get("cipher")
        _authentication = ap_data.get("authentication")
        _beacons = int(ap_data.get("beacons"))
        _data_frames = int(ap_data.get("data_frames"))
        _associated_stas = ap_data.get("associated_stas")
        _observed_ds = ap_data.get("observed_ds_states")
        
        ap_obj = AP(
            essid=_essid,
            bssid=_bssid,
            channel=_channel,
            encryption_mode=_encryption,
            signal_strength=_signal_strength,
            beacon_frames_num=_beacons,
            data_frames_num=_data_frames,
            cipher=_cipher,
            auth_method=_authentication
        )
        
        for sta in _associated_stas.split(","):
            ap_obj.add_associated_sta(sta)
        ap_objects.append(ap_obj)

        for state in _observed_ds.split(","):
            ap_obj.observed_ds_states.add(state)

    return ap_objects


def import_sta_from_json(filename: str)->list['Station']:
    from helpers.classes import Station

    file_path = f"input/{filename}.json"
    if not os.path.exists(file_path):
        return None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return None

    sta_objects = []
    imported_stas = data.get("sta_list", [])

    for sta_data in imported_stas:
        _mac = sta_data.get("mac")
        _con_bssid = sta_data.get("connected_bssid")
        _data_frames = sta_data.get("data_frames_num")
        _observed_ds = sta_data.get("observed_ds_states")
        _sent_arps = sta_data.get("arped_IPs")
        
        sta_obj = Station(
            _mac,
            _con_bssid,
            "",
            _data_frames
        )
        for observed_state in _observed_ds.split(","):
            sta_obj.observed_ds_states.add(observed_state)

        for sent_arp in _sent_arps.split(","):
            sta_obj.sent_arps.add(sent_arp)

        sta_objects.append(sta_obj)
    
    return sta_objects    



def is_multicast(mac: str) -> bool:
    """
    Checks whether the provided MAC address is a multicast address.

    Args:
        mac (str): The MAC address to evaluate.

    Returns:
        bool: True if the I/G bit is set, False otherwise.
    """
    return int(mac[:2], 16) & 1