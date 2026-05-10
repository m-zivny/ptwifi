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

from helpers.classes import *

def visible_len(s: str) -> int:
    # Return the visible string length without ANSI escape sequences.
    return len(re.sub(r'\x1b\[[0-9;]*m', '', s))

def pad_ansi(s: str, width: int) -> str:
    # Pad a string to the required width while preserving ANSI formatting.
    return s + ' ' * (width - visible_len(s))

def print_ap_header() -> None:
    # Print the formatted table header used for Access Point output.
    print(
        f"{'ESSID':<35}"
        f"{'BSSID':<20}"
        f"{'Channels':<10}"
        f"{'Power':<20}"
        f"{'Encryption':<15}"
        f"{'Cipher':<10}"
        f"{'Auth':<10}"
        f"{'Beacons':<10}"
        f"{'Data Frames':<20}"
        f"{'Vendor':<40}"
        f"{'Approx. distance [m]':<10}"
    )

def print_station_header() -> None:
    # Print the formatted table header used for station output.
    print(
        f"{'Station MAC':<20}"
        f"{'Connected BSSID':<20}"
        f"{'Data Frames':<20}"
        f"{'Last Probed':<20}"
    )


def format_color_strength(strength: int) -> str:
    # Format RSSI value using predefined color categories.
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
    # Check whether the script is running with sudo (root) privileges.
    if os.getuid() == 0:
        return True
    else:
        return False

def is_file_open(filepath):
    # Check whether the specified file is currently opened by any process.
    result = subprocess.run(['lsof', filepath], capture_output=True, text=True)
    return bool(result.stdout.strip())

def find_vendor(bssid: str) -> str:
    # Resolve the device vendor using the OUI prefix of the BSSID.
    vendors = pd.read_csv("helpers/manuf.csv", sep=';')
    vendors['oui'] = vendors['oui'].str.replace(' ',  '')
    vendors['vendor'] = vendors['vendor'].str.replace(' ', '')
    try:
        return vendors['vendor_full'][vendors['oui'] == bssid[0:8].upper()].item()
    except ValueError:
        return "Unknown"

def format_array(raw_list : list) -> str:
    # Convert a list of values into a comma-separated string.
    formatted_string_array = ""
    for item in raw_list:
        if raw_list.index(item) != raw_list.index(raw_list[-1]):
            formatted_string_array += str(item) + ","
        else:
            formatted_string_array += str(item)
    return formatted_string_array


def calculate_approx_distance(rssi: float, channel: int) -> float:
    # Estimate approximate distance from RSSI and channel frequency using the Log-Distance Path Loss model.
    DEFAULT_AP_POWER = 20.0
    PATH_LOSS_EXPONENT = 4.0 

    if channel in range(1, 14):
        frequency = 2412 + 5 * (channel - 1)
    elif channel in range(36, 65):
        frequency = 5180 + 5 * (channel - 36)
    elif channel in range(100, 141):
        frequency = 5500 + 5 * (channel - 100)
    else:
        return 0.0

    l_1m = 20 * np.log10(frequency) - 27.55
    exponent = (DEFAULT_AP_POWER - rssi - l_1m) / (10 * PATH_LOSS_EXPONENT)
    distance = np.power(10, exponent)
    
    return round(distance, 2)


def strip_whitespaces(input_string: str) -> list:
    # Automatically handles multiple spaces and leading/trailing whitespace
    return input_string.strip().split()

def merge_list_to_string(string_list: list) -> str:
    return " ".join(string_list)

def append_json(filename, new_object):
    # Append a new object to a JSON array stored in a file.
    # Create the JSON file with an empty array if it does not exist yet.
    if not os.path.exists(filename):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump([], f)

    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    data.append(new_object)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)