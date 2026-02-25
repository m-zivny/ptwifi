import os
import re
import subprocess
import pandas as pd
import numpy as np
import json

from helpers.classes import *

def visible_len(s: str) -> int:
    return len(re.sub(r'\x1b\[[0-9;]*m', '', s))
def pad_ansi(s: str, width: int) -> str:
    return s + ' ' * (width - visible_len(s))

def print_ap_header() -> None:
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
    print(
        f"{'Station MAC':<20}"
        f"{'Connected BSSID':<20}"
        f"{'Data Frames':<20}"
        f"{'Last Probed':<20}"
    )


def format_color_strength(strength: int) -> str:
    sc = StrengthColors()
    if strength >= -5:
        return "?"
    if strength > 0:
        return "?"

    if strength >= -30:
        end_format = sc.excellent
    elif strength >= -50:
        end_format  = sc.great
    elif strength >= -60:
        end_format = sc.very_good
    elif strength >= -67:
        end_format = sc.good
    elif strength >= -70:
        end_format = sc.reliable
    elif strength >= -80:
        end_format = sc.unreliable
    else:
        end_format = sc.poor

    return sc.bold + end_format[0] + end_format[1] +" (" + str(strength) + ")" + sc.reset


def is_sudo() -> bool:
    if os.getuid() == 0:
        return True
    else:
        return False

def is_file_open(filepath):
    result = subprocess.run(['lsof', filepath], capture_output=True, text=True)
    return bool(result.stdout.strip())

def find_vendor(bssid: str) -> str:
    vendors = pd.read_csv("helpers/manuf.csv", sep=';')
    vendors['oui'] = vendors['oui'].str.replace(' ',  '')
    vendors['vendor'] = vendors['vendor'].str.replace(' ', '')
    try:
        return vendors['vendor_full'][vendors['oui'] == bssid[0:8].upper()].item()
    except ValueError:
        return "Uknown"

def format_array(raw_list : list) -> str:
    _formatted = ""
    for item in raw_list:
        if raw_list.index(item) != raw_list.index(raw_list[-1]):
            _formatted += str(item) + ","
        else:
            _formatted += str(item)
    return _formatted

def get_approx_dist(power: float, channel: int) -> float:

    _att_constant = -27.56
    _approx_ap_power = 20

    if channel in range(1, 12):
        _freq = 2412 + 5*(channel-1)
    elif channel in range(36, 65):
        _freq = 5180 + 20 * (channel-36) / 4
    elif channel in range(100, 141):
        _freq = 5500 + 20 * (channel - 100) / 4
    else:
        return 0

    _FSPL = _approx_ap_power - power
    return round(np.power(10, (_FSPL - 20 * np.log10(_freq) - _att_constant)/20), 2)

def strip_whitespaces(_list: str) -> list:
    _list = _list.split(" ")
    _filtered_data = []

    for data in _list:
        if data != '':
            _filtered_data.append(data)

    return _filtered_data

def merge_list_to_string(_list :list) -> str:
    _formatted_string = ""
    for data in _list:
        if _list.index(data) != len(_list)-1:
            _formatted_string += data + " "
        else:
            _formatted_string += data
    return _formatted_string

def append_json(file, new_object):
    if not os.path.exists(file):
        with open(file, "w", encoding="utf-8") as f:
            json.dump([], f)

    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)

    data.append(new_object)

    with open(file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)