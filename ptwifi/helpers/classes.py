"""
helpers/classes.py
Author: Martin Živný

Description
-----------
This module defines classes and constants used throughout the ptwifi tool.

It provides data structures for representing detected Access Points and
client stations, as well as utility classes defining program modes,
interface modes, and terminal output formatting.

Responsibilities
----------------
- Define data structures representing Access Points and client stations
- Provide constants describing ptwifi operational modes
- Provide constants describing wireless interface modes
- Define terminal styling utilities used for formatted console output
"""

import helpers.helper_functions as helper

channels_2g = [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10]
channels_5g = [
    36, 40, 44, 48,                                  
    52, 56, 60, 64,                                  
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 
    149, 153, 157, 161, 165                          
]

PRINT_WIDTH = {
    "essid": 30,
    "bssid": 20,
    "channel": 10,
    "signal_strength": 23,
    "encryption": 15,
    "cipher": 20,
    "auth": 10,
    "beacons": 10,
    "data_frames": 13,
    "vendor": 35,
    "distance": 10,
    "station_mac": 20,
    "connected_bssid": 20,
    "sta_data_frames": 20,
    "last_probed": 20
}


class PTModes:
    """Defines available PTWiFi tool modes."""
    ACTIVE = "active"
    PASSIVE = "passive"
    DEAUTH = "deauth"

class Style:
    """Defines terminal text formatting styles used in console output."""
    BOLD = "\033[1m"
    ITALIC = "\033[3m"
    INVERSE = "\033[7m"
    UNDERLINE = "\033[4m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    RESET = "\033[0m"

class StrengthColors:
    """Defines color codes used for displaying signal strength in terminal output."""
    EXCELLENT = ["\033[38;5;46m", "Excellent"]
    GREAT = ["\033[38;5;40m", "Great"]
    VERY_GOOD = ["\033[38;5;190m", "Very good"]
    GOOD = ["\033[38;5;226m", "Good"]
    RELIABLE = ["\033[38;5;214m", "Reliable"]
    UNRELIABLE = ["\033[38;5;202m", "Unreliable"]
    POOR = ["\033[38;5;196m", "Poor"]
    BOLD = "\033[1m"
    RESET = "\033[0m"


class AP:
    """
    Represents a detected wireless Access Point.

    Attributes:
        essid (str): The Extended Service Set Identifier (network name).
        bssid (str): The Basic Service Set Identifier (MAC address).
        channel (int): The operational channel.
        encryption_mode (str): The primary encryption mode.
        signal_strength (int): The RSSI value in dBm.
        beacon_frames_num (int): Total number of captured beacon frames.
        data_frames_num (int): Total number of captured data frames.
        cipher (str): The pairwise/group cipher suite.
        auth_method (str): The authentication method.
        vendor (str): The resolved vendor string based on the BSSID.
        distance (float): The estimated distance in meters.
        observed_ds_states (set[str]): A set of observed Distribution System states.
        associated_STAs (list[str]): A list of MAC addresses of associated clients.
        test_results (dict): A dictionary storing results from active and deauth tests.
    """
    def __init__(self, 
            essid: str, 
            bssid: str,
            channel: int,
            encryption_mode: str = "", 
            signal_strength: int = 0, 
            beacon_frames_num: int = 0, 
            data_frames_num: int = 0,  
            cipher: str = "", 
            auth_method: str = ""
            ) -> None:

        self.essid = essid.strip() if len(essid.strip()) > 0 else "Hidden"
        self.bssid = bssid.strip()
        self.signal_strength = int(signal_strength)

        channel = int(channel)
        if channel > 0:
            self.channel = channel
            self.update_distance()
        else:
            self.channel = 0
            self.distance = 0

        self.encryption_mode = encryption_mode.strip().split(" ")[0]
        self.cipher = cipher.strip()
        self.auth_method = auth_method.strip()

        self.beacon_frames_num = int(beacon_frames_num)
        self.data_frames_num = int(data_frames_num)
        self.vendor = helper.find_vendor(self.bssid)

        self.observed_ds_states: set[str] = set()
        self.associated_STAs = []
        self.test_results = {}

    def print_realtime(self) -> None:
        """
        Prints formatted real-time information about the Access Point to the standard output.
        """
        print(
            helper.pad_ansi(f"{StrengthColors.BOLD}{self.essid}{StrengthColors.RESET}", PRINT_WIDTH["essid"])
            + helper.pad_ansi(self.bssid, PRINT_WIDTH["bssid"])
            + helper.pad_ansi(f"{self.channel}", PRINT_WIDTH["channel"])
            + helper.pad_ansi(helper.format_color_strength(self.signal_strength), PRINT_WIDTH["signal_strength"])
            + helper.pad_ansi(self.encryption_mode, PRINT_WIDTH["encryption"])
            + helper.pad_ansi(self.cipher, PRINT_WIDTH["cipher"])
            + helper.pad_ansi(self.auth_method, PRINT_WIDTH["auth"])
            + helper.pad_ansi(str(self.beacon_frames_num), PRINT_WIDTH["beacons"])
            + helper.pad_ansi(str(self.data_frames_num), PRINT_WIDTH["data_frames"])
            + helper.pad_ansi(str(self.vendor), PRINT_WIDTH["vendor"])
            + helper.pad_ansi(str(self.distance), PRINT_WIDTH["distance"])
        )


    def add_associated_sta(self, mac_address: str) -> None:
        """
        Adds a client station MAC address to the associated list if not already present.

        Args:
            mac_address (str): The MAC address of the client station.
        """
        if mac_address not in self.associated_STAs:
            self.associated_STAs.append(mac_address)
    
    def update_distance(self) -> None:
        """
        Updates the estimated distance based on the current signal strength and channel.
        """
        if self.signal_strength < -10 and self.channel:
                self.distance = helper.calculate_approx_distance(self.signal_strength, self.channel)
        else:
            self.distance = 0
        
class Station:
    """
    Represents a detected wireless client station.

    Attributes:
        mac (str): The MAC address of the station.
        connected_bssid (str): The BSSID of the associated Access Point.
        probed_essids (list[str]): A list of ESSIDs the station has probed for.
        data_frames_num (int): Total number of captured data frames.
        observed_ds_states (set[str]): A set of observed Distribution System states.
        possible_bridge (bool): Indicates if the station is suspected of being a bridge.
        sent_arps (set[str]): A set of unique IP addresses extracted from sent ARP requests.
    """

    def __init__(self, mac: str, connected_bssid: str, probed_essid: str, data_frames_num: int) -> None:
        self.mac = mac.strip()
        self.connected_bssid = str(connected_bssid).strip()

        probed_essid = str(probed_essid).strip()
        if probed_essid != "nan":
            self.probed_essids = [probed_essid]
        else:
            self.probed_essids = []

        self.data_frames_num = int(data_frames_num)
        self.observed_ds_states = set()
        self.possible_bridge = False
        self.sent_arps = set()

    def print_realtime(self) -> None:
        """
        Prints formatted real-time information about the client station to standard output.
        """
        if len(self.probed_essids) > 0:
            formatted_essids = self.probed_essids
        else:
            formatted_essids = ["/"]
        print(
            helper.pad_ansi(self.mac, 20)
            + helper.pad_ansi(self.connected_bssid, PRINT_WIDTH["connected_bssid"])
            + helper.pad_ansi(str(self.data_frames_num), PRINT_WIDTH["sta_data_frames"])
            + helper.pad_ansi(str(formatted_essids), PRINT_WIDTH["last_probed"])
        )