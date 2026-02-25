import helpers.helper_functions as helper

class InterfaceModes:
    monitor = "monitor"
    managed = "managed"

class PTModes:
    active = "active"
    passive = "passive"
    deauth = "deauth"

class Style:
    bold = "\033[1m"
    italic = "\033[3m"
    inverse = "\033[7m"
    underline = "\033[4m"
    reset = "\033[0m"

class StrengthColors:
    excellent = ["\033[38;5;46m", "Excelent"]
    great = ["\033[38;5;40m", "Great"]
    very_good = ["\033[38;5;190m", "Very good"]
    good = ["\033[38;5;226m", "Good"]
    reliable = ["\033[38;5;214m", "Reliable"]
    unreliable = ["\033[38;5;202m", "Unreliable"]
    poor = ["\033[38;5;196m", "Poor"]
    reset = "\033[0m"
    bold = "\033[1m"



class AP:
    def __init__(self, essid, bssid, signal_strength, beacon_frames_num, data_frames_num, channel, encryption_mode,
                 cipher, auth_method) -> None:
        if essid != " ":
            self.essid = str(essid[1:])
        else:
            self.essid = "Hidden"
        self.bssid = str(bssid)
        self.signal_strength = int(signal_strength)
        self.beacon_frames_num = int(beacon_frames_num)
        if int(channel[1:]) > 0:
            self.channels = [int(channel[1:])]
            if signal_strength < -10:
                self.distance = helper.get_approx_dist(signal_strength, self.channels[0])
            else:
                self.distance = 0
        else:
            self.channels = []
            self.distance = 0
        self.encryption_mode = str(encryption_mode[1:])
        self.encryption_mode = str(encryption_mode[1:]).split(" ",1)[0]
        self.cipher = str(cipher[1:])
        self.auth_method = str(auth_method[1:])
        self.data_frames_num = int(data_frames_num)
        self.vendor = helper.find_vendor(self.bssid)
        self.associated_STAs = []

    def add_channel(self, channel: int):
        if int(channel) not in self.channels and int(channel) > 0:
            self.channels.append(channel)

    def print_realtime(self) -> None:
        print(
            helper.pad_ansi(f"{StrengthColors.bold}{self.essid}{StrengthColors.reset}", 35)
            + helper.pad_ansi(self.bssid, 20)
            + helper.pad_ansi(helper.format_array(self.channels), 10)
            + helper.pad_ansi(helper.format_color_strength(self.signal_strength), 20)
            + helper.pad_ansi(self.encryption_mode, 15)
            + helper.pad_ansi(self.cipher, 10)
            + helper.pad_ansi(self.auth_method, 10)
            + helper.pad_ansi(str(self.beacon_frames_num), 10)
            + helper.pad_ansi(str(self.data_frames_num), 20)
            + helper.pad_ansi(str(self.vendor), 40)
            + helper.pad_ansi(str(self.distance), 10)
        )

    def set_beacon_frames_sum(self, num):
        self.beacon_frames_num = int(num)

    def set_data_frames_sum(self, num):
        self.data_frames_num = int(num)


def find_index_by_bssid(device_list, bssid):
    for i, device in enumerate(device_list):
        if device.bssid == bssid:
            return i
    return None

def find_station_index_by_mac(device_list, mac):
    for i, device in enumerate(device_list):
        if device.mac == mac:
            return i
    return None


class Station:
    def __init__(self, mac, connected_bssid, probed_essid, data_frames_num) -> None:
        self.mac = str(mac)
        self.connected_bssid = str(connected_bssid[1:])
        if str(probed_essid) != "nan":
            self.probed_essids = [str(probed_essid)]
        else:
            self.probed_essids = []
        self.data_frames_num = int(data_frames_num)

    def set_connected_bssid(self, bssid):
        if bssid[1:] != self.connected_bssid:
            self.connected_bssid = str(bssid)

    def add_probed_essid(self, probed_essid):
        probed_essid = str(probed_essid)
        if probed_essid != "nan":
            if probed_essid not in self.probed_essids:
                self.probed_essids.append(probed_essid)

    def set_data_frames_num(self, data_frames_num):
        self.data_frames_num = int(data_frames_num)

    def print_realtime(self) -> None:
        if len(self.probed_essids) > 0:
            formatted_essids = self.probed_essids
        else:
            formatted_essids = ["/"]
        print(
            helper.pad_ansi(self.mac, 20)
            + helper.pad_ansi(self.connected_bssid, 20)
            + helper.pad_ansi(str(self.data_frames_num), 20)
            + helper.pad_ansi(str(formatted_essids), 20)
        )