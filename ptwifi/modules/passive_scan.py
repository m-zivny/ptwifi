"""
modules/passive_scan.py
Author: Martin Živný

Description
-----------
This module implements the passive scanning phase of the PTWiFi tool.

It captures 802.11 frames passing through the wireless medium and extracts
information about available Access Points and client stations. It implements
threads for channel hopping and real-time terminal output.
"""

import threading
import time
from datetime import datetime
from scapy.all import sniff, Dot11, Dot11Elt, RadioTap, ARP

from helpers.classes import AP, Station, channels_2g, channels_5g
from helpers.interface_setup import set_channel
from helpers.helper_functions import format_array, append_json, get_channel_from_frequency, is_multicast, print_ap_header, print_station_header

DWELL_TIME = 0.3
discovered_aps: dict[str, AP] = {}
discovered_stas: dict[str, Station] = {}

def channel_hopper(interface: str, channels: list[str], stop_event: threading.Event) -> None:
    """
    Periodically switches the wireless interface channel to scan multiple frequencies.

    Args:
        interface (str): The name of the wireless interface in monitor mode.
        channels (list[str]): A list of channels to hop across.
        stop_event (threading.Event): An event flag to signal the thread to terminate.
    """
    while not stop_event.is_set():
        for channel in channels:
            if stop_event.is_set():
                break
            try:
                set_channel(interface, str(channel))
            except Exception:
                pass
            time.sleep(DWELL_TIME)

def display_results(stop_event: threading.Event, sta_filter: bool, hidden_filter: bool) -> None:
    """
    Periodically refreshes the terminal output to display real-time scan results.

    Args:
        stop_event (threading.Event): An event flag to signal the thread to terminate.
        sta_filter (bool): Flag indicating whether to display detected client stations.
        hidden_filter (bool): Flag indicating whether to display hidden Access Points.
    """
    while not stop_event.is_set():
        print("\033[H\033[J", end="")
        
        ap_list = list(discovered_aps.values())
        ap_list.sort(key=lambda ap: str(ap.essid))

        print_ap_header()
        
        for ap in ap_list:
            if str(ap.essid) != "Hidden":
                ap.print_realtime()

        if hidden_filter:
            print("\n")
            for ap in ap_list:
                if str(ap.essid) == "Hidden":
                    ap.print_realtime()
                    
        if sta_filter:
            sta_list = list(discovered_stas.values())
            sta_list.sort(key=lambda sta: str(sta.mac))
            if sta_list:
                print("\n\n")
                print_station_header()
                for station in sta_list:
                    if station.data_frames_num > 1:
                        station.print_realtime()
                    
        time.sleep(0.5)

def get_security_attributes(rsn_payload: bytes) -> tuple[str, str, str]:
    """
    Parses the Robust Security Network (RSN) Information Element payload.

    Args:
        rsn_payload (bytes): The raw bytes of the RSN element payload.

    Returns:
        tuple[str, str, str]: A tuple containing the encryption standard, 
                              the pairwise cipher suite, and the authentication method.
    """
    rsn_hex = rsn_payload.hex()

    encryption = "WPA2"
    auth = "Unknown"
    ciphers = []

    # AKM suites
    if "000fac08" in rsn_hex:
        encryption = "WPA3"
        auth = "SAE"
    elif "000fac12" in rsn_hex:
        encryption = "WPA3"
        auth = "OWE"
    elif "000fac02" in rsn_hex:
        auth = "PSK"
    elif "000fac01" in rsn_hex:
        auth = "802.1X"

    # Pairwise ciphers
    if "000fac04" in rsn_hex:
        ciphers.append("CCMP")
    if "000fac02" in rsn_hex:
        ciphers.append("TKIP")
    if "000fac08" in rsn_hex or "000fac09" in rsn_hex:
        ciphers.append("GCMP")

    cipher = "+".join(sorted(set(ciphers))) if ciphers else "Unknown"

    return encryption, cipher, auth

def analyze_beacon(frame: Dot11) -> None:
    """
    Extracts network parameters from 802.11 Beacon management frames.

    Args:
        frame (Dot11): The captured Scapy packet containing a Dot11 Beacon layer.
    """
    bssid = frame.addr3.upper() if frame.addr3 else None
    if not bssid:
        return

    # Extract operational channel from DS Parameter Set (ID 3)
    channel = 0
    current_layer = frame.getlayer(Dot11Elt)
    while current_layer:
        try:
            if current_layer.ID == 3 and len(current_layer.info) > 0:
                channel = int(current_layer.info[0])
                break
        except Exception:
            pass
        current_layer = current_layer.payload.getlayer(Dot11Elt)

    if bssid in discovered_aps:
        ap = discovered_aps[bssid]
        ap.beacon_frames_num += 1
        ap.observed_ds_states.add("00")
        
        if channel > 0:
            ap.channel = channel

        if frame.haslayer(RadioTap):
            try:
                ap.signal_strength = frame[RadioTap].dBm_AntSignal
                ap.update_distance()
            except Exception:
                pass
        
        if ap.essid == "Hidden":
            try:
                detected_bssid = frame.getlayer(Dot11Elt).info.decode("utf-8", errors="ignore")
                if detected_bssid:
                    ap.essid = detected_bssid
            except Exception:
                pass
        return

    privacy = True if "privacy" in frame.cap else False
    if privacy:
        encryption_mode = "WEP"
        cipher = "WEP"
        auth_method = "Open"
    else:
        encryption_mode = "Open"
        cipher = "None"
        auth_method = "None"

    essid = "Hidden"
    current_layer = frame.getlayer(Dot11Elt)
    if current_layer:
        decoded = current_layer.info.decode("utf-8", errors="ignore")
        if decoded not in ("", "\x00"):
            essid = decoded

    while current_layer:
        try:
            if current_layer.ID == 0:
                decoded = current_layer.info.decode("utf-8", errors="ignore")
                if decoded not in ("", "\x00"):
                    essid = decoded
            if current_layer.ID == 48:
                encryption_mode, cipher, auth_method = get_security_attributes(current_layer.info)
        except Exception:
            pass
        current_layer = current_layer.payload.getlayer(Dot11Elt)

    signal = 0
    if frame.haslayer(RadioTap):
        try:
            signal = frame[RadioTap].dBm_AntSignal
        except Exception:
            pass

    ap_obj = AP(
        essid,
        bssid,
        channel,
        encryption_mode,
        signal,
        1,
        0,
        cipher,
        auth_method
    )
    discovered_aps[bssid] = ap_obj

def analyze_probe(frame: Dot11) -> None:
    """
    Extracts probed ESSIDs and client MAC addresses from 802.11 Probe Request frames.

    Args:
        frame (Dot11): The captured Scapy packet containing a Dot11 Probe Request layer.
    """
    sta_mac = frame.addr2
    if not sta_mac:
        return
    sta_mac = sta_mac.upper()
    
    probed_essid = ""
    current_layer = frame.getlayer(Dot11Elt)
    while current_layer:
        if current_layer.ID == 0:
            try:
                decoded = current_layer.info.decode('utf-8', errors='ignore')
                probed_essid = decoded if decoded not in ('\x00', '') else ""
            except AttributeError:
                pass
            break
        current_layer = current_layer.payload.getlayer(Dot11Elt)
            
    if sta_mac not in discovered_stas:
        discovered_stas[sta_mac] = Station(sta_mac, "Not associated", probed_essid, 1)
    else:
        sta = discovered_stas[sta_mac]
        sta.data_frames_num += 1
        if probed_essid and probed_essid not in sta.probed_essids:
            sta.probed_essids.append(probed_essid)

    bssid = frame.addr3
    if bssid and probed_essid:
        bssid = bssid.upper()
        if bssid != "FF:FF:FF:FF:FF:FF" and bssid in discovered_aps:
            if discovered_aps[bssid].essid == "Hidden":
                discovered_aps[bssid].essid = probed_essid

def analyze_data(frame: Dot11) -> None:
    """
    Analyzes 802.11 Data frames to map associated stations and identify network topology (DS bits).

    Args:
        frame (Dot11): The captured Scapy packet containing a Dot11 Data layer.
    """
    if frame.type != 2:
        return

    if is_multicast(frame.addr1):
        return

    is_protected = "protected" in frame.FCfield
    to_ds = 1 if "to-DS" in frame.FCfield else 0
    from_ds = 1 if "from-DS" in frame.FCfield else 0
    ds_str = f"{to_ds}{from_ds}"

    sta_mac = None
    bssid = None
    bssid_wds_master = None

    if to_ds == 1 and from_ds == 0:
        sta_mac = frame.addr2
        bssid = frame.addr1
    elif to_ds == 0 and from_ds == 1:
        sta_mac = frame.addr1
        bssid = frame.addr2
    elif to_ds == 1 and from_ds == 1:
        bssid = frame.addr1
        bssid_wds_master = frame.addr2
    elif to_ds == 0 and from_ds == 0:
        bssid = frame.addr1
        sta_mac = frame.addr2
    else:
        return

    if not bssid_wds_master and sta_mac and bssid:
        sta_mac = sta_mac.upper()
        bssid = bssid.upper()
        
        if bssid in discovered_aps:
            ap = discovered_aps[bssid]
            ap.data_frames_num += 1
            ap.observed_ds_states.add(ds_str)
            if is_protected and ap.encryption_mode == "Open":
                ap.encryption_mode = "Encrypted"
            if sta_mac not in ap.associated_STAs:
                ap.associated_STAs.append(sta_mac)
                
        if sta_mac not in discovered_stas:
            discovered_stas[sta_mac] = Station(sta_mac, bssid, "", 1)
        else:
            sta = discovered_stas[sta_mac]
            sta.connected_bssid = bssid
            sta.data_frames_num += 1
            
        discovered_stas[sta_mac].observed_ds_states.add(ds_str)
            
    elif bssid_wds_master and bssid:
        bssid = bssid.upper()
        bssid_wds_master = bssid_wds_master.upper()
        
        for ap_mac in (bssid, bssid_wds_master):
            if ap_mac in discovered_aps:
                ap = discovered_aps[ap_mac]
                ap.data_frames_num += 1
                ap.observed_ds_states.add(ds_str)
                if is_protected and ap.encryption_mode == "Open":
                    ap.encryption_mode = "Encrypted"
            else:
                if ap_mac not in discovered_stas:
                    discovered_stas[ap_mac] = Station(ap_mac, bssid_wds_master, "", 1)
                
                sta = discovered_stas[ap_mac]
                sta.data_frames_num += 1
                sta.observed_ds_states.add(ds_str)

def analyze_arp(frame: Dot11) -> None:
    """
    Extracts sender IP addresses from ARP packets to detect MAC NAT/Pseudobridge configurations.

    Args:
        frame (Dot11): The captured Scapy packet containing an ARP layer.
    """
    arp_layer = frame.getlayer(ARP)
    
    src_mac = arp_layer.hwsrc
    src_ip = arp_layer.psrc

    if src_mac and src_ip:
        src_mac = src_mac.upper()
        if src_mac in discovered_stas:
            discovered_stas[src_mac].sent_arps.add(src_ip)

def frame_handler(frame: Dot11) -> None:
    """
    Main packet processing callback. Routes the frame to the appropriate analysis function.

    Args:
        frame (Dot11): The captured Scapy packet.
    """
    if not frame.haslayer(Dot11):
        return
        
    if frame.type == 0 and frame.subtype == 8:
        analyze_beacon(frame)
    elif frame.type == 0 and frame.subtype == 4:
        analyze_probe(frame)
    elif frame.type == 2 or frame.type == 1:
        analyze_data(frame)
        if frame.haslayer(ARP):
            analyze_arp(frame)

def run(interface: str, channels_to_hop: list[str] = None, sta_filter: bool = True, hidden_filter: bool = True, filename_json: str = None) -> tuple[list[AP], list[Station]]:
    """
    Initializes and executes the passive scanning process.

    Args:
        interface (str): The name of the wireless interface in monitor mode.
        channels_to_hop (list[str], optional): A list of specific channels to scan. Defaults to all standard channels.
        sta_filter (bool, optional): Flag indicating whether to display clients in the terminal. Defaults to True.
        hidden_filter (bool, optional): Flag indicating whether to display hidden APs in the terminal. Defaults to True.
        filename_json (str, optional): The filename used for exporting JSON results. Defaults to None.

    Returns:
        tuple[list[AP], list[Station]]: Two lists containing the discovered Access Point and Station objects.
    """
    global discovered_aps, discovered_stas
    discovered_aps.clear()
    discovered_stas.clear()

    channels = channels_to_hop if channels_to_hop else [str(ch) for ch in channels_2g + channels_5g]
 
    stop_event = threading.Event()
    
    hopper_thread = threading.Thread(
        target=channel_hopper,
        args=(interface, channels, stop_event),
        daemon=True
    )
    
    display_thread = threading.Thread(
        target=display_results,
        args=(stop_event, sta_filter, hidden_filter),
        daemon=True
    )

    try:
        hopper_thread.start()
        display_thread.start()
        sniff(iface=interface, prn=frame_handler, store=0)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(e.with_traceback())
        pass
    finally:
        if filename_json is not None:
            timestamp = datetime.now().strftime("[%d. %m. %Y [%H:%M]]")
            export_path = f"output/passive_scan/{timestamp} {filename_json}.json"

            for ap in discovered_aps.values():
                append_json(export_path,
                    {
                        'essid': ap.essid,
                        'bssid': ap.bssid,
                        'channel': ap.channel,
                        'signal_strength': ap.signal_strength,
                        'encryption': ap.encryption_mode,
                        'cipher': ap.cipher,
                        'authentication': ap.auth_method,
                        'beacons': ap.beacon_frames_num,
                        'data_frames': ap.data_frames_num,
                        'vendor': ap.vendor,
                        'associated_stas': format_array(ap.associated_STAs),
                        'approx_distance_m': ap.distance,
                        'observed_ds_states': format_array(list(ap.observed_ds_states))
                    }
                )
            for sta in discovered_stas.values():
                append_json(export_path,{
                    'mac': sta.mac,
                    'observed_ds_states': format_array(list(sta.observed_ds_states)),
                    'arped_IPs': format_array(list(sta.sent_arps))
                })

        stop_event.set()
        hopper_thread.join(timeout=1.0)
        display_thread.join(timeout=1.0)
        print("\n\n")
        return list(discovered_aps.values()), list(discovered_stas.values())