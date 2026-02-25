from scapy.layers.dot11 import *
from scapy.volatile import RandMAC
from helpers import interface_setup as setup
from helpers.helper_functions import *
import time

def build_probe():
    return (
        RadioTap() /
        Dot11(type=0, subtype=4,
              addr1="ff:ff:ff:ff:ff:ff",
              addr2=RandMAC(),
              addr3="ff:ff:ff:ff:ff:ff") /
        Dot11Elt(ID="SSID", info=b"") /
        Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
        Dot11Elt(ID="ESRates", info=b"\x30\x48\x60\x6c")
    )


def run(interface: str, channels: list, json_name: str):
    if channels is None:
        channels = [x for x in range(1,14)]
    found_aps = []
    probe = build_probe()
    try:
        while True:
            for ch in channels:
                setup.set_channel(interface, ch)
                sendp(probe, iface=interface, verbose=False)
                responses = sniff(
                    iface=interface,
                    timeout=0.30,
                    lfilter=lambda p: p.haslayer(Dot11ProbeResp)
                )

                for p in responses:
                    bssid = p.addr2
                    ssid = p[Dot11Elt].info.decode(errors="ignore")

                    if ssid == "":
                        continue

                    existing = next((ap for ap in found_aps if ap["BSSID"] == bssid), None)

                    if existing:
                        if ch not in existing["Channels"]:
                            existing["Channels"].append(ch)
                    else:
                        found_aps.append({
                            "SSID": ssid,
                            "BSSID": bssid,
                            "Channels": [ch],
                        })

                print("\033[H\033[J", end="")
                print("SSID" + " " * 31 + "BSSID\t\t\t Channels")

                for ap in found_aps:
                    _formatted_ap_ssid = ap["SSID"] + " " * (35-len(ap["SSID"])-1)
                    print(f"{_formatted_ap_ssid} {ap['BSSID']} \t\t {ap['Channels']}")

                time.sleep(0.3)

    except KeyboardInterrupt:
        if json_name is not None:
            for ap in found_aps:
                append_json(f"output/active_scan-{json_name}.json",
                            {
                                'ESSID': ap["SSID"],
                                'BSSID': ap["BSSID"],
                                'Channel': format_array(ap["Channels"]),
                            }
                            )
        print("\n Ending...")
        return