from BeaconScanner import BaeconScan
from NetworkDevice import TrafficAnalyzer
from pathlib import Path

def main():
    tsharkPath = 'E:\\Wireshark\\tshark.exe'
    beaconPcap = 'nwm.pcapng'


    if not Path(tsharkPath).is_file():
        print("Nie znaleziono plików PCAP.")
        return

    scanner = BaeconScan(tsharkPath, beaconPcap)
    networks = scanner.scanBeacon()
    scanner.scan_cipher()

    for bssid, net in networks.items():
        print(f"{net['ssid']} ({bssid}) -> {net.get('typ_szyfrowania', 'Nieznane')}")   

    analyzer = TrafficAnalyzer(tsharkPath, beaconPcap, networks)
    analyzer.analyze()
    analyzer.print_summary()

if __name__ == "__main__":
    main()
