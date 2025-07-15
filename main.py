import subprocess
from pathlib import Path
from BeaconScanner import BaeconScan
from NetworkDevice import TrafficAnalyzer

def capture_pcap(output_file='capture.pcapng', duration=30, interface='wlan0'):
    subprocess.run([
        "dumpcap",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-w", output_file
    ])

def main():
    tsharkPath = 'E:\\Wireshark\\tshark.exe'
    capture_pcap('auto_capture.pcapng', duration=15)

    if not Path(tsharkPath).is_file():
        print("Nie znaleziono pliku TShark.")
        return

    scanner = BaeconScan(tsharkPath, 'auto_capture.pcapng')
    networks = scanner.scanBeacon()
    
    scanner.scanCipher(networks)
    for bssid, net in networks.items():
        print(f"{net['ssid']} ({bssid}) -> {net.get('typ_szyfrowania', 'Nieznane')}")   

    analyzer = TrafficAnalyzer(tsharkPath, 'auto_capture.pcapng', networks)
    analyzer.analyze()
    analyzer.print_summary()

if __name__ == "__main__":
    main()
