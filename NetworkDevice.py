import subprocess


class TrafficAnalyzer:
    def __init__(self, tsharkPath, pcapFile, networks):
        self.tsharkPath = tsharkPath
        self.pcapFile = pcapFile
        self.networks = networks

    def analyze(self):
        cmd = [
            self.tsharkPath,
            '-r', self.pcapFile,
            '-Y', 'wlan.fc.type == 2',
            '-T', 'fields',
            '-e', 'wlan.sa',
            '-e', 'wlan.da',
            '-e', 'wlan.bssid'
        ]

        output = subprocess.check_output(cmd, text=True)

        for line in output.strip().splitlines():
            fields = line.split('\t')
            if len(fields) < 3:
                continue
            sa, da, bssid = fields
            if bssid in self.networks:
                if sa != bssid:
                    self.networks[bssid]['komunikacja_z'].add(sa)
                if da != bssid:
                    self.networks[bssid]['komunikacja_z'].add(da)

    def print_summary(self):
        for net in self.networks.values():
            print(f"\nSSID: {net['ssid']:30}  BSSID: {net['bssid']}  Szyfrowana: {net['szyfrowana']}")
            if net['komunikacja_z']:
                print(f"  -> Komunikuje się z {len(net['komunikacja_z'])} urządzeniami:")
                for addr in sorted(net['komunikacja_z']):
                    print(f"     - {addr}")
            else:
                print("  -> Brak komunikacji z innymi adresami (brak ramek data)")