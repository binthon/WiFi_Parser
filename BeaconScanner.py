import subprocess

class BaeconScan:
    def __init__(self, tsharkPath, pcapFile):
        self.tsharkPath = tsharkPath
        self.pcapFile = pcapFile
        self.networks = {}


    def scanBeacon(self):
        cmd = [
            self.tsharkPath,
            '-r', self.pcapFile,
            '-Y', 'wlan.fc.type_subtype == 8',
            '-T', 'fields',
            '-e', 'wlan.ssid',
            '-e', 'wlan.bssid',
            '-e', 'wlan.fixed.capabilities.privacy'
        ]

        outputBaecon = subprocess.check_output(cmd, text=True)
        seen = set()

        for line in outputBaecon.strip().splitlines():
            fields = line.split('\t')
            if len(fields) < 3:
                continue

            ssidHex, bssid, privacy = fields
            try:
                ssid = bytes.fromhex(ssidHex).decode('utf-8', errors='replace')
            except ValueError:
                ssid = ssidHex

            print(f"RAW privacy: '{privacy}' for SSID: {ssid}")

            key = (ssid, bssid)
            if key in seen:
                continue
            seen.add(key)

            self.networks[bssid] = {
                'ssid': ssid,
                'bssid': bssid,
                'szyfrowana': "Open" if privacy.strip().lower() in ["0", "false", "no"] else "Encrypted",
                'komunikacja_z': set()
            }

        return self.networks
    
    def scan_cipher(self):
        cmd = [
            self.tsharkPath,
            '-r', self.pcapFile,
            '-Y', 'wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5',
            '-T', 'fields',
            '-e', 'wlan.bssid',
            '-e', 'wlan.fixed.capabilities.privacy',
            '-e', 'wlan.rsn.akms.type',
            '-e', 'wlan.rsn.pcs.type',
            '-e', 'wlan.tag.vendor.oui',
        ]

        output = subprocess.check_output(cmd, text=True)
        
        for line in output.strip().splitlines():
            fields = line.split('\t')
            if len(fields) < 2:
                continue

            bssid = fields[0]
            privacy = fields[1].strip()
            rsn_akm = fields[2].strip() if len(fields) > 2 else ""
            rsn_cipher = fields[3].strip() if len(fields) > 3 else ""
            vendor_oui = fields[4].strip() if len(fields) > 4 else ""

            if bssid not in self.networks:
                continue

            # Interpretacja szyfrowania
            if privacy in ["0", "false", "no"]:
                cipher_type = "OPEN"
            elif "1" in vendor_oui:
                cipher_type = "WEP"
            elif rsn_akm:
                if "8" in rsn_akm:
                    cipher_type = "WPA3"
                elif "2" in rsn_akm:
                    cipher_type = "WPA2"
                elif "1" in rsn_akm:
                    cipher_type = "WPA"
                else:
                    cipher_type = "Encrypted (unknown AKM)"
            else:
                cipher_type = "Encrypted (no RSN)"

            self.networks[bssid]["typ_szyfrowania"] = cipher_type

