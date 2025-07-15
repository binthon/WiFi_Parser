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
    
    def scanCipher(self, networks):
        cmd = [
            self.tsharkPath,
            '-r', self.pcapFile,
            '-Y', 'wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5',
            '-T', 'fields',
            '-e', 'wlan.bssid',
            '-e', 'wlan.fixed.capabilities.privacy',
            '-e', 'wlan.rsn.akms.type',
            '-e', 'wlan.tag.oui'
        ]

        output = subprocess.check_output(cmd, text=True)

        for line in output.strip().splitlines():
            fields = line.split('\t')
            bssid, privacy, rsn_akm, vendor_oui = (fields + [""] * 4)[:4]

            if bssid not in self.networks:
                continue

    
            if "typ_szyfrowania" in self.networks[bssid]:
                continue

            privacy = privacy.strip().lower()
            rsn_akm = rsn_akm.strip()
            vendor_oui = vendor_oui.strip().lower()


            if privacy in ["0", "false", "no"]:
                cipher_type = "OPEN"
            elif not rsn_akm and not vendor_oui.startswith("00:50:f2"):
                cipher_type = "WEP"
            elif not rsn_akm and vendor_oui.startswith("00:50:f2"):
                cipher_type = "WPA1"
            elif rsn_akm:
                akms = rsn_akm.split(',')
                if "12" in akms:
                    cipher_type = "WPA3-Enterprise (Suite-B 192)"
                elif "9" in akms:
                    cipher_type = "WPA3-Enterprise"
                elif "8" in akms:
                    if "2" in akms or "3" in akms:
                        cipher_type = "WPA2/WPA3-Transition"
                    else:
                        cipher_type = "WPA3-Personal"
                elif "2" in akms:
                    cipher_type = "WPA2-Enterprise"
                elif "3" in akms:
                    cipher_type = "WPA2-Personal"
                elif "1" in akms:
                    cipher_type = "WPA-Enterprise"
                else:
                    cipher_type = f"Encrypted (Unknown AKM: {rsn_akm})"
            else:
                cipher_type = "Encrypted (no RSN/Vendor Info)"

            self.networks[bssid]["typ_szyfrowania"] = cipher_type


