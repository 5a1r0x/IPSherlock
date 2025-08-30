from ipsherlockgraphic import *

USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (X11; Linux i686; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
]

REFERRERS = [
    'https://www.google.com/',
    'https://www.bing.com/',
    'https://duckduckgo.com/',
    'https://search.yahoo.com/',
    'https://www.ecosia.org/',
    'https://www.qwant.com/'
]

class IPSherlock:
    def __init__(self, arg):
        self.arg = arg
        self.abuseipdbkey = os.getenv('ABUSEIPDB_API_KEY')
        self.criminalipkey = os.getenv('CRIMINALIP_API_KEY')
        self.virustotalkey = os.getenv('VIRUSTOTAL_API_KEY')
        self.graynoisekey = os.getenv('GREYNOISE_API_KEY')
        self.ipregistrykey = os.getenv('IPREGISTRY_API_KEY')
        self.headers = self._generate_headers()
        self.ip = str(arg.ipaddress[0]) if hasattr(arg, 'ipaddress') and arg.ipaddress else None
        self.delay_seconds = self.arg.delay if getattr(self.arg, 'delay', None) else 0
        self.data1 = None
        self.data2 = None
        self.data3 = None
        self.data4 = None

    def _process_ip_info(self):
        ip_obj = ipaddress.ip_address(self.ip)
        version = ip_obj.version
        bit_length = ipaddress.IPV4LENGTH if version == 4 else ipaddress.IPV6LENGTH
        byte_length = bit_length // 8

        try:
            host = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:
            host = self.data1.get('hostname', 'Unknown')

        privacy_levels = {
            'PROXY': 'Low',
            'VPN': 'Medium',
            'RELAY': 'Medium',
            'TOR': 'High',
            'I2P': 'High',
            'ANONYMIZER': 'High'
        }

        network_type = self.data3.get('type', '').upper()
        anonymity = privacy_levels.get(network_type, 'Low')

        return {
            'ip_obj': ip_obj,
            'version': version,
            'bit_length': bit_length,
            'byte_length': byte_length,
            'host': host,
            'anonymity': anonymity
        }

    @staticmethod
    def _generate_headers():
        return {
            "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Referer": secrets.choice(REFERRERS),
            "User-Agent": secrets.choice(USER_AGENTS),
            "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }

    def _save_to_file(self, title, content):
        filename = f"{title}IPv4.txt" if ":" not in self.ip else f"{title}IPv6.txt"
        try:
            with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(str(json.dumps(content, indent=2)))
            IPSherlockGraphic.NOTICE(f"File Saved: {filename}")
        except IOError as e:
            IPSherlockGraphic.ERROR(f"File Problem: {e}")

    @staticmethod
    def _save_to_json(content):
        try:
            print("", str(json.dumps(content, indent=2)), "\n")
        except Exception as e:
            IPSherlockGraphic.ERROR(e)

    def _handle_output(self, label, data):
        if self.arg.file:
            self._save_to_file(label, data)
            return True
        elif self.arg.json:
            self._save_to_json(data)
            return True
        return False

    def _generate_google_dorks(self):
        if self.arg.category:
            print(f"\n{Colors.BLUE} G O O G L E D O R K S{Colors.RESET}\n")
        dorks = [
            f'{self.ip} OR "{self.ip}" OR "IP Address" {self.ip}',
            f'site:{self.ip}',
            f'inurl:"{self.ip}:8080"',
            f'filetype:env {self.ip}',
            f'intitle:"dashboard" "{self.ip}"',
            f'filetype:log "{self.ip}"',
            f'inurl:"/live.html" "{self.ip}"',
            f'inurl:"/api/" "{self.ip}"',
            f'intitle:"index of" "{self.ip}"',
            f'filetype:pdf OR filetype:docx site:{self.ip}',
            f'"Proxy: {self.ip}" "open"',
            f'"Remote Desktop Gateway" "{self.ip}"',
            f'"{self.ip}" "port:3306"',
            f'"ssh" "login" "{self.ip}"',
            f'inurl:"/view.shtml" "{self.ip}"',
            f'"Server: Apache" "{self.ip}"',
            f'"{self.ip}" "vulnerability" OR "CVE"',
            f'"ftp://{self.ip}" "anonymous"',
            f'"Generated by WordPress" "{self.ip}"',
            f'"phpinfo()" "{self.ip}"',
            f'"IP Location" "{self.ip}"'
    ]

        if self._handle_output('GoogleDorks', dorks):
            return

        for dork in dorks:
            print(Colors.RESET, dork)

    def _fetch_ip_data(self):
        try:
            time.sleep(self.delay_seconds)
            r1 = requests.get(
                url=f"https://ipinfo.io/{self.ip}/json",
                headers=self.headers,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay_seconds)
            r2 = requests.get(
                url=f"https://ipwho.is/{self.ip}",
                headers=self.headers,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay_seconds)
            r3 = requests.get(
                url=f"https://proxycheck.io/v2/{self.ip}&vpn=1&asn=1&risk=1&node=1",
                headers=self.headers,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay_seconds)
            r4 = requests.get(
                url=f"https://api.ipapi.is/?q={self.ip}",
                headers=self.headers,
                timeout=10,
                verify=True
            )

            if not all([r1.ok, r2.ok, r3.ok]):
                errors = []
                if not r1.ok:
                    errors.append(f"IpInfo: {r1.status_code} | {r1.reason}")
                if not r2.ok:
                    errors.append(f"IpWho: {r2.status_code} | {r2.reason}")
                if not r3.ok:
                    errors.append(f"ProxyCheck: {r3.status_code} | {r3.reason}")
                if not r4.ok:
                    errors.append(f"IpApi: {r4.status_code} | {r4.reason}")
                raise ConnectionError("| ".join(errors))

            self.data1 = r1.json()
            self.data2 = r2.json()
            self.data3 = r3.json().get(self.ip, {})
            self.data4 = r4.json()
            self.node = r3.json().get('node', 'Unknown')

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f'Network: {e}')
        except json.JSONDecodeError:
            raise ValueError('Invalid JSON response from API')

    def _my_ip_address(self):
        if self.arg.category:
            print(f"\n{Colors.BLUE} P E R S O N A L I P{Colors.RESET}\n")

        try:
            time.sleep(self.delay_seconds)
            ipv4 = requests.get(
                url=f"https://ipinfo.io/json", headers=self.headers,
                timeout=10,
                verify=True
            )

            ip4 = ipv4.json()
            IPSherlockGraphic.INFO('IPv4', ip4.get('ip', 'Unknown'))

            time.sleep(self.delay_seconds)
            ipv6 = requests.get(
                url=f"https://v6.ident.me", headers=self.headers,
                timeout=10,
                verify=True
            )

            ip6 = ipv6.text

            IPSherlockGraphic.INFO('IPv6', ip6 if ip6 else 'Unknown')

            if self.arg.json or self.arg.file:
                IPSherlockGraphic.NOTICE("Parameters not available for this command")

        except requests.exceptions.RequestException:
            IPSherlockGraphic.INFO('IPv6', "Unknown")
        except Exception as e:
            IPSherlockGraphic.ERROR(e)

    def _display_network_info(self, ip_info):
        if self.arg.category:
            print(f'\n{Colors.BLUE} N E T W O R K{Colors.RESET}\n')

        try:
            domain = self.data2.get('connection', {}).get('domain', 'Unknown')
            if domain == "" or not domain:
                domain = 'Unknown'

            network_information = {
                'IP Address': self.data1.get('ip', 'Unknown'),
                'Name': 'Internet Protocol',
                'Version': ip_info['version'],
                'Bit': ip_info["bit_length"],
                'Byte': ip_info["byte_length"],
                'Interface': str(ipaddress.ip_interface(self.ip)),
                'Private': 'No',
                'Link Local': 'Yes' if ip_info['ip_obj'].is_link_local else 'No',
                'Global': 'Yes' if ip_info['ip_obj'].is_global else 'No',
                'Local Host': 'Yes' if ip_info['ip_obj'].is_loopback else 'No',
                'Multicast': 'Yes' if ip_info['ip_obj'].is_multicast else 'No',
                'Reserved': 'Yes' if ip_info['ip_obj'].is_reserved else 'No',
                'Unspecified': 'Yes' if ip_info['ip_obj'].is_unspecified else 'No',
                'Host': ip_info["host"],
                'Domain': domain,
                'Provider': self.data3.get('provider', 'Unknown'),
                'Organization': self.data1.get("org", 'Unknown'),
                'Device': self.data3.get('devices', {}).get('address', 'Unknown'),
                'Subnet': self.data3.get('devices', {}).get('subnet', 'Unknown')
            }

            if self._handle_output('Network', network_information):
                return

            for i, info in network_information.items():
                IPSherlockGraphic.INFO(f"{i}", f"{info}")

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(e)

    def _display_geolocation(self):
        if self.arg.category:
            print(f"\n{Colors.BLUE} G E O L O C A T I O N{Colors.RESET}\n")

        try:
            currency = self.data3.get('currency', {})
            currency_str = f"{currency.get('name', 'Unknown')} {currency.get('code', 'Unknown')} {currency.get('symbol', '')}"
            if self.data2.get('calling_code'):
                pprefix = f"+{self.data2.get('calling_code')}"
            else:
                pprefix = 'Unknown'

            geolocation_information = {
                'City': self.data1.get('city', 'Unknown'),
                'Region': self.data1.get('region', 'Unknown'),
                'Country': self.data3.get('country', 'Unknown'),
                'Capital': self.data2.get('capital', 'Unknown'),
                'Continent': self.data3.get('continent', 'Unknown'),
                'ISO Code': self.data3.get('isocode', 'Unknown'),
                'Postal Code': self.data2.get('postal', 'Unknown'),
                'Current Time': self.data2.get('timezone', {}).get('current_time', 'Unknown'),
                'Latitude': self.data3.get('latitude', 'Unknown'),
                'Longitude': self.data3.get('longitude', 'Unknown'),
                'Currency': currency_str,
                'Phone Prefix': pprefix
            }

            if self._handle_output('Geolocation', geolocation_information):
                return

            for i, info in geolocation_information.items():
                IPSherlockGraphic.INFO(f"{i}", f"{info}")

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(e)

    def _display_security_info(self, anonymity):
        if self.arg.category:
            print(f"\n{Colors.BLUE} S E C U R I T Y{Colors.RESET}\n")

        try:
            security_information = {
                'Connection': self.data3.get('type', 'Unknown'),
                'Anonimity': anonymity,
                'Risk': self.data4.get('company', {}).get('abuser_score', 'Unknown'),
                'Bogon': 'Yes' if self.data4.get('is_bogon', 'Unknown') else 'No',
                'Mobile': 'Yes' if self.data4.get('is_mobile', 'Unknown') else 'No',
                'Satellite': 'Yes' if self.data4.get('is_satellite', 'Unknown') else 'No',
                'Crawler': 'Yes' if self.data4.get('is_crawler', 'Unknown') else 'No',
                'Data Center': 'Yes' if self.data4.get('is_datacenter', 'Unknown') else 'No',
                'Tor': 'Yes' if self.data4.get('is_tor', 'Unknown') else 'No',
                'Proxy': 'Yes' if self.data4.get('is_proxy', 'Unknown') else 'No',
                'Abuser': 'Yes' if self.data4.get('is_abuser', 'Unknown') else 'No',
                'VPN': 'Yes' if self.data4.get('is_vpn', 'Unknown') else 'No',
                'Service': self.data4.get('vpn', {}).get('service', 'No'),
            }

            if self._handle_output('Security', security_information):
                return

            for i, info in security_information.items():
                IPSherlockGraphic.INFO(f"{i}", f"{info}")

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(e)

    def _display_whois_info(self):
        if self.arg.category:
            print(f"\n{Colors.BLUE} W H O I S{Colors.RESET}\n")

        try:
            obj = IPWhois(self.ip)
            results = obj.lookup_rdap()

            whois_information = {
                'CIDR': results.get('network', {}).get('cidr'),
                'ASN': results.get('asn'),
                'ASN Description': results.get('asn_description'),
                'ASN Country Code': results.get('asn_country_code'),
                'RIR': self.data4.get('rir', 'Unknown'),
                'Name': results.get('network', {}).get('name'),
                'Handle': results.get('network', {}).get('handle'),
                'Type': results.get('network', {}).get('type'),
                'Status': results.get('network', {}).get('status'),
                'Country': results.get('network', {}).get('country'),
                'Start Address': results.get('network', {}).get('start_address'),
                'End Address': results.get('network', {}).get('end_address'),
                'Entities': results.get('entities')
            }

            if self._handle_output('WHOIS', whois_information):
                return

            for i, info in whois_information.items():
                IPSherlockGraphic.INFO(f"{i}", f"{info}")

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(f"WHOIS Lookup Failed: {e}")

    def _private_ip_address(self):
        if self.arg.category:
            print(f"\n{Colors.BLUE} P R I V A T E I P{Colors.RESET}\n")

        try:
            private_information = {
                'IP Address': self.ip,
                'Name': 'Internet Protocol',
                'Interface': str(ipaddress.ip_interface(self.ip)),
                'Private': 'Yes'
            }

            if self._handle_output('Private', private_information):
                return

            for i, info in private_information.items():
                IPSherlockGraphic.INFO(f"{i}", f"{info}")

        except Exception as e:
            IPSherlockGraphic.ERROR(e)

    def _abuse_ipdb_info(self):
        global abuse

        if self.arg.category:
            print(f"\n{Colors.BLUE} A B U S E I P D B{Colors.RESET}\n")

        try:
            abuse_headers = {
                "Key": self.abuseipdbkey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(REFERRERS),
                "User-Agent": secrets.choice(USER_AGENTS),
                "Accept": "application/json",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay_seconds)
            abuse = requests.get(
                url=f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.ip}&maxAgeInDays=90",
                headers=abuse_headers,
                timeout=10,
                verify=True
            )

            ipdb = abuse.json()
            print(json.dumps(ipdb, indent=2,), "\n")
            
            if abuse.status_code == 429:
                IPSherlockGraphic.ERROR("Available lookups limit exceeded")
                IPSherlockGraphic.NOTICE("Request a new API key or upgrade your plan")

            elif abuse.status_code == 401:
                IPSherlockGraphic.ERROR(f"Unauthorized")
                IPSherlockGraphic.NOTICE("Check or update your API key")

            # File Output
            if self.arg.file:
                self._save_to_file('AbuseIPDB', ipdb)

        # Exceptions
        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(f"{e} | {abuse.status_code} {abuse.reason}")
            IPSherlockGraphic.NOTICE(f"Check your AbuseIPDB API key in 'sherlockey.env' file. Check the status of the website: https://www.abuseipdb.com/")

    def _criminal_ip_info(self):
        global criminal

        if self.arg.category:
            print(f"\n{Colors.BLUE} C R I M I N A L I P{Colors.RESET}\n")

        try:
            criminal_headers = {
                "x-api-key": self.criminalipkey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(REFERRERS),
                "User-Agent": secrets.choice(USER_AGENTS),
                "Accept": "application/json",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay_seconds)
            criminal = requests.get(
                url=f"https://api.criminalip.io/v1/asset/ip/report?ip={self.ip}&full=true",
                headers=criminal_headers,
                timeout=10,
                verify=True
            )

            if ":" in self.ip:
                IPSherlockGraphic.ERROR("IPv6 Address checking not supported")
                return

            crimip = criminal.json()
            print(json.dumps(crimip, indent=2))

            if crimip.get('message', 'Unknown') == 'limit exceeded':
                IPSherlockGraphic.ERROR("Available credit limit exceeded")
                IPSherlockGraphic.NOTICE("Request a new API key or upgrade your plan")
            
            elif criminal.status_code == 401:
                IPSherlockGraphic.ERROR("Unauthorized")
                IPSherlockGraphic.NOTICE("Check or update your API key")

            if self.arg.file:
                self._save_to_file('CriminalIP', crimip)

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(f"{e} | {criminal.status_code} {criminal.reason}")
            IPSherlockGraphic.NOTICE(f"Check your CriminalIP API key in 'sherlockey.env' file. Check the status of the website: https://www.criminalip.io/")

    def _virus_total_info(self):
        global virustotal

        if self.arg.category:
            print(f"\n{Colors.BLUE} V I R U S T O T A L{Colors.RESET}\n")

        try:
            vt_headers = {
                "x-apikey": self.virustotalkey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(REFERRERS),
                "User-Agent": secrets.choice(USER_AGENTS),
                "Accept": "application/json",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay_seconds)
            virustotal = requests.get(
                url=f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip}",
                headers=vt_headers,
                timeout=10,
                verify=True
            )

            vtip = virustotal.json()
            print(json.dumps(vtip, indent=2))

            if virustotal.status_code == 429:
                IPSherlockGraphic.ERROR("Available lookups limit exceeded")
                IPSherlockGraphic.NOTICE("Request a new API key or upgrade your plan")

            elif virustotal.status_code == 401:
                IPSherlockGraphic.ERROR("Unauthorized")
                IPSherlockGraphic.NOTICE("Check or update your API key")

            if self.arg.file:
                self._save_to_file('VirusTotal', vtip)

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(f"{e} | {virustotal.status_code} {virustotal.reason}")
            IPSherlockGraphic.NOTICE(f"Check your VirusTotal API key in 'sherlockey.env' file. Check the status of the website: https://www.virustotal.com/")

    def _global_database_info(self):
        global whoisdatabase
        global whoisdatabase_asn

        if self.arg.category:
            print(f"\n{Colors.BLUE} W H O I S D A T A B A S E{Colors.RESET}\n")

        try:
            whoisdb_headers = {
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(REFERRERS),
                "User-Agent": secrets.choice(USER_AGENTS),
                "Accept": "application/json",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay_seconds)
            whoisdatabase_asn = requests.get(
                url=f"https://api.ipapi.is/?q={self.ip}",
                headers=whoisdb_headers,
                timeout=10,
                verify=True
            )
            asn_result = whoisdatabase_asn.json()['asn']['asn']

            time.sleep(self.delay_seconds)
            whoisdatabase = requests.get(
                url=f"https://api.ipapi.is/?whois=AS{asn_result}",
                headers=whoisdb_headers,
                timeout=10,
                verify=True
            )

            wdb = whoisdatabase.text
            print(wdb)

            if self.arg.file:
                self._save_to_file('WHOISDatabase', wdb)

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(f"Database: {e} | {whoisdatabase.status_code} {whoisdatabase.reason}")
            IPSherlockGraphic.ERROR(f"IPApi: {e} | {whoisdatabase_asn.status_code} {whoisdatabase_asn.reason}")

    def _greynoise_ip_info(self):
        global greynoise

        if self.arg.category:
            print(f"\n{Colors.BLUE} G R E Y N O I S E{Colors.RESET}\n")

        try:
            gndb_headers = {
                "key": self.graynoisekey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(REFERRERS),
                "User-Agent": secrets.choice(USER_AGENTS),
                "Accept": "application/json",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay_seconds)
            greynoise = requests.get(
                url=f"https://api.greynoise.io/v3/community/{self.ip}",
                headers=gndb_headers,
                timeout=10,
                verify=True
            )

            if ":" in self.ip:
                IPSherlockGraphic.ERROR("IPv6 Address checking not supported")
                return

            gndb = greynoise.json()
            print(json.dumps(gndb, indent=2))

            if greynoise.status_code == 429:
                IPSherlockGraphic.ERROR("Available lookups limit exceeded")
                IPSherlockGraphic.NOTICE("Request a new API key or upgrade your plan")

            elif greynoise.status_code == 401:
                IPSherlockGraphic.ERROR("Unauthorized")
                IPSherlockGraphic.NOTICE("Check or update your API key")

            if self.arg.file:
                self._save_to_file('GreyNoise', gndb)

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(f"{e} | {greynoise.status_code} {greynoise.reason}")
            IPSherlockGraphic.NOTICE(f"Check your GreyNoise API key in 'sherlockey.env' file. Check the status of the website: https://www.greynoise.io/")

    def _ipregistry_ip_info(self):
        global ipregistry

        if self.arg.category:
            print(f"\n{Colors.BLUE} I P R E G I S T R Y{Colors.RESET}\n")

        try:
            ipre_headers = {
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(REFERRERS),
                "User-Agent": secrets.choice(USER_AGENTS),
                "Accept": "application/json",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay_seconds)
            ipregistry = requests.get(
                url=f"https://api.ipregistry.co/{self.ip}?hostname=true&key={self.ipregistrykey}",
                headers=ipre_headers,
                timeout=10,
                verify=True
            )

            ipre = ipregistry.json()
            print(json.dumps(ipre, indent=2))
            
            if ipregistry.status_code == 429:
                IPSherlockGraphic.ERROR("Available lookups limit exceeded")
                IPSherlockGraphic.NOTICE("Request a new API key or upgrade your plan")
            
            elif ipregistry.status_code == 401:
                IPSherlockGraphic.ERROR("Unauthorized")
                IPSherlockGraphic.NOTICE("Check or update your API key")

            if self.arg.file:
                self._save_to_file('IPRegistry', ipre)

        except requests.exceptions.RequestException as re:
            IPSherlockGraphic.ERROR(f"Request: {re}")
        except Exception as e:
            IPSherlockGraphic.ERROR(f"{e} | {ipregistry.status_code} {ipregistry.reason}")
            IPSherlockGraphic.NOTICE(f"Check your IPRegistry API key in 'sherlockey.env' file. Check the status of the website: https://ipregistry.co/")

    def _fakeipaddress_info(self):

        if self.arg.category:
            print(f"\n{Colors.BLUE} F A K E I P{Colors.RESET}\n")

        fake_ip = {
            'IPv4': str(ipaddress.IPv4Address(random.getrandbits(32))),
            'IPv6': str(ipaddress.IPv6Address(random.getrandbits(128)))
        }
        
        self.ip = '.'

        if self._handle_output('FakeIPAddress', fake_ip):
            return

        for f, fakeip in fake_ip.items():
            IPSherlockGraphic.INFO(f"{f}", f"{fakeip}")

    def run(self):
        try:
            IPSherlockGraphic.CLEAR()
            print(IPSherlockGraphic.LOGO)

            if self.arg.myip:
                self._my_ip_address()
                return

            if self.arg.fakeip:
                self._fakeipaddress_info()
                return

            if not self.ip:
                IPSherlockGraphic.ERROR('No IP Address provided')
                IPSherlockGraphic.NOTICE('Use -ip <IP Address>')
                return

            elif self.arg.googledorks:
                self._generate_google_dorks()
                return

            elif ipaddress.ip_address(self.ip).is_private:
                self._private_ip_address()
                return

            api_handlers = {
                'abuseipdb': self._abuse_ipdb_info,
                'criminalip': self._criminal_ip_info,
                'virustotal': self._virus_total_info,
                'whoisdb': self._global_database_info,
                'greynoise': self._greynoise_ip_info,
                'ipregistry': self._ipregistry_ip_info
            }

            api_called = False
            for flag, action in api_handlers.items():
                if getattr(self.arg, flag, False):
                    action()
                    api_called = True

            if api_called:
                return

            self._fetch_ip_data()
            ip_info = self._process_ip_info()

            if any([self.arg.network, self.arg.geolocation, self.arg.security, self.arg.whois, self.arg.myip]):
                if self.arg.network:
                    self._display_network_info(ip_info)
                if self.arg.geolocation:
                    self._display_geolocation()
                if self.arg.security:
                    self._display_security_info(ip_info['anonymity'])
                if self.arg.whois:
                    self._display_whois_info()
                if self.arg.myip:
                    self._my_ip_address()
            else:
                self._display_network_info(ip_info)
                self._display_geolocation()
                self._display_security_info(ip_info['anonymity'])
                self._display_whois_info()

        except KeyboardInterrupt:
            IPSherlockGraphic.NOTICE('IPSherlock Interrupted')
        except Exception as e:
            IPSherlockGraphic.ERROR(e)
