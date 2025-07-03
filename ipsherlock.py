#!/usr/bin/env python3

"""
Name: IP Sherlock
Version: 1.0
Developer: 5a1r0x
GitHub: https://github.com/5a1r0x/IPSherlock.git
License: Apache 2.0
Powered by AI
"""

import os
import argparse
import ipaddress
import secrets
import socket
import json
import time

try:
    import requests
    from ipwhois import IPWhois
    from colorama import init, Fore, Style
    init(autoreset=True)
except ModuleNotFoundError as m:
    path = os.getcwd()
    files = os.listdir(path)
    if "requirements.txt" in files:
        os.system("pip install -r requirements.txt")
    else:
        print(f"[ERROR] Unable to install the necessary modules ({m}). Check the existence of the requirements.txt file and its contents.")

class IPSherlock:
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

    REFERERS = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://duckduckgo.com/",
        "https://www.reddit.com/",
        "https://github.com/",
        "https://news.ycombinator.com/",
        "https://stackoverflow.com/",
        "https://medium.com/",
        "https://twitter.com/"
    ]

    def __init__(self, arg):
        self.arg = arg
        self.headers = self._generate_headers()
        self.ip = arg.ipaddress[0] if arg.ipaddress else None
        self.delay = int(arg.time[0]) if hasattr(arg, 'time') and arg.time else 0
        self.data1 = None
        self.data2 = None
        self.data3 = None
        self.node = None

    def _generate_headers(self):
        """Generate random HTTP headers for requests"""
        return {
            "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Referer": secrets.choice(self.REFERERS),
            "User-Agent": secrets.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }

    @staticmethod
    def logo():
        print("\033[38;5;27m" + r"""
  _____ _____     _____ _               _            _    
 |_   _|  __ \   / ____| |             | |          | |   
   | | | |__) | | (___ | |__   ___ _ __| | ___   ___| | __
   | | |  ___/   \___ \| '_ \ / _ \ '__| |/ _ \ / __| |/ /
  _| |_| |       ____) | | | |  __/ |  | | (_) | (__|   <
 |_____|_|      |_____/|_| |_|\___|_|  |_|\___/ \___|_|\_\
""")

    @staticmethod
    def print_info(label, value):
        print(f"{Fore.CYAN} {label}{Fore.CYAN}:{Fore.RESET} {value}{Fore.RESET}")

    @staticmethod
    def print_error(msg):
        print(f"{Fore.RED} [ERROR] {msg}{Fore.RESET}")

    @staticmethod
    def print_success(msg):
        print(f"{Fore.GREEN} [SUCCESS] {msg}{Fore.RESET}")

    @staticmethod
    def print_help(msg):
        print(f"{Fore.YELLOW} [HELP] {msg}{Fore.RESET}")

    @staticmethod
    def clean_terminal():
        os.system('cls') if os.name == 'nt' else os.system('clear')

    def _fetch_ip_data(self):
        """Retrieve IP data from external APIs"""
        try:
            time.sleep(self.delay)
            r1 = requests.get(
                f"https://ipinfo.io/{self.ip}/json", # 1000 R/DAY
                headers=self.headers,
                stream=True,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay)
            r2 = requests.get(
                f"https://ipwho.is/{self.ip}", # FREE PLAN 10.000 R/MONTH
                headers=self.headers,
                stream=True,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay)
            r3 = requests.get(
                f"https://proxycheck.io/v2/{self.ip}&vpn=1&asn=1&risk=1&node=1", # 100 R/DAY
                headers=self.headers,
                stream=True,
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
                raise ConnectionError("; ".join(errors))

            self.data1 = r1.json()
            self.data2 = r2.json()
            self.data3 = r3.json().get(self.ip, {})
            self.node = r3.json().get("node", "Unknown")

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Network Error: {str(e)}")
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON response from API")

    def _my_ip_address(self):
        """Get personal IP Address"""
        time.sleep(self.delay)
        ipv4 = requests.get(url=f"https://ipinfo.io/json", headers=self.headers, stream=True, timeout=10, verify=True)
        time.sleep(self.delay)
        ipv6 = requests.get(url=f"https://api.myip.com/", headers=self.headers, stream=True, timeout=10, verify=True)
        ip4 = ipv4.json()["ip"]
        ip6 = ipv6.json()["ip"]
        if ":" in ip6:
            self.print_info("IPv4", ip4)
            self.print_info("IPv6", ip6)
        else:
            self.print_info("IPv4", ip4)
            self.print_info("IPv6", "Unknown")

    def _process_ip_info(self):
        """Process the main IP information"""
        ip_obj = ipaddress.ip_address(self.ip)
        version = ip_obj.version
        bit_length = ipaddress.IPV4LENGTH if version == 4 else ipaddress.IPV6LENGTH
        byte_length = bit_length // 8

        try:
            host = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:
            host = self.data1.get("hostname", "Unknown")

        privacy_levels = {
            'PROXY': 'Low',
            'VPN': 'Medium',
            'RELAY': 'Medium',
            'TOR': 'High',
            'I2P': 'High',
            'ANONYMIZER': 'High'
        }
        network_type = self.data3.get("type", "").upper()
        anonymity = privacy_levels.get(network_type, 'Low')

        return {
            "ip_obj": ip_obj,
            "version": version,
            "bit_length": bit_length,
            "byte_length": byte_length,
            "host": host,
            "anonymity": anonymity
        }

    def _display_network_info(self, ip_info):
        """Display network information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m N E T W O R K\n")

        domain = self.data2.get("connection", {}).get("domain", "Unknown")
        if domain == "" or not domain:
            domain = "Unknown"

        self.print_info("IP Address", self.data1.get("ip", "Unknown"))
        self.print_info("Name", "Internet Protocol")
        self.print_info("Version", ip_info["version"])
        self.print_info("Bit", ip_info["bit_length"])
        self.print_info("Byte", ip_info["byte_length"])
        self.print_info("Interface", ipaddress.ip_interface(self.ip))
        self.print_info("Private", "Yes" if ip_info["ip_obj"].is_private else "No")
        self.print_info("Link Local", "Yes" if ip_info["ip_obj"].is_link_local else "No")
        self.print_info("Global", "Yes" if ip_info["ip_obj"].is_global else "No")
        self.print_info("Local Host", "Yes" if ip_info["ip_obj"].is_loopback else "No")
        self.print_info("Multicast", "Yes" if ip_info["ip_obj"].is_multicast else "No")
        self.print_info("Reserved", "Yes" if ip_info["ip_obj"].is_reserved else "No")
        self.print_info("Unspecified", "Yes" if ip_info["ip_obj"].is_unspecified else "No")
        self.print_info("Host", ip_info["host"])
        self.print_info("Domain", domain)
        self.print_info("Provider", self.data3.get("provider", "Unknown"))
        self.print_info("Organization", self.data1.get("org", "Unknown"))
        self.print_info("Device", self.data3.get("devices", {}).get("address", "Unknown"))
        self.print_info("Subnet", self.data3.get("devices", {}).get("subnet", "Unknown"))

    def _display_geolocation(self):
        """Display geolocation information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m G E O L O C A T I O N\n")

        self.print_info("City", self.data1.get("city", "Unknown"))
        self.print_info("Region", self.data1.get("region", "Unknown"))
        self.print_info("Country", self.data3.get("country", "Unknown"))
        self.print_info("Continent", self.data3.get("continent", "Unknown"))
        self.print_info("ISO Code", self.data3.get("isocode", "Unknown"))
        self.print_info("Postal Code", self.data2.get("postal", "Unknown"))
        self.print_info("Current Time", self.data2.get("timezone", {}).get("current_time", "Unknown"))
        self.print_info("Latitude", self.data3.get("latitude", "Unknown"))
        self.print_info("Longitude", self.data3.get("longitude", "Unknown"))

        currency = self.data3.get("currency", {})
        currency_str = f"{currency.get('name', 'Unknown')} {currency.get('code', 'Unknown')} {currency.get('symbol', '')}"
        self.print_info("Currency", currency_str)

    def _display_security_info(self, anonymity):
        """Display security information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m S E C U R I T Y\n")

        self.print_info("Node", self.node)
        self.print_info("Connection", self.data3.get("type", "Unknown"))
        self.print_info("Anonimity", anonymity)
        self.print_info("Risk", self.data3.get("risk", "Unknown"))

    def _display_whois_info(self):
        """Display WHOIS information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m W H O I S\n")

        try:
            obj = IPWhois(self.ip)
            results = obj.lookup_rdap()

            self.print_info("CIDR", results.get('network', {}).get('cidr'))
            self.print_info("ASN", results.get('asn'))
            self.print_info("ASN Description", results.get('asn_description'))
            self.print_info("ASN Country Code", results.get('asn_country_code'))
            self.print_info("Name", results.get('network', {}).get('name'))
            self.print_info("Handle", results.get('network', {}).get('handle'))
            self.print_info("Type", results.get('network', {}).get('type'))
            self.print_info("Status", results.get('network', {}).get('status'))
            self.print_info("Country", results.get('network', {}).get('country'))
            self.print_info("Start Address", results.get('network', {}).get('start_address'))
            self.print_info("End Address", results.get('network', {}).get('end_address'))
            self.print_info("Entities", results.get('entities'))
            self.print_info("Links", results.get('links'))
            self.print_info("Events", results.get('events'))
        except Exception as e:
            self.print_error(f"WHOIS Lookup Failed: {str(e)}")
            self.print_help("If you are on termux use the 'pkg install whois' command to install the integrated whois package")

    def _generate_json_output(self):
        """Generate JSON output"""
        return json.dumps({
            "ipinfo": self.data1,
            "ipwhois": self.data2,
            "proxycheck": {
                "node": self.node,
                "data": self.data3
            }
        }, indent=2)

    def _save_to_file(self, content):
        """Save output to file"""
        filename = f"IPSherlock_{self.ip}.txt" if ":" not in self.ip else f"IPSherlock_IPv6.txt"
        try:
            with open(filename, "w", encoding='utf-8', errors='ignore') as f:
                f.write(content)
            self.print_success(f"File Saved: {filename}")
        except IOError as e:
            self.print_error(f"File Save Failed: {str(e)}")

    def run(self):
        try:
            self.clean_terminal()
            self.logo()

            if self.arg.myipaddress:
                self._my_ip_address()
                return

            if not self.ip:
                raise ValueError("No IP Address provided. Use -ip <IP Address> or -m for your IP Address.")

            self._fetch_ip_data()
            ip_info = self._process_ip_info()

            if self.arg.json:
                print(self._generate_json_output())
                return
            elif self.arg.file:
                self._save_to_file(self._generate_json_output())
                return

            # Display selected categories
            if any([self.arg.network, self.arg.geolocation, self.arg.security, self.arg.whois, self.arg.myipaddress]):
                if self.arg.network:
                    self._display_network_info(ip_info)
                if self.arg.geolocation:
                    self._display_geolocation()
                if self.arg.security:
                    self._display_security_info(ip_info["anonymity"])
                if self.arg.whois:
                    self._display_whois_info()
                if self.arg.myipaddress:
                    self._my_ip_address()
            else:
                # Display all categories
                self._display_network_info(ip_info)
                self._display_geolocation()
                self._display_security_info(ip_info["anonymity"])
                self._display_whois_info()

        except Exception as e:
            self.print_error(str(e))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ipsherlock',
        description='ip address investigation and whois intelligence',
        epilog='use ethically and responsibly'
    )

    parser.add_argument('-t', '--time', help='delay before sending the request to different apis', type=int, nargs=1)
    parser.add_argument('-ip', '--ipaddress', help='get information from an ip address', type=str, nargs=1)
    parser.add_argument('-m', '--myipaddress', help='get personal ip address', action='store_true')
    parser.add_argument('-n', '--network', help='get network information from an ip address', action='store_true')
    parser.add_argument('-g', '--geolocation', help='get geolocation information from an ip address',action='store_true')
    parser.add_argument('-s', '--security', help='get security information from an ip address', action='store_true')
    parser.add_argument('-w', '--whois', help='get whois information from an ip address', action='store_true')
    parser.add_argument('-c', '--category', help='divide the information by category', action='store_true')
    parser.add_argument('-j', '--json', help='save the output in json format', action='store_true')
    parser.add_argument('-f', '--file', help='save the output to a file', action='store_true')

    args = parser.parse_args()

    investigator = IPSherlock(args)
    investigator.run()
