#!/usr/bin/env python3

"""
Name: IP Sherlock
Version: 1.1
Developer: 5a1r0x
GitHub: https://github.com/5a1r0x/IPSherlock
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
    from dotenv import load_dotenv
    load_dotenv("sherlockey.env")
    from colorama import init, Fore, Style
    init(autoreset=True)
except ModuleNotFoundError as m:
    path = os.getcwd()
    files = os.listdir(path)
    if "requirements.txt" in files:
        os.system("pip install -r requirements.txt")
    else:
        print(f"[E] Unable to install the necessary modules ({m}). Check the existence of the requirements.txt file and its contents.")

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
        self.abuseipdbkey = os.getenv("ABUSEIPDB_API_KEY") # 1000 R/DAY (FREE TIER)
        self.criminalipkey = os.getenv("CRIMINALIP_API_KEY") # 50 R/MONTH (FREE TIER)
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

    def _save_to_file(self, content):
        """Save Output To File"""
        print(" F I L E\n")
        filename = f"IPSherlockIPv4.txt" if ":" not in self.ip else f"IPSherlockIPv6.txt"
        try:
            with open(filename, "w", encoding='utf-8', errors='ignore') as f:
                f.write(str(content))
            self.print_success(f"File Saved: {filename}")
        except IOError as e:
            self.print_error(f"File Save Failed: {e}")

    def _save_to_json(self, content):
        """Save Output In Json Format"""
        print(" J S O N\n")
        try:
            print(str(json.dumps(content, indent=2)))
        except Exception as e:
            self.print_error(e)

    @staticmethod
    def logo():
        print("\033[38;5;27m" + r"""
  _____ _____     _____ _               _            _    
 |_   _|  __ \   / ____| |             | |          | |   
   | | | |__) | | (___ | |__   ___ _ __| | ___   ___| | __
   | | |  ___/   \___ \| '_ \ / _ \ '__| |/ _ \ / __| |/ /
  _| |_| |       ____) | | | |  __/ |  | | (_) | (__|   <
 |_____|_|      |_____/|_| |_|\___|_|  |_|\___/ \___|_|\_\ """)

    @staticmethod
    def print_info(label, value):
        print(f"{Fore.CYAN} {label}{Fore.CYAN}:{Fore.RESET} {value}{Fore.RESET}")

    @staticmethod
    def print_error(msg):
        print(f"{Fore.RED} [E] {msg}{Fore.RESET}")

    @staticmethod
    def print_success(msg):
        print(f"{Fore.GREEN} [S] {msg}{Fore.RESET}")

    @staticmethod
    def print_help(msg):
        print(f"{Fore.YELLOW} [I] {msg}{Fore.RESET}")

    @staticmethod
    def clean_terminal():
        os.system('cls') if os.name == 'nt' else os.system('clear')

    def _fetch_ip_data(self):
        """Retrieve IP Data From External Urls"""
        try:
            time.sleep(self.delay)
            r1 = requests.get(
                f"https://ipinfo.io/{self.ip}/json",
                headers=self.headers,
                stream=True,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay)
            r2 = requests.get(
                f"https://ipwho.is/{self.ip}",
                headers=self.headers,
                stream=True,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay)
            r3 = requests.get(
                f"https://proxycheck.io/v2/{self.ip}&vpn=1&asn=1&risk=1&node=1",
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

        # Exceptions
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Network Error: {e}")
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON Response From API")

    def _my_ip_address(self):
        """Personal IP Address"""
        try:
            time.sleep(self.delay)
            ipv4 = requests.get(url=f"https://ipinfo.io/json", headers=self.headers, stream=True, timeout=10,
                                verify=True)

            # Force IPv4
            ip4 = ipv4.json()
            self.print_info('IPv4', ip4["ip"])

            time.sleep(self.delay)
            ipv6 = requests.get(url=f"https://api6.myip.com/", headers=self.headers, stream=True, timeout=10,
                                verify=True)

            ip6 = ipv6.json()

            ipaddress_information = {
                'IPv4': ip4.get("ip", "Unknown"),
                'IPv6': ip6.get("ip", "Unknown")
            }

            # File Output
            if self.arg.file:
                self._save_to_file(ipaddress_information)
                return

            # JSON Output
            elif self.arg.json:
                self._save_to_json(ipaddress_information)
                return

            # Terminal Output
            for i, info in ipaddress_information.items():
                self.print_info(f"{i}", f"{info}")

        # Exceptions
        except requests.exceptions.RequestException:
            self.print_info("IPv6", "Unknown (No Connectivity)")
        except Exception as e:
            self.print_error(e)

    def _process_ip_info(self):
        """Process the main IP Information"""
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
        """Display Network Information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m N E T W O R K\n")

        try:
            domain = self.data2.get("connection", {}).get("domain", "Unknown")
            if domain == "" or not domain:
                domain = "Unknown"

            network_information = {
                'IP Address': self.data1.get("ip", "Unknown"),
                'Name': 'Internet Protocol',
                'Version': ip_info["version"],
                'Bit': ip_info["bit_length"],
                'Byte': ip_info["byte_length"],
                'Interface': str(ipaddress.ip_interface(self.ip)),
                'Private': "Yes" if ip_info["ip_obj"].is_private else "No",
                'Link Local': "Yes" if ip_info["ip_obj"].is_link_local else "No",
                'Global': "Yes" if ip_info["ip_obj"].is_global else "No",
                'Local Host': "Yes" if ip_info["ip_obj"].is_loopback else "No",
                'Multicast': "Yes" if ip_info["ip_obj"].is_multicast else "No",
                'Reserved': "Yes" if ip_info["ip_obj"].is_reserved else "No",
                'Unspecified': "Yes" if ip_info["ip_obj"].is_unspecified else "No",
                'Host': ip_info["host"],
                'Domain': domain,
                'Provider': self.data3.get("provider", "Unknown"),
                'Organization': self.data1.get("org", "Unknown"),
                'Device': self.data3.get("devices", {}).get("address", "Unknown"),
                'Subnet': self.data3.get("devices", {}).get("subnet", "Unknown")
            }

            # File Output
            if self.arg.file:
                self._save_to_file(network_information)
                return

            # JSON Output
            elif self.arg.json:
                self._save_to_json(network_information)
                return

            # Terminal Output
            for i, info in network_information.items():
                self.print_info(f"{i}", f"{info}")

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Network: {re}")
        except Exception as e:
            self.print_error(e)

    def _display_geolocation(self):
        """Display Geolocation Information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m G E O L O C A T I O N\n")

        try:
            currency = self.data3.get("currency", {})
            currency_str = f"{currency.get('name', 'Unknown')} {currency.get('code', 'Unknown')} {currency.get('symbol', '')}"

            geolocation_information = {
                'City': self.data1.get("city", "Unknown"),
                'Region': self.data1.get("region", "Unknown"),
                'Country': self.data3.get("country", "Unknown"),
                'Continent': self.data3.get("continent", "Unknown"),
                'ISO Code': self.data3.get("isocode", "Unknown"),
                'Postal Code': self.data2.get("postal", "Unknown"),
                'Current Time': self.data2.get("timezone", {}).get("current_time", "Unknown"),
                'Latitude': self.data3.get("latitude", "Unknown"),
                'Longitude': self.data3.get("longitude", "Unknown"),
                'Currency': currency_str
            }

            # File Output
            if self.arg.file:
                self._save_to_file(geolocation_information)
                return

            # JSON Output
            elif self.arg.json:
                self._save_to_json(geolocation_information)
                return

            # Terminal Output
            for i, info in geolocation_information.items():
                self.print_info(f"{i}", f"{info}")

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Network: {re}")
        except Exception as e:
            self.print_error(e)

    def _display_security_info(self, anonymity):
        """Display Security Information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m S E C U R I T Y\n")

        try:
            security_information = {
                'Node': self.node,
                'Connection': self.data3.get("type", "Unknown"),
                'Anonimity': anonymity,
                'Risk': self.data3.get("risk", "Unknown")
            }

            # File Output
            if self.arg.file:
                self._save_to_file(security_information)
                return

            # JSON Output
            elif self.arg.json:
                self._save_to_json(security_information)
                return

            # Terminal Output
            for i, info in security_information.items():
                self.print_info(f"{i}", f"{info}")

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Network: {re}")
        except Exception as e:
            self.print_error(e)

    def _display_whois_info(self):
        """Display Whois Information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m W H O I S\n")

        try:
            obj = IPWhois(self.ip)
            results = obj.lookup_rdap()

            whois_information = {
                'CIDR': results.get('network', {}).get('cidr'),
                'ASN': results.get('asn'),
                'ASN Description': results.get('asn_description'),
                'ASN Country Code': results.get('asn_country_code'),
                'Name': results.get('network', {}).get('name'),
                'Handle': results.get('network', {}).get('handle'),
                'Type': results.get('network', {}).get('type'),
                'Status': results.get('network', {}).get('status'),
                'Country': results.get('network', {}).get('country'),
                'Start Address': results.get('network', {}).get('start_address'),
                'End Address': results.get('network', {}).get('end_address'),
                'Entities': results.get('entities'),
                'Links': results.get('links'),
                'Events': results.get('events')
            }

            # File Output
            if self.arg.file:
                self._save_to_file(whois_information)
                return

            # JSON Output
            elif self.arg.json:
                self._save_to_json(whois_information)
                return

            # Terminal Output
            for i, info in whois_information.items():
                self.print_info(f"{i}", f"{info}")

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Network: {re}")
        except Exception as e:
            self.print_error(f"WHOIS Lookup Failed: {e}")
            self.print_help("If you are on termux use the 'pkg install whois' command to install the integrated whois package")

    def _abuse_ipdb_info(self):
        """(API) AbuseIPDB Information"""
        global abuse

        if self.arg.category:
            print(f"\n\033[38;5;27m A B U S E I P D B\n")

        try:
            abuse_headers = {
                "Key": self.abuseipdbkey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(self.REFERERS),
                "User-Agent": secrets.choice(self.USER_AGENTS),
                "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache" }

            time.sleep(self.delay)
            abuse = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.ip}&maxAgeInDays=90",
                headers=abuse_headers,
                timeout=10,
                stream=True,
                verify=True)

            ipdb = abuse.json()
            print(ipdb)

            # File Output
            if self.arg.file:
                self._save_to_file(ipdb)

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(f"{e} | {abuse.status_code} {abuse.reason}")
            self.print_help(f"Check your AbuseIPDB API Key in 'sherlockey.env' file. Check the status of the website.")

    def _criminal_ip_info(self):
        """(API) CriminalIP Information"""
        global criminal

        if self.arg.category:
            print(f"\n\033[38;5;27m C R I M I N A L I P\n")

        try:
            criminal_headers = {
                "x-api-key": self.criminalipkey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(self.REFERERS),
                "User-Agent": secrets.choice(self.USER_AGENTS),
                "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache" }

            time.sleep(self.delay)
            criminal = requests.get(
                f"https://api.criminalip.io/v1/asset/ip/report?ip={self.ip}",
                headers=criminal_headers,
                timeout=10,
                stream=True,
                verify=True)

            if ":" in self.ip:
                self.print_error("IPv6 Address Checking Not Available")
                return

            crimip = criminal.json()
            print(crimip)

            # File Output
            if self.arg.file:
                self._save_to_file(crimip)

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(f"{e} | {criminal.status_code} {criminal.reason}")
            self.print_help(f"Check your Criminal IP API Key in 'sherlockey.env' file. Check the status of the website.")

    def run(self):
        try:
            self.clean_terminal()
            self.logo()

            # Personal IP Address
            if self.arg.myipaddress:
                self._my_ip_address()
                return

            # AbuseIPDB
            if self.arg.abuseipdb:
                self._abuse_ipdb_info()
                return

            # CriminalIP
            if self.arg.criminalip:
                self._criminal_ip_info()
                return

            # Process IP Information
            self._fetch_ip_data()
            ip_info = self._process_ip_info()

            # Display Selected Categories
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
            # Display All Categories
            else:
                self._display_network_info(ip_info)
                self._display_geolocation()
                self._display_security_info(ip_info["anonymity"])
                self._display_whois_info()

        # Exception
        except Exception as e:
            self.print_error(e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ipsherlock',
        description='ip address investigation and whois intelligence',
        epilog='use ethically and responsibly'
    )

    parser.add_argument('-ip', '--ipaddress', help='get information from an ip address', type=str, nargs=1)
    parser.add_argument('-t', '--time', help='delay before sending the request to apis', type=int, nargs=1)
    parser.add_argument('-m', '--myipaddress', help='get personal ip address', action='store_true')
    parser.add_argument('-n', '--network', help='get network information from an ip address', action='store_true')
    parser.add_argument('-g', '--geolocation', help='get geolocation information from an ip address',action='store_true')
    parser.add_argument('-s', '--security', help='get security information from an ip address', action='store_true')
    parser.add_argument('-w', '--whois', help='get whois information from an ip address', action='store_true')
    parser.add_argument('-c', '--category', help='divide the information by category', action='store_true')
    parser.add_argument('-a', '--abuseipdb', help='get information from abuseipdb api', action='store_true')
    parser.add_argument('-ci', '--criminalip', help='get information from criminalip api', action='store_true')
    parser.add_argument('-j', '--json', help='save the output in json format', action='store_true')
    parser.add_argument('-f', '--file', help='save the output to a file', action='store_true')

    args = parser.parse_args()

    investigator = IPSherlock(args)
    investigator.run()
