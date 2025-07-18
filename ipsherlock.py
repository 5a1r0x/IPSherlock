#!/usr/bin/env python3

"""
Name: IP Sherlock
Version: 1.3
Developer: 5a1r0x
GitHub: https://github.com/5a1r0x/IPSherlock
License: Apache 2.0
Powered by AI
"""

import os
import argparse
from ipaddress import *
import secrets
import socket
import json
import time
import random

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
    if 'requirements.txt' in files:
        os.system('pip install -r requirements.txt')
    else:
        print(f"[E] Unable to install the necessary module: '{m.name}'. Check the existence of the 'requirements.txt' file and its contents. Otherwise try to install the necessary module manually.")

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

    REFERRERS = [
        'https://www.google.com/',
        'https://www.bing.com/',
        'https://duckduckgo.com/',
    ]

    def __init__(self, arg):
        self.arg = arg
        self.abuseipdbkey = os.getenv('ABUSEIPDB_API_KEY')
        self.criminalipkey = os.getenv('CRIMINALIP_API_KEY')
        self.virustotalkey = os.getenv('VIRUSTOTAL_API_KEY')
        self.graynoisekey = os.getenv('GREYNOISE_API_KEY')
        self.headers = self._generate_headers()
        self.ip = str(arg.ipaddress[0]) if hasattr(arg, 'ipaddress') and arg.ipaddress else None
        self.delay = int(arg.time[0]) if hasattr(arg, 'time') and arg.time else 0
        self.data1 = None
        self.data2 = None
        self.data3 = None
        self.data4 = None

    def _process_ip_info(self):
        """Process IP Information"""
        ip_obj = ipaddress.ip_address(self.ip)
        version = ip_obj.version
        bit_length = ipaddress.IPV4LENGTH if version == 4 else ipaddress.IPV6LENGTH
        byte_length = bit_length // 8

        # Try to get the host from the socket module, otherwise use the API
        try:
            host = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:
            host = self.data1.get('hostname', 'Unknown')

        # Privacy levels divided by anonymity
        privacy_levels = {
            'PROXY': 'Low',
            'VPN': 'Medium',
            'RELAY': 'Medium',
            'TOR': 'High',
            'I2P': 'High',
            'ANONYMIZER': 'High'
        }

        # Network type (API) and anonimity
        network_type = self.data3.get('type', '').upper()
        anonymity = privacy_levels.get(network_type, 'Low')

        # Objects
        return {
            'ip_obj': ip_obj,
            'version': version,
            'bit_length': bit_length,
            'byte_length': byte_length,
            'host': host,
            'anonymity': anonymity
        }

    def _generate_headers(self):
        """Generate random HTTP headers for requests"""
        return {
            "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Referer": secrets.choice(self.REFERRERS),
            "User-Agent": secrets.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }

    def _save_to_file(self, title, content):
        """Save output to a file"""
        filename = f"{title}IPv4.txt" if ":" not in self.ip else f"{title}IPv6.txt"
        try:
            with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(str(content))
            self.print_help(f"File Saved: {filename}")
        except IOError as e:
            self.print_error(f"File Save Failed: {e}")

    def _save_to_json(self, content):
        """Save output in JSON format"""
        try:
            print("", str(json.dumps(content, indent=2)))
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
 |_____|_|      |_____/|_| |_|\___|_|  |_|\___/ \___|_|\_\
 """)

    @staticmethod
    def print_info(label, value):
        """Information Message"""
        print(f"{Fore.CYAN} {label}{Fore.CYAN}:{Fore.RESET} {value}{Fore.RESET}")

    @staticmethod
    def print_error(msg):
        """Error Message"""
        print(f"{Fore.RED} [E] {msg}{Fore.RESET}")

    @staticmethod
    def print_help(msg):
        """Help Message"""
        print(f"{Fore.CYAN} [I] {msg}{Fore.RESET}")

    @staticmethod
    def clean_terminal():
        """Clean Terminal"""
        os.system('cls') if os.name == 'nt' else os.system('clear')

    def _fetch_ip_data(self):
        """Retrieve IP Data from free APIs"""
        try:
            time.sleep(self.delay)
            r1 = requests.get(
                f"https://ipinfo.io/{self.ip}/json",
                headers=self.headers,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay)
            r2 = requests.get(
                f"https://ipwho.is/{self.ip}",
                headers=self.headers,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay)
            r3 = requests.get(
                f"https://proxycheck.io/v2/{self.ip}&vpn=1&asn=1&risk=1&node=1",
                headers=self.headers,
                timeout=10,
                verify=True
            )
            time.sleep(self.delay)
            r4 = requests.get(
                f"https://api.ipapi.is/?q={self.ip}",
                headers=self.headers,
                timeout=10,
                verify=True
            )

            # Check if even one of the apis is not responding correctly, then give an error
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
                raise ConnectionError("; ".join(errors))

            # JSON Data
            self.data1 = r1.json()
            self.data2 = r2.json()
            self.data3 = r3.json().get(self.ip, {})
            self.data4 = r4.json()
            self.node = r3.json().get('node', 'Unknown')

        # Exceptions
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f'Network Error: {e}')
        except json.JSONDecodeError:
            raise ValueError('Invalid JSON response from API')

    def _my_ip_address(self):
        """Personal IP Address"""
        if self.arg.category:
            print(f"\n\033[38;5;27m P E R S O N A L I P\n")

        try:
            time.sleep(self.delay)
            ipv4 = requests.get(url=f"https://ipinfo.io/json", headers=self.headers,
                                timeout=10,
                                verify=True
                                )

            # Force the acquisition of the IPv4 Address
            ip4 = ipv4.json()
            self.print_info('IPv4', ip4.get('ip', 'Unknown'))

            # IPv6 Address
            time.sleep(self.delay)
            ipv6 = requests.get(url=f"https://v6.ident.me", headers=self.headers,
                                timeout=10,
                                verify=True
                                )

            # Response to the request in text format
            ip6 = ipv6.text

            # Get the IPv6 Address if available
            self.print_info('IPv6', ip6 if ip6 else 'Unknown')

            # Parameters not available (useless)
            if self.arg.json or self.arg.file:
                self.print_help('Parameters not available for this command')

        # Exceptions
        except requests.exceptions.RequestException:
            self.print_info('IPv6', "Unknown (No Connectivity)")
        except Exception as e:
            self.print_error(e)

    def _display_network_info(self, ip_info):
        """Display network information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m N E T W O R K\n")

        try:
            # Try to get the domain from the API, otherwise check that it is not present or none
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

            # File Output
            if self.arg.file:
                self._save_to_file('Network', network_information)
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
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(e)

    def _display_geolocation(self):
        """Display geolocation information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m G E O L O C A T I O N\n")

        try:
            # Try to get the currency from the API with his name, value and format
            currency = self.data3.get('currency', {})
            currency_str = f"{currency.get('name', 'Unknown')} {currency.get('code', 'Unknown')} {currency.get('symbol', '')}"

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
                'Phone Prefix': "+" + self.data2.get('calling_code', 'Unknown')
            }

            # File Output
            if self.arg.file:
                self._save_to_file('Geolocation', geolocation_information)
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
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(e)

    def _display_security_info(self, anonymity):
        """Display security information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m S E C U R I T Y\n")

        try:
            security_information = {
                'Connection': self.data3.get('type', 'Unknown'),
                'Anonimity': anonymity,
                'Risk': self.data3.get('risk', 'Unknown'),
                'Bogon': 'Yes' if self.data4.get('is_bogon', 'Unknown') else 'No',
                'Mobile': 'Yes' if self.data4.get('is_mobile', 'Unknown') else 'No',
                'Satellite': 'Yes' if self.data4.get('is_satellite', 'Unknown') else 'No',
                'Crawler': 'Yes' if self.data4.get('is_crawler', 'Unknown') else 'No',
                'Data Center': 'Yes' if self.data4.get('is_datacenter', 'Unknown') else 'No',
                'Tor': 'Yes' if self.data4.get('is_tor', 'Unknown') else 'No',
                'Proxy': 'Yes' if self.data4.get('is_proxy', 'Unknown') else 'No',
                'Abuser': 'Yes' if self.data4.get('is_abuser', 'Unknown') else 'No'
            }

            # File Output
            if self.arg.file:
                self._save_to_file('Security',security_information)
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
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(e)

    def _display_whois_info(self):
        """Display whois information"""
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
                self._save_to_file('WHOIS', whois_information)
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
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(f"WHOIS Lookup Failed: {e}")
            # Download 'whois' package for termux
            self.print_help("I'm trying to download the built-in 'whois' package...")
            try:
                os.system(f'pkg install whois')
                self.print_help("Package 'whois' successfully installed. Use whois <IP Address>.")
            except Exception as e:
                self.print_error(e)

    def _private_ip_address(self):
        """Private IP Address information"""
        if self.arg.category:
            print(f"\n\033[38;5;27m P R I V A T E I P\n")

        try:
            private_information = {
                'IP Address': self.ip,
                'Name': 'Internet Protocol',
                'Interface': str(ipaddress.ip_interface(self.ip)),
                'Private': 'Yes'
            }

            # File Output
            if self.arg.file:
                self._save_to_file('Private', private_information)
                return

            # JSON Output
            elif self.arg.json:
                self._save_to_json(private_information)
                return

            # Terminal Output
            for i, info in private_information.items():
                self.print_info(f"{i}", f"{info}")

        # Exception
        except Exception as e:
            self.print_error(e)

    def _abuse_ipdb_info(self):
        """(API) AbuseIPDB information"""
        global abuse

        if self.arg.category:
            print(f"\n\033[38;5;27m A B U S E I P D B\n")

        self.print_help("Free Plan: 1000 Lookups/Day\n")

        try:
            abuse_headers = {
                "Key": self.abuseipdbkey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(self.REFERRERS),
                "User-Agent": secrets.choice(self.USER_AGENTS),
                "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay)
            abuse = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.ip}&maxAgeInDays=90",
                headers=abuse_headers,
                timeout=10,
                verify=True
            )

            ipdb = abuse.json()
            print("", json.dumps(ipdb, indent=2))

            # Check if the user has exceeded the maximum limit of allowed check
            if abuse.status_code == 429:
                self.print_error("Daily check exceeded")
                self.print_help("Request a new API key or upgrade your plan")

            # Check if the user is unauthorized
            if abuse.status_code == 401:
                self.print_error("Unauthorized")
                self.print_help("Check or update your API key")

            # File Output
            if self.arg.file:
                self._save_to_file('AbuseIPDB', ipdb)

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(f"{e} | {abuse.status_code} {abuse.reason}")
            self.print_help(f"Check your AbuseIPDB API key in 'sherlockey.env' file. Check the status of the website.")

    def _criminal_ip_info(self):
        """(API) CriminalIP information"""
        global criminal

        if self.arg.category:
            print(f"\n\033[38;5;27m C R I M I N A L I P\n")

        self.print_help("Free Plan: 50 Lookups/Month\n")

        try:
            criminal_headers = {
                "x-api-key": self.criminalipkey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(self.REFERRERS),
                "User-Agent": secrets.choice(self.USER_AGENTS),
                "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay)
            criminal = requests.get(
                f"https://api.criminalip.io/v1/asset/ip/report?ip={self.ip}&full=true",
                headers=criminal_headers,
                timeout=10,
                verify=True
            )

            # Check if the IP Address version is 6 (not supported)
            if ":" in self.ip:
                self.print_error("IPv6 Address checking not supported")
                return

            crimip = criminal.json()
            print("", json.dumps(crimip, indent=2))

            # Check if the user has exceeded the maximum limit available credits
            if crimip.get('message', 'Unknown') == 'limit exceeded':
                self.print_error("Available credit limit exceeded")
                self.print_help("Request a new API key or upgrade your plan")

            # Check if the user is unauthorized
            if criminal.status_code == 401:
                self.print_error("Unauthorized")
                self.print_help("Check or update your API key")

            # File Output
            if self.arg.file:
                self._save_to_file('CriminalIP', crimip)

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(f"{e} | {criminal.status_code} {criminal.reason}")
            self.print_help(f"Check your Criminal IP API key in 'sherlockey.env' file. Check the status of the website.")

    def _virus_total_info(self):
        """(API) VirusTotal information"""
        global virustotal

        if self.arg.category:
            print(f"\n\033[38;5;27m V I R U S T O T A L\n")

        self.print_help("Free Plan: 500 Lookups/Day\n")

        try:
            vt_headers = {
                "x-apikey": self.virustotalkey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(self.REFERRERS),
                "User-Agent": secrets.choice(self.USER_AGENTS),
                "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay)
            virustotal = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip}",
                headers=vt_headers,
                timeout=10,
                verify=True
            )

            vtip = virustotal.json()
            print("", json.dumps(vtip, indent=2))

            # Check if the user has exceeded the maximum lookups available
            if virustotal.status_code == 429:
                self.print_error("Available lookups limit exceeded")
                self.print_help("Request a new API key or upgrade your plan")

            # Check if the user is unauthorized
            if virustotal.status_code == 401:
                self.print_error("Unauthorized")
                self.print_help("Check or update your API key")

            # File Output
            if self.arg.file:
                self._save_to_file('VirusTotal', vtip)

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(f"{e} | {virustotal.status_code} {virustotal.reason}")
            self.print_help(f"Check your VirusTotal API key in 'sherlockey.env' file. Check the status of the website.")

    def _global_database_info(self):
        """(API) IPApi global database information"""
        global whoisdatabase

        if self.arg.category:
            print(f"\n\033[38;5;27m W H O I S D A T A B A S E\n")

        try:
            ripedb_headers = {
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(self.REFERRERS),
                "User-Agent": secrets.choice(self.USER_AGENTS),
                "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            # Send a request to get the asn
            time.sleep(self.delay)
            whoisdatabase_asn = requests.get(
                f"https://api.ipapi.is/?q={self.ip}",
                headers=ripedb_headers,
                timeout=10,
                verify=True
            )
            # Get the asn
            asn_result = whoisdatabase_asn.json()['asn']['asn']

            # Send a request to get the global database information with asn
            time.sleep(self.delay)
            whoisdatabase = requests.get(
                f"https://api.ipapi.is/?whois=AS{as_result}",
                headers=ripedb_headers,
                timeout=10,
                verify=True
            )

            # Print the result
            rpdb = whoisdatabase.text
            print(rpdb)

            # File Output
            if self.arg.file:
                self._save_to_file('WhoisDatabase', rpdb)

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(f"Database: {e} | {whoisdatabase.status_code} {whoisdatabase.reason}")
            self.print_error(f"IPApi: {e} | {whoisdatabase_asn.status_code} {whoisdatabase_asn.reason}")

    def _greynoise_ip_info(self):
        """(API) GreyNoise IP information"""
        global greynoise

        if self.arg.category:
            print(f"\n\033[38;5;27m G R E Y N O I S E\n")

        self.print_help("Free Plan: 25 Lookups/Time\n")

        try:
            gndb_headers = {
                "key": self.graynoisekey,
                "Accept-Language": secrets.choice(["it-IT,it;q=0.9", "en-US,en;q=0.9", "fr-FR,fr;q=0.8"]),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": secrets.choice(self.REFERRERS),
                "User-Agent": secrets.choice(self.USER_AGENTS),
                "Accept": "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }

            time.sleep(self.delay)
            greynoise = requests.get(
                f"https://api.greynoise.io/v3/community/{self.ip}",
                headers=gndb_headers,
                timeout=10,
                verify=True
            )

            # Check if the IP Address version is 6 (not supported)
            if ":" in self.ip:
                self.print_error("IPv6 Address checking not supported")
                return

            gndb = greynoise.json()
            print("", json.dumps(gndb, indent=2))

            # Check if the user has exceeded the maximum limit of allowed lookups
            if greynoise.status_code == 429:
                self.print_error("Maximum lookups exceeded")
                self.print_help("Request a new API key or upgrade your plan")

            # Check if the user is unauthorized
            if greynoise.status_code == 401:
                self.print_error("Unauthorized")
                self.print_help("Check or update your API key")

            # File Output
            if self.arg.file:
                self._save_to_file('GreyNoise', gndb)

        # Exceptions
        except requests.exceptions.RequestException as re:
            self.print_error(f"Request: {re}")
        except Exception as e:
            self.print_error(f"{e} | {greynoise.status_code} {greynoise.reason}")
            self.print_help(f"Check your GreyNoise API key in 'sherlockey.env' file. Check the status of the website.")

    def _fakeipaddress_info(self):
        """Generate fake IP Addresses"""

        if self.arg.category:
            print(f"\n\033[38;5;27m F A K E I P A D D R E S S\n")

        self.print_help('These IP addresses are fake and randomly generated\n')

        fake_ip = {
            'IPv4': str(IPv4Address(random.getrandbits(32))),
            'IPv6': str(IPv6Address(random.getrandbits(128)))
        }

        # Parameter to avoid errors during the saving of the file because ip is required
        self.ip = '.'

        # File Output
        if self.arg.file:
            self._save_to_file('FakeIPAddress', fake_ip)
            return

        # JSON Output
        if self.arg.json:
            print("", json.dumps(fake_ip, indent=2))
            return

        # Terminal Output
        for f, fakeip in fake_ip.items():
            self.print_info(f"{f}", f"{fakeip}")

    def run(self):
        try:
            self.clean_terminal()
            self.logo()

            # Personal IP Address
            if self.arg.myipaddress:
                self._my_ip_address()
                return

            # Fake IP Address
            if self.arg.fakeipaddress:
                self._fakeipaddress_info()
                return

            # Check if IP Address is provided
            if not self.ip:
                self.print_error('No IP Address provided')
                self.print_help('Use -ip <IP Address>')
                return

            # Private IP Address
            if ipaddress.ip_address(self.ip).is_private:
                self._private_ip_address()
                return

            # (API JSON) AbuseIPDB
            if self.arg.abuseipdb:
                self._abuse_ipdb_info()
                return

            # (API JSON) CriminalIP
            if self.arg.criminalip:
                self._criminal_ip_info()
                return

            # (API JSON) VirusTotal
            if self.arg.virustotal:
                self._virus_total_info()
                return

            # (WHOIS DATABASE) IpApi
            if self.arg.whoisdb:
                self._global_database_info()
                return

            # (API JSON) GreyNoise Community
            if self.arg.greynoise:
                self._greynoise_ip_info()
                return

            # Process IP Information
            self._fetch_ip_data()
            ip_info = self._process_ip_info()

            # Display selected categories
            if any([self.arg.network, self.arg.geolocation, self.arg.security, self.arg.whois, self.arg.myipaddress]):
                if self.arg.network:
                    self._display_network_info(ip_info)
                if self.arg.geolocation:
                    self._display_geolocation()
                if self.arg.security:
                    self._display_security_info(ip_info['anonymity'])
                if self.arg.whois:
                    self._display_whois_info()
                if self.arg.myipaddress:
                    self._my_ip_address()
            # Display all categories
            else:
                self._display_network_info(ip_info)
                self._display_geolocation()
                self._display_security_info(ip_info['anonymity'])
                self._display_whois_info()

        # Exceptions
        except KeyboardInterrupt:
            self.print_help('IPSherlock Interrupted')
        except Exception as e:
            self.print_error(e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ipsherlock',
        description='ip address investigation and whois intelligence',
        epilog='use ethically and responsibly'
    )

    parser.add_argument('-ip', '--ipaddress', help='get information from an ip address', type=str, nargs=1)
    parser.add_argument('-t', '--time', help='delay before sending requests to apis', type=int, nargs=1)
    parser.add_argument('-c', '--category', help='divide the information by category', action='store_true')
    parser.add_argument('-m', '--myipaddress', help='get personal ip addresses', action='store_true')
    parser.add_argument('-n', '--network', help='get network information', action='store_true')
    parser.add_argument('-g', '--geolocation', help='get geolocation information',action='store_true')
    parser.add_argument('-s', '--security', help='get security information', action='store_true')
    parser.add_argument('-w', '--whois', help='get whois information', action='store_true')
    parser.add_argument('-wd', '--whoisdb', help='get information from whois database', action='store_true')
    parser.add_argument('-ab', '--abuseipdb', help='get information from abuseipdb api', action='store_true')
    parser.add_argument('-ci', '--criminalip', help='get information from criminalip api', action='store_true')
    parser.add_argument('-vt', '--virustotal', help='get information from virustotal api', action='store_true')
    parser.add_argument('-gn', '--greynoise', help='get information from greynoise api', action='store_true')
    parser.add_argument('-fk', '--fakeipaddress', help='get fake ip addresses', action='store_true')
    parser.add_argument('-j', '--json', help='save the output in json format', action='store_true')
    parser.add_argument('-f', '--file', help='save the output to a file', action='store_true')

    args = parser.parse_args()

    investigator = IPSherlock(args)
    investigator.run()
