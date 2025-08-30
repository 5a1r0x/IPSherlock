#!/usr/bin/env python3

"""
Name: IP Sherlock
Version: 1.5
Developer: 5a1r0x
GitHub: https://github.com/5a1r0x/IPSherlock
YouTube: https://youtube.com/@SyroxModsOfficial
License: MIT
Powered by AI
"""

import os
import argparse
import ipaddress
import secrets
import socket
import json
import time
import random
import traceback
from ipsherlockfunc import *
from ipsherlockgraphic import *

try:
    import requests
    from ipwhois import IPWhois
    from dotenv import load_dotenv
    load_dotenv('sherlockey.env')
except ModuleNotFoundError as m:
    path = os.getcwd()
    files = os.listdir(path)
    if 'requirements.txt' in files:
        os.system('pip install -r requirements.txt')
    else:
        print(f"[ERROR] Unable to install the necessary module: '{m.name}'. Check the existence of the 'requirements.txt' file and its contents. Try to install the necessary module manually.")
except Exception as e:
    traceback.print_exc()
    IPSherlockGraphic.ERROR(e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ipsherlock',
        description='ip address investigation and whois intelligence',
        epilog='use ethically and responsibly'
    )

    parser.add_argument('-ip', '--ipaddress', help='get information from an ip address', type=str, nargs=1)
    parser.add_argument('-d', '--delay', help='delay before sending requests to apis', type=int)
    parser.add_argument('-c', '--category', help='divide the information by category', action='store_true')
    parser.add_argument('-m', '--myip', help='get personal ip addresses', action='store_true')
    parser.add_argument('-n', '--network', help='get network information', action='store_true')
    parser.add_argument('-g', '--geolocation', help='get geolocation information',action='store_true')
    parser.add_argument('-s', '--security', help='get security information', action='store_true')
    parser.add_argument('-w', '--whois', help='get whois information', action='store_true')
    parser.add_argument('-wd', '--whoisdb', help='get information from whois database', action='store_true')
    parser.add_argument('-ab', '--abuseipdb', help='get information from abuseipdb api', action='store_true')
    parser.add_argument('-cp', '--criminalip', help='get information from criminalip api', action='store_true')
    parser.add_argument('-vt', '--virustotal', help='get information from virustotal api', action='store_true')
    parser.add_argument('-gn', '--greynoise', help='get information from greynoise api', action='store_true')
    parser.add_argument('-ir', '--ipregistry', help='get information from ipregistry api', action='store_true')
    parser.add_argument('-gd', '--googledorks', help='get information from googledorks', action='store_true')
    parser.add_argument('-fk', '--fakeip', help='get fake and random ip addresses', action='store_true')
    parser.add_argument('-j', '--json', help='save the output in json format', action='store_true')
    parser.add_argument('-f', '--file', help='save the output in a file', action='store_true')

    args = parser.parse_args()

    investigator = IPSherlock(args)
    investigator.run()
