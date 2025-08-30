<div align="center">
  <img src="assets/ipsherlocklogo.png" alt="Logo" width="500">
</div>

<h1 align="center">IP Sherlock</h1>

<p align="center">
  <strong>IP Address Investigation and WHOIS Intelligence</strong>
</p>

<div align="center">

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-lightblue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Interface](https://img.shields.io/badge/Interface-Terminal%20%7C%20CLI-darkblue.svg)

</div>

## Major Features
```plaintext
• Multi Source Intelligence
• Multi Platform
• Forensic Analysis
• Privacy Protection
• Multiple Output Formats
• Enterprise Ready
```

## Project Structure

```plaintext
IPSherlock
├── assets/
│   └── ipsherlocklogo.png
├── docs/
│   ├── CHANGELOG.md
│   ├── COMMANDS.md
│   ├── CONTRIBUTING.md
│   ├── DISCLAIMER.md
│   └── PREREQUISITES.md
├── sherlock/
│   ├── ipsherlock.py
│   ├── ipsherlockfunc.py
│   ├── ipsherlockgraphic.py
│   ├── requirements.txt
│   └── sherlockey.env
├── .gitignore
├── LICENSE
├── README.md
└── 1.5
```

## Virtual Environment
Windows
```bash
python3 -m venv sherlockwindows
sherlockwindows\Scripts\activate.bat
```
Linux
```bash
python3 -m venv sherlocklinux
source sherlocklinux/bin/activate
```
MacOS
```bash
python3 -m venv sherlockmacos
source sherlockmacos/bin/activate
```

## Installation

```bash
git clone https://github.com/5a1r0x/IPSherlock.git
cd IPSherlock
cd sherlock
pip install -r requirements.txt
python3 ipsherlock.py -h
```

## Usage

```bash
usage: ipsherlock [-h] [-ip IPADDRESS] [-d DELAY] [-c] [-m] [-n] [-g] [-s] [-w] [-wd] [-ab] [-cp] [-vt] [-gn] [-ir]
                  [-gd] [-fk] [-j] [-f]

ip address investigation and whois intelligence

options:
  -h, --help            show this help message and exit
  -ip, --ipaddress IPADDRESS
                        get information from an ip address
  -d, --delay DELAY     delay before sending requests to apis
  -c, --category        divide the information by category
  -m, --myip            get personal ip addresses
  -n, --network         get network information
  -g, --geolocation     get geolocation information
  -s, --security        get security information
  -w, --whois           get whois information
  -wd, --whoisdb        get information from whois database
  -ab, --abuseipdb      get information from abuseipdb api
  -cp, --criminalip     get information from criminalip api
  -vt, --virustotal     get information from virustotal api
  -gn, --greynoise      get information from greynoise api
  -ir, --ipregistry     get information from ipregistry api
  -gd, --googledorks    get information from googledorks
  -fk, --fakeip         get fake and random ip addresses
  -j, --json            save the output in json format
  -f, --file            save the output in a file

use ethically and responsibly
```
