<div align="center">
  <img src="IPSherlockSummer.png" alt="Logo" width="500">
</div>

<h1 align="center">IP Sherlock</h1>
<h3 align="center"><mark>Summer Edition</mark></h3>

<p align="center">
  <strong>IP Address Investigation and WHOIS Intelligence</strong>
</p>

<div align="center">

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-lightgreen)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-greem)](https://opensource.org/licenses/Apache-2.0)
![Platform](https://img.shields.io/badge/Platform-Terminal%20%7C%20CLI-darkgreen.svg)

</div>

## 🔥 Key Features

- Multi-Source Intelligence
- Forensic Analysis
- Privacy Protection
- Multiple Output Formats
- Enterprise Ready

## ⚓ Virtual Environment
Windows
```bash
python3 -m venv sherlock
sherlock\Scripts\activate.bat
```
Linux
```bash
python3 -m venv sherlock
source sherlock/bin/activate
```

## 🐝 Installation

```bash
git clone https://github.com/5a1r0x/IPSherlock.git
cd IPSherlock
pip install -r requirements.txt
python3 ipsherlock.py -h
```

## 🪁 Usage

```bash
usage: ipsherlock [-h] [-ip IPADDRESS] [-t TIME] [-c] [-m] [-n] [-g] [-s] [-w] [-wd] [-ab] [-ci] [-vt] [-gn] [-fk]
                  [-j] [-f]

ip address investigation and whois intelligence

options:
  -h, --help            show this help message and exit
  -ip, --ipaddress IPADDRESS
                        get information from an ip address
  -t, --time TIME       delay before sending requests to apis
  -c, --category        divide the information by category
  -m, --myipaddress     get personal ip addresses
  -n, --network         get network information
  -g, --geolocation     get geolocation information
  -s, --security        get security information
  -w, --whois           get whois information
  -wd, --whoisdb        get information from whois database
  -ab, --abuseipdb      get information from abuseipdb api
  -ci, --criminalip     get information from criminalip api
  -vt, --virustotal     get information from virustotal api
  -gn, --greynoise      get information from greynoise api
  -fk, --fakeipaddress  get fake ip addresses
  -j, --json            save the output in json format
  -f, --file            save the output to a file

use ethically and responsibly
```
