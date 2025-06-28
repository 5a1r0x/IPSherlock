<p align="center">
  <img src="IPSherlock.png" alt="IPSherlock Logo" width="600"/>
</p>

<h1 align="center">IP Sherlock</h1>

<p align="center">
  <strong>IP Address Investigation and WHOIS Intelligence</strong>
</p>

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](https://opensource.org/licenses/Apache-2.0)

</div>

## 🚀 Key Features

- Multi-Source Intelligence
- Forensic Analysis
- Privacy Protection
- Multiple Output Formats
- Enterprise Ready

## ⚓ Virtual Environment
Windows
```bash
python3 -m venv ipsherlock
ipsherlock\Scripts\activate.bat
```
Linux
```bash
python3 -m venv ipsherlock
source ipsherlock/bin/activate
```

## 📦 Installation

```bash
git clone https://github.com/5a1r0x/IPSherlock.git
cd IPSherlock
pip install -r requirements.txt
python3 ipsherlock.py
```

## 🪁 Usage

```bash
usage: ipsherlock [-h] -ip IPADDRESS [-n] [-g] [-s] [-w] [-c] [-j] [-f]

ip address investigation and whois intelligence

options:
  -h, --help            show this message and exit
  -ip, --ipaddress IPADDRESS
                        get information from an ip address
  -n, --network         get network information from an ip address
  -g, --geolocation     get geolocation information from an ip address
  -s, --security        get security information from an ip address
  -w, --whois           get whois information from an ip address
  -c, --category        divide the information by category
  -j, --json            save the output in json format
  -f, --file            save the output to a file

use ethically and responsibly
```
