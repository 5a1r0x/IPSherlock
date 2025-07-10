# 🫧 Command Guide

## List

 - -h --help
 - -ip --ipaddress IPADDRESS
 - -t --time TIME
 - -m --myipaddress
 - -n --network
 - -g --geolocation
 - -s --security
 - -w --whois
 - -c --category
 - -a --abuseipdb
 - -ci --criminalip
 - -j --json
 - -f --file

## Examples
Show Help Message
```bash
python3 ipsherlock.py -h
```
Get Personal IP Address
```bash
python3 ipsherlock.py -m
```
Get IP Address Information From Just One Category
```bash
python3 ipsherlock.py -ip 1.1.1.1 -n
```
View Output In Json Format
```bash
python3 ipsherlock.py -ip 1.1.1.1 -j
```
Save Output To A File
```bash
python3 ipsherlock.py -ip 1.1.1.1 -f
```
Get IP Address Information From API With Category
```bash
python3 ipsherlock.py -ip 1.1.1.1 -ci -c
```
