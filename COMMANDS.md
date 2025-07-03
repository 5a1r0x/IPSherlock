# Command Guide

## 📜 List

 - -h --help
 - -ip --ipaddress IPADDRESS
 - -m --myipaddress
 - -n --network
 - -g --geolocation
 - -s --security
 - -w --whois
 - -c --category
 - -j --json
 - -f --file
 - -t --time TIME

## 🫧 Example
Lists all IP information divided by category
```bash
python3 ipsherlock.py -ip 1.1.1.1 -c
```
Get your IP address
```bash
python3 ipsherlock.py -m
```
Get only the information from the security category
```bash
python3 ipsherlock.py -ip 1.1.1.1 -s
```
View output in json format
```bash
python3 ipsherlock.py -ip 1.1.1.1 -j
```
Save the output (json format) to a file
```bash
python3 ipsherlock.py -ip 1.1.1.1 -f
```
File Output <br> IPv4: IPSherlock_IPv4Address.txt <br> IPv6: IPSherlock_IPv6.txt
