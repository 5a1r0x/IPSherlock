# Command Guide

## List

 - -h --help
 - -ip --ipaddress IPADDRESS
 - -d --delay DELAY
 - -c --category
 - -m --myipaddress
 - -n --network
 - -g --geolocation
 - -s --security
 - -w --whois
 - -wd --whoisdb
 - -ab --abuseipdb
 - -cp --criminalip
 - -vt --virustotal
 - -gn --greynoise
 - -ir --ipregistry
 - -gd --googledorks
 - -fk --fakeipaddress
 - -j --json
 - -f --file

## Examples
Show help message
```bash
python3 ipsherlock.py -h
```
Get personal IP Address
```bash
python3 ipsherlock.py -m
```
Get IP Address information from just one category
```bash
python3 ipsherlock.py -ip 1.1.1.1 -n
```
View output in JSON format
```bash
python3 ipsherlock.py -ip 1.1.1.1 -j
```
Save output to a file
```bash
python3 ipsherlock.py -ip 1.1.1.1 -f
```
Get IP Address information from API with category
```bash
python3 ipsherlock.py -ip 1.1.1.1 -ci -c
```
Generate fake IP Address
```bash
python3 ipsherlock.py -fk -c
```
