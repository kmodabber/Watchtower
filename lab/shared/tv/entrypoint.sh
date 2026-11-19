#!/bin/sh
# Smart TV: Cast ports plus an mDNS announcement. Clean device: no findings.

# Port 8008: real httpd so Nmap reports "http".
httpd -f -p 8008 -h /etc/lab/http &

# Ports 8009 and 8443: only need to be open.
socat TCP-LISTEN:8009,fork,reuseaddr SYSTEM:'true' &
socat TCP-LISTEN:8443,fork,reuseaddr SYSTEM:'true' &

# Announce _googlecast._tcp over mDNS.
python3 /etc/lab/announce.py &