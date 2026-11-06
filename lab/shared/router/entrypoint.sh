#!/bin/sh
# Router: DNS, web admin over plain HTTP, UPnP description.
dnsmasq --conf-file=/etc/lab/dnsmasq.conf        # port 53 (forks into background)

httpd -f -p 80   -h /etc/lab/http &              # RF-HTTP-ADMIN

httpd -f -p 5000 -h /etc/lab/upnp &              # RF-UPNP