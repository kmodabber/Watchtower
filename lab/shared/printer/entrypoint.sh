#!/bin/sh
# Printer: web page over plain HTTP, IPP and raw print port (banner-only).

# Port 80: real busybox httpd, so Nmap identifies it as HTTP.
httpd -f -p 80 -h /etc/lab/http &

# Port 631 (IPP): answers with an HTTP-style banner, then closes.
socat TCP-LISTEN:631,fork,reuseaddr \
  SYSTEM:'printf "HTTP/1.0 200 OK\r\nServer: CUPS/2.4 IPP/2.1\r\n\r\n"' &

# Port 9100 (raw print): only needs to be open.
socat TCP-LISTEN:9100,fork,reuseaddr SYSTEM:'true' &