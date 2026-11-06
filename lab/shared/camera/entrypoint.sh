#!/bin/sh
# Camera: telnet, web admin over plain HTTP, RTSP (open port only).
telnetd -F -p 23 &                               # RF-TELNET

httpd -f -p 80 -h /etc/lab/http &                 # RF-HTTP-ADMIN

socat TCP-LISTEN:554,fork,reuseaddr \             
    SYSTEM:'printf "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"' &