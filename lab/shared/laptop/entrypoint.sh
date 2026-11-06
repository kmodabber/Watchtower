#!/bin/sh
# Laptop: SSH only. Clean device, must raise no findings.
socat TCP-LISTEN:22,fork,reuseaddr \
    SYSTEM:'printf "SSH-2.0-OpenSSH_9.6\r\n"' &