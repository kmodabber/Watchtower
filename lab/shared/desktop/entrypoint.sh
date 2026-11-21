#!/bin/sh
# Desktop (Windows PC): fake Remote Desktop and VNC listeners.
# Fake listeners only

# Port 3389 (RDP): only needs to be open.
socat TCP-LISTEN:3389,fork,reuseaddr SYSTEM:'true' &

# Port 5900 (VNC): a real VNC server greets with an RFB version line
socat TCP-LISTEN:5900,fork,reuseaddr SYSTEM:'printf "RFB 003.008\n"' &