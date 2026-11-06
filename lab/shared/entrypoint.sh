#!/bin/sh
# Start this device's services, then keep the container alive.
# Each device supplies /etc/lab/entrypoint.sh (mounted from devices/<name>/).
set -e
sh /etc/lab/entrypoint.sh

# Keep the container running (listening for connections in background)
exec tail -f /dev/null