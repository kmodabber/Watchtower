#!/bin/sh

# Reads the list of services and opens a TCP listerner per line then sends payload to anyone who connects
while IFS='|' read -r port payload; do

  # Skip blank lines and comments.
  case "$port" in ''|\#*) continue ;; esac

    #Run in background subshell
    (
        # Pass the banner via environment to avoid shell injection issues
        export PAYLOAD="$payload"

        # Start a TCP listener on the specified port and send the payload to any incoming connection
        exec socat TCP-LISTEN:"$port",fork,reuseaddr \
            SYSTEM:'printf "%b" "$PAYLOAD"' <dev/null
    ) &

done < /etc/lab/services.txt

# Keep the container running (listening for connections in background)
exec tail -f /dev/null