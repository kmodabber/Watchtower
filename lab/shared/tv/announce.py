"""Announce this container as a Google Cast TV over mDNS. Lab use only."""

import logging
import socket
import time

from zeroconf import ServiceInfo, Zeroconf

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("announce")

SERVICE_TYPE = "_googlecast._tcp.local."


def main() -> None:
    ip = socket.gethostbyname(socket.gethostname())
    info = ServiceInfo(
        SERVICE_TYPE,
        f"Living-Room-TV.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(ip)],
        port=8009,
        properties={"fn": "Living Room TV", "md": "Chromecast"},
        server="living-room-tv.local.",
    )
    # Bind to the container's own IP: the internal network has no default route.
    zeroconf = Zeroconf(interfaces=[ip])
    zeroconf.register_service(info)
    log.info("announcing %s on %s", SERVICE_TYPE, ip)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
