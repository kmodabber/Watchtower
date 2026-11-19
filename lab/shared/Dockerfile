FROM alpine:3.20

RUN apk add --no-cache socat busybox-extras dnsmasq python3 py3-zeroconf

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]