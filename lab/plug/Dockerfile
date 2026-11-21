FROM alpine:3.20

RUN apk add --no-cache mosquitto

COPY mosquitto.conf /etc/mosquitto/mosquitto.conf

CMD ["mosquitto", "-c", "/etc/mosquitto/mosquitto.conf"]
