FROM alpine:3.20

RUN apk add --no-cache samba vsftpd

RUN mkdir -p /srv/share /srv/ftp \
    && echo "lab file" > /srv/share/readme.txt \
    && echo "lab file" > /srv/ftp/welcome.txt

COPY smb.conf /etc/samba/smb.conf
COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]