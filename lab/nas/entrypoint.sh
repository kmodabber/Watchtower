#!/bin/sh
# Starts both of the NAS daemons. vsftpd goes in the background while smbd stays in the foreground as the container's main process.
# Note: If smbd dies, the container will exit. If vsftpd dies, smbd will continue to run.

vsftpd /etc/vsftpd/vsftpd.conf &
exec smbd --foreground --no-process-group --debug-stdout