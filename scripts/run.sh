#!/bin/sh

# while true; do
#   sleep 60
# done


# start syslog
/usr/sbin/rsyslogd -n -iNONE &


cd /go/src/github.com/kingcdavid
go run main.go

# Wait for syslogs to get to file
sleep 10