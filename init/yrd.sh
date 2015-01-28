#!/bin/sh -e
### BEGIN INIT INFO
# hyperboria.sh - An init script (/etc/init.d/) for cjdns
# Provides:          cjdroute
# Required-Start:    $remote_fs $network
# Required-Stop:     $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Cjdns router
# Description:       A routing engine designed for security, scalability, speed and ease of use.
# cjdns git repo:    https://github.com/cjdelisle/cjdns/
### END INIT INFO

GIT_PATH="/opt/cjdns"
CJDNS_USER="root"  #see wiki about changing user to service user.

start() {
     # Start it up with the user cjdns
     if [ $(pgrep cjdroute | wc -l) != 0 ];
     then
         echo "Cjdroute is already running. Doing nothing..."
     else
         echo " * Starting cjdroute"
         sudo -u $CJDNS_USER yrd start
     fi
 }

 stop() {

     if [ $(pgrep cjdroute | wc -l) != 2 ];
     then
         echo "Cjdns isn't running."
     else
         echo "Killing cjdroute"
         killall cjdroute
     fi
 }

 status() {
     if [ $(pgrep cjdroute | wc -l) != 0 ];
     then
         echo "Cjdns is running"
     else
         echo "Cjdns is not running"
     fi
 }

 update() {
     cd $GIT_PATH
     echo "Updating..."
     git pull
     ./do
 }


 ## Check to see if we are running as root first.
 if [ "$(id -u)" != "0" ]; then
     echo "This script must be run as root" 1>&2
     exit 1
 fi

 case $1 in
     start)
         start
         exit 0
     ;;
     stop)
         stop
         exit 0
     ;;
     reload|restart|force-reload)
         stop
         sleep 1
         start
         exit 0
     ;;
     status)
         status
         exit 0
     ;;
     update|upgrade)
         update
         stop
         sleep 2
         start
         exit 0
     ;;
     **)
         echo "Usage: $0 (start|stop|restart|status|update)" 1>&2
         exit 1
     ;;
 esac
