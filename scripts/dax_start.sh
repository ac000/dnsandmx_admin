#!/bin/sh
#

IP="127.0.0.1"
PORT="8080"
PID="/var/run/dax.pid"
APP="/var/www/sites/admin.dnsandmx.com"
CONFIG="/usr/local/etc/dax.cfg"
DAX_UID="dax"
DAX_GID="dax"

cd $APP
spawn-fcgi -u $DAX_UID -g $DAX_GID -a $IP -p $PORT -P $PID -- ${APP}/dax $CONFIG
