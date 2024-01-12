#!/bin/sh

rootfs=`mount | grep "on / type" | cut -d':' -f 2 | cut -d' ' -f 1`

if [ $rootfs == '/dev/mmcblk0p2' ];then
	selection="-e stable,copy2"
else
	selection="-e stable,copy1"
fi
		
# Override these variables in sourced script(s) located
# in /usr/lib/swupdate/conf.d or /etc/swupdate/conf.d
SWUPDATE_ARGS="-n -v -H raspberrypi3:1.0 ${selection} -f /etc/swupdate.cfg ${SWUPDATE_EXTRA_ARGS}"
SWUPDATE_WEBSERVER_ARGS=""
SWUPDATE_SURICATTA_ARGS=""

# source all files from /etc/swupdate/conf.d and /usr/lib/swupdate/conf.d/
# A file found in /etc replaces the same file in /usr
for f in `(test -d /usr/lib/swupdate/conf.d/ && ls -1 /usr/lib/swupdate/conf.d/; test -d /etc/swupdate/conf.d && ls -1 /etc/swupdate/conf.d) | sort -u`; do
  if [ -f /etc/swupdate/conf.d/$f ]; then
    . /etc/swupdate/conf.d/$f
  else
    . /usr/lib/swupdate/conf.d/$f
  fi
done

exec /usr/bin/swupdate $SWUPDATE_ARGS
