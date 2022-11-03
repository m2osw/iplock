#!/bin/sh
#
# Test that the synflood works (that our packets get dropped after 100)
# Once the test ran, you should see a non-zero count on the synflood line
# of your firewall.
#
# Usage: synflood <ip> [<port>]
# The default <port> is 5000

IP=$1
if test -z "$IP"
then
	echo "error: synflood requires an IP address as its first argument."
	exit 1
fi

PORT=$2
if test -z "$PORT"
then
	PORT=5000
fi

echo "running \c"
COUNT=0
while test ${COUNT} -lt 150
do
	# Start in the background since it's not going to connect either way
	#
	echo ".\c"
	nc -w 1 $IP $PORT &
	sleep 0.1
	COUNT=`expr ${COUNT} + 1`
done
echo

