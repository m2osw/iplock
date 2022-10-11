#!/bin/sh -e
#
# A sample script based on what I wrote on stackoverflow to manage a list of
# dynamically changing IP addresses in an ipset
#
# https://serverfault.com/questions/123265/how-to-create-an-iptables-rule-using-domain-name/1112558#1112558
#

if test -z "$1" -o "$1" = "-h" -o "$1" = "--help"
then
	echo "Usage: dynamic-ips.sh <domain name>"
	exit 1
fi

# determine the list of ip(s)
new_ip=`dig "${1}" +short`
if test -z "${new_ip}"
then
	echo "error: could not gather the IP address(es) of ${1}"
	exit 1
fi

INITIALIZED=/run/user/$UID/dynamic_ip_setup
if test ! -f ${INITIALIZED}
then
	touch ${INITIALIZED}

	# create the "dyanmic_ips" ipset (it may exist)
	#
	sudo ipset create dynamic_ips hash:ip -exist

	# add a rule where the source IP must match that ipset
	#
	# WARNING: this command is likely totally wrong since appending is
	#          no likely to place the rule in a correct location but it
	#          gives you an idea of how to define said rule
	#
	sudo iptables -A INPUT -p tcp -m tcp --dport 22 --syn \
		       -m set --match-set dynamic_ips src -j ACCEPT
fi

# destroy the new set in case something went wrong and it lingered
# ignore errors if the command fails
#
if sudo ipset destroy new_ips
then
	echo "warning: new_ips was not properly destroy on a previous run."
fi

# for the following, fail on error

# create the new set
#
sudo ipset create new_ips hash:ip

# add the ip(s) to the set
#
for ip in $new_ip
do
    sudo ipset add new_ips $ip
done

# swap the sets
#
sudo ipset swap dynamic_ips new_ips

# remove the old set (which is now inside new_ips)
# this is safer & saves some memory
#
sudo ipset destroy new_ips


