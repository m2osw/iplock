#!/bin/sh
#
# Allow you to clear the firewall to a pristine state.
#
# This is mainly for programmers to make sure they can test from scratch
# without having to reboot.

if test -t 0
then
    read -p "Are you sure you want to reset your firewall? (type: YES I AM SURE!) " sure
    if test "${sure}" != "YES I AM SURE!"
    then
        echo "warning: clearing of firwall canceled."
        exit 1
    fi
fi

sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

# vim: ts=4 sw=4 et
