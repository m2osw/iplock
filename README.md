
<p align="center">
<img alt="advgetopt" title="IP Lock -- a command line to easily add and remove IPs from your firewall."
src="https://snapwebsites.org/sites/snapwebsites.org/files/images/iplock-logo.jpg" width="200" height="200"/>
</p>

iplock
======

The `iplock` command line is an `iptable` firewall IP address blocker.

We use it with Snap! to block unwanted users either through tools
such as `fail2ban` or from within our `libsnapwebsites` library.

The library comes with setup files which control how we add and remove
IP addresses to the firewall. There are several methods depending on
what `iplock` does.


Not a Bug
=========

Note that when you uninstall `iplock` from your system, it does not
automatically remove the IP addresses that it was asked to block.
This is for clear security reasons. This is not a bug. It is expected
that if you uninstall our tool, you are probably going to install
another tool which will re-add all or some of those IP addresses
to your firewall.

If you want to clear your firewall and still have Snap! installed
you can reset it by running the default firewall script:

    sudo /etc/network/firewall

This command resets the firewall as it looks like after a reboot on
a Snap! system.

Note that when `snapfirewall` starts, it adds the IP addresses using
the `iplock` tool first, then allows the Snap! Server to accept client's
connections.


Bugs
====

Submit bug reports and patches on
[github](https://github.com/m2osw/snapwebsites/issues).


_This file is part of the [snapcpp project](https://snapwebsites.org/)._
