
Administrator Modified and Additional Scheme Files
==================================================

Please create files under `/etc/iplock/schemes/schemes.d` starting with two
digits, a dash and the name of the file found under the `/etc/iplock/scheme`
directory. Then add parameters that you want to overwrite to that file.
For example, the `/etc/iplock/scheme/http.conf` parameters can be overwritten
using the following file:

    /etc/iplock/scheme/scheme.d/50-http.conf

That way, you will continue to get the default configuration
changes from the source package under `/etc/iplock/schemes`.

All files get first loaded from `/etc/iplock/schemes` and then again
from `/etc/iplock/schemes/schemes.d`. Any parameter redefined in the
sub-directory overwrites the parameter of the same name in
the main directory.

The first two digits are used to sort the files. The first one
loaded is `00-<name>.conf` and the last one loaded is `99-<name>.conf`.
The user parameters are expected to be defined in a file using number
50 as in `50-<name>.conf`. Other projects make changes using filenames
with lower numbers (i.e. `20-<name>.conf`) and number 80 is considered
special and used as the _global settings_. It gets copied to all your
machines using `snaprfs` and it overwrites your user settings.

For example, if you make use of a service that attempts penetration tests
on your system and you want to allowlist those attempts, you can add a
file named `/etc/iplock/schemes/schemes.d/50-http.conf` with:

    # Prevent system from blocking penetration tests
    allowlist=192.168.45.0/24

This comes particularly handy when you have PCI DSS tests running against
your machines. Just enter their IP addresses in the allowlist.


Parameters in a Scheme File
===========================

A scheme file supports the following definitions:

    ports=
    allowlist=
    check=
    block=
    unblock=
    batch=

### ports

The `ports` parameter defines a list or ports to block whenever this
scheme is specified. Each port number is separated by a comma.

### allowlist

The `allowlist` parameter defines a list of IP addresses optionally
followed by a CIDR. For example, to allowlist all 10.0.0.0 private
addresses, you can write:

    allowlist=10.0.0.0/8

An IP address which is defined in the `allowlist` parameter never
gets blocked.

### check

The `check` parameter defines a command line the process can use
to check whether a rule exists or not. If the rule exists, the
process is expected to exit with 0. If the rule cannot be found,
the process is expected to exit with 1.

The `check` command is run whether you are trying to `--block` or
`--unblock` an IP address. When blocking, nothing else happens if
the IP is already in the chain list. When unblocking, nothing else
happens if the IP is not in the chain list.

### block

The `block` command is used to add the IP address to the iptables
chain. The add can use an _append_ (`-A`) or an _insert_ (`-I`)
command. We prefer the insert to get the IP address at the start
of the chain, since this is a hot request, it will be quicker for
the ipfilter system to block the IP if found earlier.

### unblock

The `unblock` command is used to remove the IP address from the
iptables chain. The remove uses the _delete_ (`-D`) command.

### batch

The `batch` command is used to add the IP addresses to the iptables
chains when starting your firewall. This way you can read a large
number of IP addresses from a database and set them in all at once.

In most cases, `batch` uses the append (`-A`) command.


For More
========

For additional details, check out the http.conf and smtp.conf files.


_This file is part of the [snapcpp project](https://snapwebsites.org/)._
