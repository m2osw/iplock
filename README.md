
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


Firewall Editor (SNAP-355 part 3)
=================================

The iplock project comes with a console and graphical set of tools used
to edit and setup the firewall. This tool makes use of configuration files
that are read using advgetopt and generates a script supported by iptables.

The configuration files are saved under `/etc/iplock/firewall`. These are
used to setup the base firewall which the `iplock` can later use to
dynamically add and remove rules of what looks like hacking attempts.

## Configuration Files organization

The iplock project makes use of the advgetopt which loads files from
a .d folder and order them using the first two digits of the filenames.
This allows us to define the order in which the configuration files
should be added to the firewall which, obviously, is very important.

By default the firewall marks all the chains with "DROP". This means
we have to have an "ACCEPT" for anything that we want to accept. This
works by adding intermediate files in the .d folder.

This technique allows other projects to add their own configuration
files to open or block the ports they manage.

## Configuration Format

The following show the list of supported tags:

    chain::<name>::policy = accept | drop
    chain::<name>::type = return | drop
    chain::<name>::log = <message>

    rule::<name>::condition = <condition>
    rule::<name>::chains = <name>[, <name>]*
    rule::<name>::interfaces = <interface>[, <interface>]*
    rule::<name>::destination_interfaces = <interface>[, <interface>]*
    rule::<name>::sources = <source>[, <source>]*
    rule::<name>::except_sources = <source>[, <source>]*
    rule::<name>::destinations = <destination>[, <destination>]*
    rule::<name>::except_destinations = <destination>[, <destination>]*
    rule::<name>::protocols = tcp, udp
    rule::<name>::state = [!]new, [!]established, [!]related
    rule::<name>::limit = <number>[, <number>]
    rule::<name>::action = <action>
    rule::<name>::log = <message>

    variable::<name> = <value>

Some entries accept lists, which in most cases means that multiple rules
are created to handle the rule.

The `log` variable means that we add a `-j LOG` rule before the other
rule(s). In iptables parlance, this is an action. We simplify for you
having a single rule implement both features at once.

### `chain::<name>::policy`

This parameter defines the default policy of a system chain.

With Ubuntu, the default is to `ACCEPT` any traffic. You can change the
policy to `DROP` instead. This means traffic that was not accepted by
a rule within that chain will be dropped.

Only built-in chains can be assigned a policy.

### `chain::<name>::type`

This parameter defines the type of the chain.

At this time, this mainly defines how we close the chain, as is, which rule
to use to close the chain.

### `rule::<name>::chains`

This parameter defines the list of chains that are to receive this rule.

Chain names include built-in chains (INPUT, OUTPUT, etc.) and user defined
chains. User defined chains do not need to be pre-defined. The tool will
automatically create them as required.

### `rule::<name>::interfaces`

This parameter defines the list of interfaces that the rule applies to.

### `rule::<name>::sources`

This parameter defines a list of IP addresses or domain names to use to
filter the incoming network traffic.

By default, no source is checked and the rule is accepted whatever
the source is.

### `rule::<name>::except_sources`

This parameter defines a list of IP addresses or domain names to not
match when this rule is checked. If the source matches, then that rule
will be skipped. This is particularly useful in the FORWARD chain to
avoid having your own traffic forwarded.

### `rule::<name>::destinations`

This parameter defines a list of IP addresses or domain names to use to
filter the outgoing network traffic.

By default, no destination is checked and the rule is accepted whatever
the destination is.

### `rule::<name>::except_destinations`

This parameter defines a list of IP addresses or domain names to not
match when this rule is checked. If the destination matches, then that rule
will be skipped.

### `rule::<name>::protocol`

This parameter defines which parameter is necessary to match this rule.
By default, no protocol gets matched.

### `rule::<name>::limit`

This parameter defines the maximum number of connections are accepted
by this rule. The parameter accepts one or two numbers. The first number
represents the maximum number of connections from the sources and the
second represents the maximum number of connections from the destinations.

Note that each limit requires a rule for each limit.

### `rule::<name>::action`

This parameter defines what to do when the rule is a match.

We support the following actions:

* `ACCEPT`

    On a match, the packet is accepted.

* `DROP`

    On a match, the packet is dropped. This means our computer stops working
    on that packet immediately. No more wasting time.

* `REJECT [<type>]`

    On a match, the packet is rejected. This means our computer builds a
    reponse so we can tell the client that we do not want their traffic.
    This is a nice way to refuse data. However, this makes use of more
    of your bandwidth and lets the client know that you exist.

    In most cases, especially on the Internet, it is wiser to use DROP.
    Limit your use of the REJECT action to just local traffic.

    The type is one of the available reject type. See the `--reject-with`
    docs. We like to use `icmp-port-unreachable` which says that the
    port is not open.

* `CALL <chain>`

    This action is used to call a user defined chain. This is particularly
    useful when you want to check a set of rules from multiple places.
    For example, we have a set of _bad TCP packets_ which we like to
    check on INPUT and OUTPUT.

### Variables (`variable::<name>`)

The configuration can reference variables. These are lists of IP addresses,
domain names, port numbers, etc.

For example, when specifying an IP address, you may use a variable such as:

    rule::<name>::sources = ${admin_ips}

This allows us to write one rule for all the administrators (opposed to
one rule per administrator) and with any number of variables, all the user
of any given group.

To support multiple lists in variables, separate them with commas:

    rule::<name>::destinations = ${admin_ips}, ${lan_users}, ${clients}

Using variables enables you to write rules that do not require to be
handled individually.

### Auto-Masking

We want to have the list of IP addresses sorted and check whether we
can use a mask in order to optimize the number of rules. So if you use
16 IP addresses for your local network and they all match a given mask
then we can use one rule instead of 16.

### List of Ports

There is an interesting side effect with lists of ports. These can actually
be used as is in a rule (i.e. certain rules support multiple ports).
The number of ports in a rule is limited, though.

Note that this is a sort of optimization rather than a feature.
a.k.a. If possible we optimize the number of rules by using the multi-port
feature.

### Some Examples

#### Block a Set of Interfaces:

The following lists a set of interfaces that you just want to block completely:

    rule::blocked_interfaces::chains = INPUT, OUTPUT
    rule::blocked_interfaces::interfaces = eth3, eth4
    rule::blocked_interfaces::action = DROP
    rule::blocked_interfaces::log = interface unavailable

This rule prevents all communications (IN and OUT) from `eth3` and `eth4`.


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

vim: ts=4 sw=4 et
