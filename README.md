
<p align="center">
<img alt="iplock" title="IP Lock -- a command line to easily add and remove IPs from your firewall."
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
dynamically add and remove rules and IP addresses of what looks like
hacking attempts.

## Configuration Files organization

The iplock project makes use of the advgetopt to load configuration files
from the `/usr/share/iplock/rules` folder. The rules are order using the
`before`, `after`, and `section` names defined within the rules.
This allows us to define the order in which the rules have to be loaded
in the firewall which, obviously, is very important.

The `before`/`after` parameters work within a `section`. It is otherwise
ignored. The `section` allows us to have groups of rules such as
`"localhost"`, `"tools"`, and `"footer"`. The sections are sorted using
their own `before` and `after` parameters.

By default the ipload tool marks all the chains with "DROP". This means
we have to have an "ACCEPT" rule for anything that we want to accept. This
works by adding intermediate files in the .d folder.

This technique allows other projects to add their own configuration
files to open or block the ports they manage.

## Configuration Format

The following shows the list of supported tags (see details below):

    [chain::<chain-name>]
    policy = ACCEPT | DROP
    type = RETURN | DROP | USER-DEFINED
    log = <message>

    [section]
    name = <section-name>
    before = <section-name>[, <section-name>]*
    after = <section-name>[, <section-name>]*
    default = true | false

    [rule::<rule-name>]
    chains = <chain-name>[, <chain-name>]*
    section = <section-name>
    before = <rule-name>[, <rule-name>]*
    after = <rule-name>[, <rule-name>]*
    condition = <condition>
    source_interfaces = <interface>[, <interface>]*
    sources = <source>[, <source>]*
    except_sources = <source>[, <source>]*
    source_ports = <port>[, <port>]*
    destination_interfaces = <interface>[, <interface>]*
    destinations = <destination>[, <destination>]*
    except_destinations = <destination>[, <destination>]*
    destination_ports = <port>[, <port>]*
    protocols = tcp, udp, icmp, etc.
    state = [!]new, [!]established, [!]related
    limit = <number>[, <number>]
    action = <action>
    log = <message>

    [variables]
    <variable-name> = <value>
    ...

Some entries accept lists, which in most cases means that multiple iptable
rules are created to handle one entry.

The `log` variable means that we add a `-j LOG` rule before the other
rule(s). In iptables parlance, this is an action. We simplify for you
having a single rule implementing both features at once.

### `chain::<chain-name>::policy`

This parameter defines the default policy of a system chain.

With Ubuntu, the default is to `ACCEPT` any traffic. You can change the
policy to `DROP` instead. This means traffic that was not accepted by
a rule within that chain will be dropped.

Only built-in chains can be assigned a policy.

**Default:** policy is set to `DROP` by default since it is more constrained.

### `chain::<name>::type`

This parameter defines the type of the chain.

At this time, this mainly defines how we close the chain, as in, which rule
to use to close the chain.

A type set to `DROP` means the chain drops any packet that is not accepted
by a rule within that chain. If the type is set to `RETURN`, then if none
of the rules within that chain was set to `DROP`, then the filtering
continues after the point where that chain was inserted.

Note that we also offer a `USER-DEFINED` type in which case no rule gets
added automatically. Instead you are expected to handle the rule yourself
by adding it to your chain in a footer section.

**Default:** `DROP` since this is a stronger constraint.

### `chain::<name>::log`

This parameter defines a log message. This message is printed only if
the `RETURN` or `DROP` rule found at the end is encountered.

**Default:** no message.

### `section::name`

Sections define groups of rules so we can more easily sort rules in the
correct order for the final list of rules to upload to the iptables.

The sections support a name. By placing a rule in a section, it is simply
added at the end. You can also force your rule(s) to appear before or after
another rule if necessary.

Note that sections are not specific to a chain. Rules appearing in different
chains can be placed in the same section.

### `section::before`

Define the name of a section that we want to appear before. In the final
list of rules, all the rules in this section will appear before the
rules found in the section named in this parameter.

Multiple names can be included. Separate each name with a comma. Spaces
are ignored.

### `section::after`

Define the name of a section that we want to appear after. In the final
list of rules, all the rules in this section will appear after the
rules found in the section named in this parameter.

Multiple names can be included. Separate each name with a comma. Spaces
are ignored.

### `section::default`

Mark this section as the default one. You are expected to set this parameter
to true.

Once all the rules for a given chain are defined, the process makes sure that
at most one default section is defined in the final list. That default is used
to add all the rules that were not assigned a section name.

If none of the sections were marked as the default section and some rules do
not specifically name a section, then an error is generated.

### `rule::<name>::chains`

This parameter defines the list of chains that are to receive this rule.

Chain names include built-in chains (INPUT, OUTPUT, etc.) and user defined
chains. User defined chains do not need to be pre-defined. The tool will
automatically create them as required and apply defaults as defined in
each `chain::...` variable.

**Default:** none, this is a required parameter, you need to have at least one
chain to which the `<name>` rule applies.

### `rule::<name>::section`

The name of the section in which to add this rule.

A single name is allowed.

The named section must exist.

If no section name is defined, the rule is added in the default section of
the corresponding chain.

### `rule::<name>::before`

The name of one or more rules that must be added after this one.

If the named rules are not defined, then that name is ignored.

### `rule::<name>::after`

The name of one or more rules that must be added before this one.

This parameter allows you to sort your rules as expected in the final output.

If the named rules are not defined, then that name is ignored.

### `rule::<name>::source_interfaces`

This parameter defines the list of interfaces that the rule applies to.

**Default:** none, which means the rule applies to all interfaces.

### `rule::<name>::sources`

This parameter defines a list of IP addresses or domain names to use to
filter the incoming network traffic.

**Default:** no source is checked and the rule is accepted whatever
the source is.

### `rule::<name>::except_sources`

This parameter defines a list of IP addresses or domain names to not
match when this rule is checked. If the source matches, then that rule
will be skipped. This is particularly useful in the `FORWARD` chain to
avoid having your own traffic forwarded.

**Default:** none.

### `rule::<name>::source_ports`

This parameter defines a list of source ports allowed to connect. The
number of ports is not limited. It will be broken up in group of 15 to
create corresponding iptables rules.

If you used the `except_sources`, then the ports are also exceptions.

**Default:** none.

### `rule::<name>::destination_interfaces`

This parameter defines the list of interfaces that the rule applies to.

**Default:** none, which means the rule applies to all interfaces.

### `rule::<name>::destinations`

This parameter defines a list of IP addresses or domain names to use to
filter the outgoing network traffic.

**Default:** no destination is checked and the rule is accepted whatever
the destination is.

### `rule::<name>::except_destinations`

This parameter defines a list of IP addresses or domain names to not
match when this rule is checked. If the destination matches, then that
rule will be skipped.

**Default:** none.

### `rule::<name>::destination_ports`

This parameter defines a list of ports to go with this rules. The number of
ports is not limited. It will be split in lists of 15 per iptables rule.

If you used the `except_destinations` parameters, then those ports are also
exceptions.

**Default:** none.

### `rule::<name>::protocol`

This parameter defines which protocol is necessary to match this rule.

**Default:** no protocol is matched meaning that all packets get checked.

### `rule::<name>::state`

The state of the packet (new, established, related, etc.)

The state can be inverted using the `!` opeartor.

**Default:** none. All states pass.

### `rule::<name>::limit`

This parameter defines the maximum number of connections accepted
by this rule. The parameter accepts one or two numbers. The first number
represents the maximum number of connections from the sources and the
second represents the maximum number of connections from the destinations.

Note that a separate iptable rule is necessary for each limit.

**Default:** no limit enforced.

### `rule::<name>::action`

This parameter defines what to do when the rule is a match.

We support the following actions:

* `ACCEPT`

   On a match, the packet is accepted.

* `DROP`

   On a match, the packet is dropped. This means our computer stops working
   on that packet immediately. No more wasting time or bandwidth.

   This should be used to block public traffic (from computers you do not
   own, i.e. the rest of the Internet). For local traffic, it is nicer to
   use the `REJECT` option.

* `REJECT [<type>]`

   On a match, the packet is rejected. This means our computer builds a
   reponse so we can tell the client that we do not want their traffic.
   This is a nice way to refuse data. However, this makes use of more
   of your bandwidth and lets the client know that you exist.

   In most cases, especially on the Internet, it is wiser to use `DROP`.
   Limit your use of the `REJECT` action to just local traffic.

   The type is one of the available reject type. See the `--reject-with`
   docs. We like to use `icmp-port-unreachable` which says that the
   port is not open to the other side, whether it is open or not.

   This should be used to block connections between your systems on your
   private network (10.x.x.x, 192.168.x.x, etc.) so that way improper
   attempts at connection fail quickly.

* `CALL <chain>`

   This action is used to call a user defined chain. This is particularly
   useful when you want to check a set of rules from multiple places.
   For example, we have a set of _bad TCP packets_ which we like to
   check on `INPUT` and `OUTPUT`.

* LOG

  The action is rarely used since in most cases you just enter a log message
  with an existing action (see `rule::<name>::log`). However, there may be
  cases where you only want to log a message and not otherwise do anything
  with the rule. In that case, use this action.

### `rule::<name>::log`

A log message assotiated with the rule. It gets sent to the iptables logs
if the rule matches.

**WARNING:** This is to be used with parsimony. Do not add a log to each one
of your rules. In most cases you want to add this to rules that you `REJECT`
or `DROP`. Logging all your rules will likely fill up your disk space very
quickly. It is, however, quite useful while debugging your firewall.

**Default:** none.

### Variables (`[variable]` + `<name> = <value>`)

The configuration can reference variables. These are lists of IP addresses,
domain names, port numbers, etc.

For example, when specifying an IP address, you may use a variable such as:

    rule::<name>::sources = ${admin_ips}

This allows us to write one rule for all the administrators (opposed to
one rule per administrator) and with any number of variables, all the users
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
The number of ports in an iptable rule is limited, but our software takes
care of handling that limit.

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

This rule prevents all communications (**in** and **out**) from `eth3` and
`eth4`.


Algorithm
=========

When the iplock firewall starts:

1. it reads all the configuration files

2. it transforms the configuration files in an iptables script

3. if it detected sets of IPs while handling the configuration files,
   read the corresponding IPs from the database and add them to the
   sets

3. it runs the iptables script

Later, the iplock system is sent new IPs to block or unblock via the
firewall service:

1. `BLOCK` -- add the IP to the database and the firewall; this is done
   by adding the IP to one of the sets; if the set is full, then a new set
   is created and added to the firewall

2. `UNBLOCK` -- remove the IP from the database and the firewall; this is
   done by removing the IP from one of the sets; if the set is empty and
   there are more than one for the same set, it gets removed (i.e. if we
   had to create a second set of an overflow, we want to remove such
   additional sets)

The `iplock` tool is used to make edits to the `iptables` rules.

The `ipcontroller` service is used to accept / receive `BLOCK` and `UNBLOCK`
messages, manage the database, and run the iplock tool to update the rules.

The `ipload` tool reads configuration files and build the `iptables` rules.




Not a Bug
=========

Note that when you uninstall `iplock` from your system, it does not
automatically remove the IP addresses that it was asked to block.
This is for clear security reasons. This is not a bug. It is expected
that if you uninstall our tool, you are probably going to install
another tool which will re-add all or some of those IP addresses
to your firewall.

If you really want to clear you firewall completely, you can use the
following command to flush everything:

    sudo iptable -F


Bugs
====

Submit bug reports and patches on
[github](https://github.com/m2osw/snapwebsites/issues).


_This file is part of the [snapcpp project](https://snapwebsites.org/)._

vim: ts=4 sw=4 et
