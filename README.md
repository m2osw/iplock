
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

    [table::<table-name>]
    prefix = <prefix>

    [chain::<table-prefix>_<chain-name>]
    policy = ACCEPT | DROP
    type = RETURN | DROP | USER-DEFINED
    log = <message>

    [section::<section-name>]
    before = <section-name>[, <section-name>]*
    after = <section-name>[, <section-name>]*
    default = true | false

    [rule::<rule-name>]
    chains = <chain-name>[, <chain-name>]*
    section = <section-name>
    before = <rule-name>[, <rule-name>]*
    after = <rule-name>[, <rule-name>]*
    condition = <condition>
    interfaces = <interface>[, <interface>]*
    source_interfaces = <interface>[, <interface>]*
    sources = <source>[, <source>]*
    except_sources = <source>[, <source>]*
    source_ports = <port>[, <port>]*
    destination_interfaces = <interface>[, <interface>]*
    destinations = <destination>[, <destination>]*
    except_destinations = <destination>[, <destination>]*
    destination_ports = <port>[, <port>]*
    protocols = tcp, udp, icmp, ...
    state = <flag> | <flag> | ..., [!] ( <flag> | <flag> | ... ), !<flag>
    limit = [<|<=|>]<number>[, [<-|->]<number>]
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

Some of the rules parameters support plural and singular names when one
or more can be specified.

Sections do not exist in iptables. We use such to automatically sort rules
in _groups_. We can more easily sort rules in the correct order for the
final list of rules to upload to the iptables.

The sections support a name. By placing a rule in a section, it is simply
added at the end. You can also force your rule(s) to appear before or after
another rule if necessary.

Note that sections are not specific to a chain. Rules appearing in different
chains can be placed in the same section.

### `table::<table-name>::prefix`

Define a prefix referencing the table from within the chain names.

If the chain name starts with this prefix, then it is added to this table.
The ending `'_'` is not expected to be included in the prefix. It is still
safe to have it here.

The prefix should be the same as the table name: `filter`, `nat`, etc.

The `<table-name>` parameter should be a valid name that the iptables system
understands.

### `chain::<table-prefix>_<chain-name>::policy`

This parameter defines the default policy of a system chain.

The name is composed of a table prefix (i.e. `"nat"`) and a chain name
(i.e. `INPUT`). This is done this way to distinguish between chains of the
same name appearing in different tables (i.e. `"nat_INPUT"` and
`"filter_INPUT"`). In most cases, the filter table is not given a prefix
because that's where you get the most rules. In that case the chain name
does not include the `"<table-prefix>_"`.

With Ubuntu, the default is to `ACCEPT` any traffic. You can change the
policy to `DROP` instead. This means traffic that was not accepted by
a rule within that chain will be dropped.

Only built-in chains can be assigned a policy.

**Default:** policy is set to `DROP` by default since it is more constrained.

### `chain::<table-prefix>_<chain-name>::type`

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

### `chain::<table-prefix>_<chain-name>::log`

This parameter defines a log message. This message is printed only if
the `RETURN` or `DROP` rule found at the end is encountered.

**Default:** no message.

### `section::<name>::before`

Define the name of a section that we want to appear before. In the final
list of rules, all the rules in this section will appear before the
rules found in the section named in this parameter.

Multiple names can be included. Separate each name with a comma. Spaces
are ignored.

### `section::<name>::after`

Define the name of a section that we want to appear after. In the final
list of rules, all the rules in this section will appear after the
rules found in the section named in this parameter.

Multiple names can be included. Separate each name with a comma. Spaces
are ignored.

### `section::<name>::default`

Mark this section as the default one. You are expected to set this parameter
to true.

Once all the rules for a given chain are defined, the process makes sure that
at most one default section is defined in the final list. That default is used
to add all the rules that were not assigned a section name.

If none of the sections were marked as the default section and some rules do
not specifically name a section, then an error is generated.

### `rule::<name>::chain` or `rule::<name>::chains`

This parameter defines the list of chains that are to receive this rule.

Chain names include built-in chains (INPUT, OUTPUT, etc.) and user defined
chains. User defined chains do not need to be pre-defined. The tool will
automatically create them as required and apply defaults as defined in
each `chain::...` variable.

The name of chains is case sensitive. So it must be `INPUT` if you want to
add to the built-in `INPUT` chain. It is customary to use lowercase of user
defined chains to avoid any future potential clashes.

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

### `rule::<name>::condition` or `rule::<name>::conditions`

This parameter is used to conditionally exclude the rule.

At the moment, I do not have a functional as2js script parser and execution
environment. So I limit the functionality to one equality like so:

    "..." == "..."
    "..." != "..."

The `"..."` can be literals or variables. For example, to use that rule only
if a `private_interface` variable is defined you can write:

    condition = '"${private_interface}" != ""'

If this is `true`, then the rule is generated. Otherwise it is ignored.

**WARNING:** You must quote the condition otherwise the start and end quotes
get removed and the expression is thus invalid. If some of your variables
include quotes, you will probably not be able to test them properly with this
version.

No condition (or an empty condition) is equivalent to `true`.

### `rule::<name>::interface` or `rule::<name>::interfaces`

This parameter defines the list of interfaces that the rule applies to.
Since this parameter does not specify a source or a destination, it can
be used with rules that have `INPUT` and `OUTPUT` as chains. The ipload
code will know whether to use the "-i" or "-o" option.

Note that works with the `FORWARD` chain. However, it is very unlikely
that is what you want since 99.9% of the time, the input and output
interfaces are different (i.e. `eth1` to `eth2`). In that case you want
to define both: the `source_interface` and the `destination_interface`
parameters.

### `rule::<name>::source_interface` or `rule::<name>::source_interfaces`

This parameter defines the list of interfaces that the rule applies to.

**Default:** none, which means the rule applies to all interfaces.

### `rule::<name>::source` or `rule::<name>::sources`

This parameter defines a list of IP addresses or domain names to use to
filter the incoming network traffic.

**Default:** no source is checked and the rule is accepted whatever
the source is.

### `rule::<name>::except_source` or `rule::<name>::except_sources`

This parameter defines a list of IP addresses or domain names to not
match when this rule is checked. If the source matches, then that rule
will be skipped. This is particularly useful in the `FORWARD` chain to
avoid having your own traffic forwarded.

**Default:** none.

### `rule::<name>::source_port` or `rule::<name>::source_ports`

This parameter defines a list of source ports allowed to connect. The
number of ports is not limited. It will be broken up in group of 15 to
create corresponding iptables rules.

If you used the `except_sources`, then the ports are also exceptions.

**Default:** none.

### `rule::<name>::destination_interface` or `rule::<name>::destination_interfaces`

This parameter defines the list of interfaces that the rule applies to.

**Default:** none, which means the rule applies to all interfaces.

### `rule::<name>::destination` or `rule::<name>::destinations`

This parameter defines a list of IP addresses or domain names to use to
filter the outgoing network traffic.

**Default:** no destination is checked and the rule is accepted whatever
the destination is.

### `rule::<name>::except_destination` or `rule::<name>::except_destinations`

This parameter defines a list of IP addresses or domain names to not
match when this rule is checked. If the destination matches, then that
rule will be skipped.

**Default:** none.

### `rule::<name>::destination_port` or `rule::<name>::destination_ports`

This parameter defines a list of ports to go with this rules. The number of
ports is not limited. It will be split in lists of 15 per iptables rule.

If you used the `except_destinations` parameters, then those ports are also
exceptions.

**Default:** none.

### `rule::<name>::protocol` or `rule::<name>::protocols`

This parameter defines which protocol is necessary to match this rule.

**Default:** no protocol is matched meaning that all packets get checked.

### `rule::<name>::state` or `rule::<name>::states`

The state or type of the packet for its target to be accepted by the rule.

We currently support states for:

* Connection state (`-m state --state ...`)
* TCP flags (`--tcpflags`)
* ICMP types (`--icmp-type`)

You can use a set of states within one rule by separating each state with a
`|` character. You can use the '!' operator to negate a flag or `!(...)` to
negate a series of flags. Note that the `established` and `related` cannot
be negated (the '!' against these two are ignored). You can separate
flag names and operators by any number of spaces.

Separate sets are defined between commas (i.e. commas mean that the states
are going to be used in separate rules).

The supported syntax looks like so:

    start: mask_compare
         | start ',' mask_compare

    mask_compare: flag_list
                | flag_list '=' flag_list

    flag_list: flag_name
             | flag_list '|' flag_name

    flag_name: 'syn'
             | 'ack'
             | 'fin'
             | 'rst'
             | 'urg'
             | 'psh'
             | 'new'
             | 'old'
             | 'all'
             | 'none'
             | 'established'
             | 'related'
             | 'timestamp-request'
             | 'any'
             | '(' flag_list ')'
             | '!' flag_name

Example:

    new, ack|fin, established|!(syn|ack|urg), !syn

Warning: the `!` operator is probably not working as expected. If applied to
a single flag, it still applies to the whole set of flags. So the following
are equivalent:

    !(syn|ack|urg)
    !syn|ack|urg

Only there isn't an easy way I can think of at the moment to prevent the
second syntax. I may later create a node for each entry found in the
expression and reconsiliate the results at the end. Then it would be possible
to detect such inconsistencies (and invalid uses such as `!related`).

We currently support:

* `new`

  The packet must be considered "new", this means it is a TCP connection
  attempt. It is not available with UDP.

  This is equivalent to `--syn` in the iptables parlance.

* `old`

  The opposite of the "new" state. This means the packet must not be a
  TCP connection attempt. It is not available with UDP.

  This is equivalent to `! --syn` in the iptables parlance.

* `established` or `related`

  Right now, these two are viewed as synomyms. It is used to accept packets
  that represent an established connection and let them go through early on.
  This works with TCP and UDP.

  In most cases, you want to use `!new` along these flags:

      state = establised | related | !new

* `syn`

  The TCP SYN signal.

* `ack`

  The TCP ACK signal.

* `fin`

  The TCP FIN signal

* `rst`

  The TCP RST signal.

* `urg`

  The TCP URG signal

* `psh`

  The TCP PSH signal

* `all`

  This represents all the TCP signals. This is useful for the mask.

* `none`

  This represents none of the TCP signals.

* `(...)`

  Group a set of flags. This is useful to negate a set of TCP flags.
  (i.e. `!(syn|ack)`).

* `!<flag>`

  Negate a TCP flag. Note that this flag has no meaning against flags that
  are not TCP flags. (i.e. `established`, `related`, etc.)

* `timestamp-request`

  An `--icmp-type` to match against.

* `any`

  An `--icmp-type` to match against.

**Default:** none. Whatever the state, the rule passes.

### `rule::<name>::limit` or `rule::<name>::limits`

This parameter defines two numbers.

* Number of allowed connections

The first number can be preceeded with `<=` (or just `<`) to represents the
minimum number of connections (i.e. `--connlimit-upto`). In most cases, this
is used with the `ACCEPT` target. It is also often used to enter a user
defined chain.

If no operator or the '>` operator is used, then it represents the maximum
number of connections (i.e. `--connlimit-above`). This rule is most often
used with a `REJECT`. It can also be used with a `DROP`.

The second number is optional. If defined, it represents a mask applied
against the matching host. It creates a group and the counters count the
number of connections within that entire group.

The second number can be preceeded by the `->` operator, in which case
the group is generated using the destination IP address (rarely used).
The default is to use the source address. Optionally, you can make this
explicit using the `<-` operator.

Example:

    limit = >32,->24

Becomes

    --connlimit-above 32 --connlimit-mask 24 --connlimit-daddr

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
