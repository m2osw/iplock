
# What is `ipload`?

The `ipload` command line tool is used to setup your firewall from rather
simple rules.

The tool is especially useful at handling many interfaces, IP addresses,
protocols within one rule which as a result generate many `iptables`
rules (i.e. many rules have a product like effect which is really annoying
to handle manually).

This is particularly useful to make sure your firewall remains up to date.
I personally find it really difficult to manually update my firewall. With
this tool and its simple rules, it is very easy to add hundreds of rules
in a snap.


# ipload configuration files

The `ipload` tool reads configuration files to generate the `iptables`
firewall from various directories.

By default, it reads from these two directories:

* `/usr/share/iplock/ipload/...` -- recursively reads all the files under
  this directory.
* `/etc/iplock/ipload/...` -- recursively reads all the files under this
  directory.

This list of directories can be changed by setting the `rules=...` parameter
in the `/etc/iplock/ipload.conf` or the `--rules ...` command line option.

When a path starts with `/etc/...` the search further looks for a file under
the `ipload.d` sub-directory. These files can be numbered to sort them out
as in:

    # Base file (not editable)
    /usr/share/iplock/ipload/network/docker.conf

    # Administrator's most specific file (last loaded)
    # which can be created & edited at will
    /etc/iplock/ipload/network/ipload.d/50-docker.conf

To see all the folders and files that the `ipload` tool reads, use the
following command line:

    sudo ipload --show --verbose --trace 2>&1 | less

The list shows the exact order in which the rules are loaded. This is
important since a later instance of a parameter overrides any previous
instances.

There is one exception about the sorting order: the `general` directory
is loaded before all the others, even though it may not appear first in
your directory (i.e. by default we have the "forward" folder that gets
loaded after). This allows for easier override of the general parameters
in other system files.

For the `docker.conf` file shown above, `ipload` will look at:

    /usr/share/iplock/ipload/docker.conf
    /usr/share/iplock/ipload/network/docker.conf
    /etc/iplock/ipload/docker.conf
    /etc/iplock/ipload/network/docker.conf
    /etc/iplock/ipload/ipload.d/??-docker.conf
    /usr/share/iplock/ipload/network/ipload.d/??-docker.conf
    /etc/iplock/ipload/netowrk/ipload.d/??-docker.conf

Where `??` is a number from `00` to `99` defining the order in which the files
are to be loaded. In most cases, as the administrator you want to use number
`50`. Other packages may install files with other numbers.


# `ipload` rule files

The rules are defined with a .ini like syntax in .conf files.
The syntax of these rules is found in the `ipload` manual page.

There are several sections defining different type of data:

## Global Variables

We support a few global variables. These are somewhat similar to having
parameters defined in `/etc/iplock/ipload.conf`, but they are too specific
to the loading of configuration files to make them part of the main
configuration file.

## Variables

The loader supports the `[variables]` section definition. The section can
be defined as many times as you'd like. The parameters defined within
those sections can later be references using the variable syntax:

    ${<variable-name>}

We use these to define lists of IP addresses, interfaces, modes, etc.

## Tables

The `ipload` can handle all the supported `iptables` tables. It uses
definitions so references to those tables can be checked.

If no rules apply to a table, then nothing is generated and uploaded to
said table.

## Chains

The `ipload` can handle all the system defined chains (such as `INPUT`)
and user defined chains (such as `unwanted`).

## Sections

The sections is an `ipload` specific concept allowing for sorting rules
in an easier way.

By default, we offer five sections:

* `header`
* `early_content`
* `content`
* `late_content`
* `footer`

This feature allows us to create rules and sort them without having to
use the `before`/`after` parameters every time.

## Rules

The rules actual represet one or more `iptables` rules.

For example, if you include the name of three different interfaces, 6 IP
addresses, and 2 protocols, one such `ipload` rule generates 36 `iptables`
rules.

Much more details are available in the `ipload` manual page:

    man ipload

