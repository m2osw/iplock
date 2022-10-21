
# Basic Usage

Please, see the manual page for additional information:

    man 5 ipload
    man 8 ipload

    # from within the source (without having to install the package)
    man doc/ipload.5
    man doc/ipload.8

# Implementation

## ipload

The base class is `ipload`. It reads all the configuration files and
then starts parsing each parameter entry.

The order in which the files are loaded matters. The last one has the
highest priority. It can override all the other file's parameters. To
determine the order in your environment, you can use the `--verbose`
command line option:

    ipload --verbose --show [<other parameters as needed>]

## Basic Rules

The `basic.rules` file is used to setup a first very basic firewall to block
any incoming and outgoing connections. The system should work as if the
network was down, except for the localhost (lo) interface.

This file is used to install the firewall as IPv4 and IPv6. If you have
rules that are specific to IPv4, make sure to include the `--ipv4` flag.
Similarly, if you have rules specific to IPv6, then include the `--ipv6`
flag in the rule.

## Organization Tree

    ipload
      tables
        chains-references (points to one chain)
          chains
            section-references (points to one section)
              sections
                rules

The `rules` objects may generate many `iptables` rules. This tree represents
the rules as found in the configuration files. Not as in the `iptables`.
Once the parsing is done, the `ipload` class makes sure that the chains,
sections, and rules are sorted properly (according to their before/after
parameters) and then start the `rules` to `iptables` conversion.

# vim: ts=4 sw=4 et
