
# Implementation

## ipload

The base class is `ipload`. It reads all the configuration files and
then starts parsing each parameter entry found.

The ipload class takes care of the creating chains and sections.

Chains takes care of creating rules.

The parsing happens in the respective chain, section, or rule. The chain
also manages the section references. This is because the same section can
be used in any number of chains so we use a reference to make sure we do
not duplicate the sections, which would complicate updates of their data).

## Organizatio Tree

    ipload
      sections
      chains
        section-references (points to one section)
          rules

The `rules` objects may generate many `iptables` rules. This tree represents
the rules as found in the configuration files. Not as in the `iptables`.
Once the parsing is done, the `ipload` class makes sure that the sections
and rules are sorted properly (according to their before/after parameters)
and then start the `rules` to `iptables` conversion.
