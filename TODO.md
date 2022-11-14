
* Finish up ipwall service (database & testing).
* Change the opening of ports for services to make use of one ipset of ports
  (for all TCP and for all UDP which do not need anything special).
* Change the ipsets to make use of counters (that uses more RAM but allows
  us to better track what's happening).
* Create some interfaces to make it easier to edit the rules (CLI, browser, GUI)
* Enhance the creation of `ipset`s by adding a declarative. Just like we have
  tables and chains, we can have sets. Parameters of a set:
  - name
  - type (hash:ip, etc.)
  - static/dynamic
  - maximum number of expected elements (if statically compute at creation time)
  - if parameters change, create a new set, upload the data, do a swap
  - timeout (TTL for data added to this set)
  - counters
  - comment
  - skbinfo (?)
  - hashsize
  - family (ipv4 or ipv6--does not apply to bitmap:port, hash:mac)
  - nomatch (?)
  - forceadd (to accept new and auto-remove old on a full set)
* Move the sitter firewall plugin to this project.
* Moved most of the knock-knock code to the library so we can actually perform a knock-knock from anywhere.
* Move docs from README.md to man pages.
* Check whether the knock ports are used in the INPUT or a sub-chain of the
  INPUT chain (We should be able to build a tree).
* Check that the knock ports do not reference an existing service to avoid potential disruptions.
* Finish implementing support for mangle table special actions.
* Add support for bad TCP state i.e. --syn means NEW so both states must be the same:
      ... -p tcp ! --syn -m state --state NEW ...
      ... -p tcp --syn -m state ! --state NEW ...
* The options of a rule are actually ordered. That mostly works in regard to
  the -m recent extensions, but not other things like where to TCP state
  should be placed within the list of recent parameters.
  - problem 1: I do not know of all the possible options and their order
    (although I suspect that all -m <name> --<flag> ... are sortable)
  - problem 2: our .conf are declaratives which do not imply an order
    * One possibility here is to have a comma separated set of strings which
      can be defined as "<type>: <parameters>" where the "<type>" is one of
      those states (i.e. "state", "recent", etc.)
    * Another possibility is to use an "order: ..." field.
* Write tests.
* Implement an nftables version.

