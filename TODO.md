
* Finish up ipwall service (database & testing).
* Change the opening of ports for services to make use of one ipset of ports (for all TCP and for all UDP which do not need anything special).
* Change the ipsets to make use of counters (that uses more RAM but allows us to better track what's happening).
* Create some interfaces to make it easier to edit the rules (CLI, browser, GUI)
* Move the sitter firewall plugin to this project.
* Moved most of the knock-knock code to the library so we can actually perform a knock-knock from anywhere.
* Add safeguard to prevent blocking our own IPs with ipload (i.e. if a rule is DROP or REJECT and the rule matches one of our local IP).
* Move docs from README.md to man pages.
* Chain LOG+DROP/REJECT should probably offer an option to define a list of (public) interfaces so one can get immediate stats per interface.
* Check whether the knock ports are used in the INPUT or a sub-chain of the INPUT chain (We should be able to build a tree).
* Check that the knock ports do not reference an existing service to avoid potential disruptions (this will be done in ipwall).
* The knock ports defined in the ipload configurations must be knocked on within 10 seconds and the port also remains opened for 10 seconds. Offer the user a way to define those durations.
* Finish implementing support for mangle table special actions.
* Add support for bad TCP state i.e. --syn means NEW so both states must be the same:
      ... -p tcp ! --syn -m state --state NEW ...
      ... -p tcp --syn -m state ! --state NEW ...
* Write tests.

