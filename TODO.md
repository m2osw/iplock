
* Test the packages to make sure everything is installed in the right place.
* Finish up ipwall service (database & testing).
* Finish up the default ipload set of rules.
* Implement more support for more sets to allow more easy and fast firewall dynamism (i.e. TCP/UDP services can have their port defined in a bitmap; list of local/private/public IPs can be in a set, etc.).
* Use snaplogger in the iplock tool (the tool generally runs on its own through ipwall so saving errors in a log file is probably going to be better).
* Create some interfaces to make it easier to edit the rules (CLI, browser, GUI)
* Move the sitter firewall plugin to this project.
* Moved most of the knock-knock code to the library so we can actually perform a knock-knock from anywhere.
* Add safeguard to prevent blocking our own IPs with ipload (i.e. if a rule is DROP or REJECT and the rule matches one of our local IP).
* Move docs from README.md to man pages.
* Chain LOG+DROP/REJECT should probably offer an option to define a list of (public) interfaces so one can get immediate stats per interface.
* Check whether the knock ports are used in the INPUT or a sub-chain of the INPUT chain (We should be able to build a tree).
* Check that the knock ports do not reference an existing service to avoid potential disruptions (this will be done in ipwall).
* The knock ports defined in the ipload configurations must be knocked on within 10 seconds and the port also remains opened for 10 seconds. Offer the user a way to define these durations.
* Finish implementing support for mangle table special actions.
* Write tests.

