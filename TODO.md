
* Test the packages to make sure everything is installed in the right place.
* Finish up ipwall service (database & testing).
* Finish up the default ipload set of rules.
* Use snaplogger in the iplock tool (the tool generally runs on its own through ipwall so saving errors in a log file is probably going to be better).
* Move the sitter firewall plugin to this project.
* Add a vim syntax file for the firewall .conf files.
* Add safeguard to prevent blocking our own IPs with ipload (i.e. if a rule is DROP or REJECT and the rule matches one of our local IP).
* Move docs from README.md to man pages.
* Chain LOG+DROP/REJECT should probably offer an option to define a list of (public) interfaces so one can get immediate stats per interface.
* Check whether the knock ports are used in the INPUT or a sub-chain of the INPUT chain (We should be able to build a tree).
* Check that the knock ports do not reference an existing service to avoid potential disruptions (this will be done in ipwall).
* Write tests.

