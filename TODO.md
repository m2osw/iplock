
* Make sure everything gets installed in the right place.
* Add two .service to run ipload and ipwall.
* (re-)Implement snapfirewall service here. (compiles, missing database, needs testing)
* Implement the ipload tool (i.e. to load a firewall on startup).
* Break the iplock class in separate files (easier to maintain and test).
* Consider using snaplogger in the iplock tool? (the tool generally runs on its own so saving errors in a log file is probably going to be better)
* Move the sitter firewall plugin to this project.
* Write tests.

