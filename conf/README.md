
Administrator Modified Files
============================

Please create files under `/etc/iplock/iplock.d` with the same name as
the files found under the `/etc/iplock` directory. Then add parameters
that you want to overwrite.

That way, you will continue to get the default configuration
changes from the source package under `/etc/iplock`.

All files get first loaded from `/etc/iplock` and then again
from `/etc/iplock/iplock.d`. Any parameter redefined in the
sub-directory overwrites the parameter of the same name in
the main directory.


Bugs
====

Submit bug reports and patches on
[github](https://github.com/m2osw/iplock/issues).


_This file is part of the [snapcpp project](https://snapwebsites.org/)._
