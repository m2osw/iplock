// Copyright (c) 2007-2024  Made to Order Software Corp.  All Rights Reserved
//
// https://snapwebsites.org/project/iplock
// contact@m2osw.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.


/** \mainpage
 *
 * \image html iplock-logo.jpg
 *
 * The ipload tool is used to load your firewall on a reboot. The set of
 * rules are defined in simple .ini like files which are loaded by this
 * tool and transform in the more complex iptables rules. Also, when using
 * certain variables, the tool may generate a plethora of rules at once
 * (like an SQL product).
 *
 * The tool is expected to run once after each reboot. If the rules are
 * modified, it is possible to run the tool again to update the firewall.
 * Since the list of IP addresses to block are defined in iptables sets,
 * they will not need to be changed in any way. They remain in place and
 * are seemlessly used again after the update.
 */


// self
//
#include    "ipload.h"


// snaplogger
//
#include    <snaplogger/message.h>


// eventdispatcher
//
#include    <eventdispatcher/signal_handler.h>


// libexcept
//
#include    <libexcept/file_inheritance.h>


// advgetopt
//
#include    <advgetopt/exception.h>


// C++
//
#include    <iostream>


// last include
//
#include    <snapdev/poison.h>



int main(int argc, char * argv[])
{
    ed::signal_handler::create_instance();
    libexcept::verify_inherited_files();
    libexcept::collect_stack_trace();

    try
    {
        ipload l(argc, argv);
        return l.run();
    }
    catch(advgetopt::getopt_exit const & e)
    {
        return e.code();
    }
    catch(std::exception const & e)
    {
        std::cerr << "error:ipload: an exception occurred: " << e.what() << '\n';
    }
    catch(...)
    {
        std::cerr << "error:ipload: received an unknown exception.\n";
    }

    return 1;
}


// vim: ts=4 sw=4 et
