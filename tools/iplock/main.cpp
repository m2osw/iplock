// Copyright (c) 2014-2022  Made to Order Software Corp.  All Rights Reserved
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
 * The iplock tool can be used to very easily add and remove IP addresses
 * you want blocking unwanted clients.
 *
 * Once installed properly, it will be capable to become root and
 * thus access the firewall as required. The rules used to add and
 * remove IPs are defined in the configuration file found under
 * /etc/network/iplock.conf (to avoid any security problems, the path
 * to the configuration file cannot be changed.)
 *
 * By default, the iplock tool expects a chain entry named bad_robots.
 * This can be changed in the configuration file.
 */


// self
//
#include    "iplock.h"


// advgetopt
//
#include    <advgetopt/exception.h>


// eventdispatcher
//
#include    <eventdispatcher/signal_handler.h>


// libexcept
//
#include    <libexcept/file_inheritance.h>


// snapdev
//
#include    <snapdev/not_reached.h>


// C++
//
#include    <iostream>


// snapdev
//
#include    <snapdev/poison.h>



int main(int argc, char * argv[])
{
    ed::signal_handler::create_instance();
    libexcept::verify_inherited_files();
    libexcept::collect_stack_trace();

    try
    {
        tool::iplock l(argc, argv);

        return l.run_command();
    }
    catch(advgetopt::getopt_exit const & e)
    {
        exit(e.code());
        snapdev::NOT_REACHED();
    }
    catch(std::exception const & e)
    {
        std::cerr << "error:iplock: an exception occurred: " << e.what() << std::endl;
    }

    return 1;
}


// vim: ts=4 sw=4 et
