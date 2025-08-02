// Copyright (c) 2014-2025  Made to Order Software Corp.  All Rights Reserved
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


/** \file
 *
 * \image html iplock-logo.jpg
 *
 * The `iplock` tool is used to very easily add and remove IP addresses
 * to an `ipset` list of addresses. In most likelihood, you have a rule
 * in your firewall which `DROP`s packets originating from these IP
 * addresses.
 *
 * Once installed properly, it is capable of becoming root and thus make
 * use of the `ipset` command line as required. The shell command line
 * used to add and remove IPs is defined in the configuration file:
 *
 * \code
 * /etc/iplock/iplock.conf
 * \endcode
 *
 * \note
 * To avoid any security issues, the path to the configuration file
 * cannot be changed.
 *
 * By default, the `iplock` tool expects two sets:
 *
 * \li `unwanted_ipv4`, and
 * \li `unwanted_ipv6`.
 *
 * This can be changed in the configuration file.
 */


// self
//
#include    "controller.h"


// iplock
//
#include    <iplock/exception.h>


// advgetopt
//
#include    <advgetopt/exception.h>


// snaplogger
//
#include    <snaplogger/message.h>


// eventdispatcher
//
#include    <eventdispatcher/signal_handler.h>


// libexcept
//
#include    <libexcept/file_inheritance.h>


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
        tool::controller c(argc, argv);

        return c.run_command();
    }
    catch(advgetopt::getopt_exit const & e)
    {
        return e.code();
    }
    catch(iplock::iplock_exception const & e)
    {
        SNAP_LOG_SEVERE
            << e
            << SNAP_LOG_SEND;
    }
    catch(std::exception const & e)
    {
        SNAP_LOG_EXCEPTION
            << "an exception occurred: "
            << e.what()
            << SNAP_LOG_SEND;
        std::cerr << "iplock:error: an exception occurred: " << e.what() << std::endl;
    }
    catch(...)
    {
        SNAP_LOG_ALERT
            << "an unknown exception was raised."
            << SNAP_LOG_SEND;
        std::cerr << "iplock:error: an unknown exception was raised." << std::endl;
    }

    return 1;
}


// vim: ts=4 sw=4 et
