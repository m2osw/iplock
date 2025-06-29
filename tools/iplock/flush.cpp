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
 * \brief iplock tool.
 *
 * This implementation offers a way to easily and safely add and remove
 * IP addresses one wants to block/unblock temporarily.
 *
 * The tool makes use of the iptables tool to add and remove rules
 * to one specific table which is expected to be included in your
 * INPUT rules (with a `-j \<table-name>`).
 */


// self
//
#include    "flush.h"

#include    "controller.h"


// snapdev
//
#include    <snapdev/string_replace_many.h>


// snaplogger
//
#include    <snaplogger/message.h>


// C++
//
#include    <iostream>


// last include
//
#include    <snapdev/poison.h>



namespace tool
{



/** \class flush
 * \brief Remove all the IP addresses from an IP set.
 *
 * This class implements the flush command which can be used to remove
 * all the IP addresses currently present in an IP set. This is equivalent
 * to remove each IP one by one, just a lot faster.
 */

flush::flush(controller * parent)
    : command(parent, "flush")
{
}


flush::~flush()
{
}


void flush::run()
{
    bool found(false);
    for(int i(0); tool::g_suffixes[i] != nullptr; ++i)
    {
        std::string set_name(get_set_name() + tool::g_suffixes[i]);

        // check whether an ipset with that suffix exists
        // if not, just skip that one
        //
        std::string const exists("ipset list [set] -name >/dev/null 2>&1");
        std::string test_exists(snapdev::string_replace_many(exists, {
                    { "[set]", set_name }
                }));
        int const re(system(test_exists.c_str()));
        if(re != 0)
        {
            if(f_verbose)
            {
                SNAP_LOG_VERBOSE
                    << "set named \""
                    << set_name
                    << "\" does not exist. Ignore."
                    << SNAP_LOG_SEND;
            }
            continue;
        }
        found = true;

        std::string const cmdline("ipset flush [set]");
        std::string cmd(snapdev::string_replace_many(cmdline, {
                    { "[set]", set_name }
                }));

        // if user specified --quiet ignore all output
        //
        if(f_quiet)
        {
            cmd += " 1>/dev/null 2>&1";
        }

        // if user specified --verbose show the command being run
        //
        if(f_verbose)
        {
            SNAP_LOG_VERBOSE
                << cmd
                << SNAP_LOG_SEND;
        }

        // run the command now
        //
        int const r(system(cmd.c_str()));
        if(r != 0)
        {
            int const e(errno);
            if(!f_verbose)
            {
                // if not verbose, make sure to show the command so the
                // user knows what failed
                //
                SNAP_LOG_INFO
                    << cmd
                    << SNAP_LOG_SEND;
            }
            SNAP_LOG_ERROR
                << "the ipset flush command failed: "
                << e
                << ", "
                << strerror(e)
                << SNAP_LOG_SEND;
            f_exit_code = 1;
        }
    }

    if(!found)
    {
        SNAP_LOG_RECOVERABLE_ERROR
            << "no set named \""
            << get_set_name()
            << "\" was found. No flush happened."
            << SNAP_LOG_SEND;
    }
}



} // namespace tool
// vim: ts=4 sw=4 et
