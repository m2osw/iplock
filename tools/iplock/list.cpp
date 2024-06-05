// Copyright (c) 2014-2024  Made to Order Software Corp.  All Rights Reserved
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
#include    "list.h"

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



/** \class list
 * \brief List the IP addresses of a set.
 *
 * This class prints out the contents of a set using the `ipset list ...`
 * command.
 *
 * \todo
 * Add options to allow things such as tweaking the formatting.
 */

list::list(controller * parent)
    : command(parent, "list")
{
}


list::~list()
{
}


void list::run()
{
    bool found(false);
    bool newline(false);
    for(int i(0); tool::g_suffixes[i] != nullptr; ++i)
    {
        std::string set_name(get_set_name() + tool::g_suffixes[i]);

        // check whether an ipset with that suffix exists
        // if not, just skip that one
        //
        if(newline)
        {
            // add a newline between each list
            //
            std::cout << '\n';
        }
        std::string const exists("ipset list [set] 2>/dev/null");
        std::string test_exists(snapdev::string_replace_many(exists, {
                    { "[set]", set_name }
                }));
        int const e(system(test_exists.c_str()));
        if(e != 0)
        {
            if(f_verbose)
            {
                SNAP_LOG_VERBOSE
                    << "set named \""
                    << set_name
                    << "\" does not exist. Nothing to list."
                    << SNAP_LOG_SEND;
                newline = true;
            }
            continue;
        }
        found = true;
        newline = true;
    }

    if(!found)
    {
        SNAP_LOG_RECOVERABLE_ERROR
            << "no set named \""
            << get_set_name()
            << "\" was found."
            << SNAP_LOG_SEND;
    }
}



} // namespace tool
// vim: ts=4 sw=4 et
