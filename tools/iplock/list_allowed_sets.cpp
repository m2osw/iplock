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
#include    "list_allowed_sets.h"


// C++
//
#include    <iostream>


// last include
//
#include    <snapdev/poison.h>



namespace tool
{



/** \class list_allowed_sets
 * \brief List the set of allowed sets.
 *
 * This class prints out the list of set names that are allowed. Only those
 * sets can be updated by the iplock tool. Trying to modify another set
 * generates an error.
 */

list_allowed_sets::list_allowed_sets(controller * parent)
    : command(parent, "list-allowed-sets")
{
}


list_allowed_sets::~list_allowed_sets()
{
}


void list_allowed_sets::run()
{
    std::string const & set_name(get_set_name());
    for(auto const & n : f_allowed_set_names)
    {
        std::cout << n;
        if(f_verbose && set_name == n)
        {
            // mark the default set with an asterisk
            //
            std::cout << " (*)";
        }
        std::cout << '\n';
    }
}


bool list_allowed_sets::needs_root() const
{
    return false;
}



} // namespace tool
// vim: ts=4 sw=4 et
