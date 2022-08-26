// Copyright (c) 2022  Made to Order Software Corp.  All Rights Reserved
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
 * \brief ipload tool
 *
 * This tool loads configuration files in order to build the firewall
 * scripts and upload those script using iptables.
 */


// self
//
#include    "utils.h"



std::string to_lower(std::string const & s)
{
    std::string r;
    for(auto const & c : s)
    {
        if(c >= 'A' && c <= 'Z')
        {
            r += c + 0x20;
        }
        else if(c == '-')
        {
            r += '_';
        }
        else
        {
            r += c;
        }
    }
    return r;
}


void list_to_lower(advgetopt::string_list_t & l)
{
    for(auto & s : l)
    {
        s = to_lower(s);
    }
}



// vim: ts=4 sw=4 et
