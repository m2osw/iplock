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
#include    "section_reference.h"


// snaplogger
//
#include    <snaplogger/message.h>


// last include
//
#include    <snapdev/poison.h>



section_reference::section_reference(section::pointer_t s)
    : f_section(s)
{
}


bool section_reference::is_valid() const
{
    return f_section->is_valid();
}


void section_reference::add_rule(rule::pointer_t r)
{
    advgetopt::string_list_t const & before(r->get_before());
    advgetopt::string_list_t const & after(r->get_after());

    // compute the minimum position first
    //
    std::size_t min_idx(0);
    {
        std::size_t idx(f_rules.size());
        while(idx > 0)
        {
            std::string const & name(f_rules[idx]->get_name());
            if(std::find(after.begin(), after.end(), name) != after.end())
            {
                min_idx = idx + 1;
                break;
            }
            --idx;
        }
    }

    for(std::size_t idx(0); idx < f_rules.size(); ++idx)
    {
        std::string const & name(f_rules[idx]->get_name());
        if(std::find(before.begin(), before.end(), name) != before.end())
        {
            if(idx < min_idx)
            {
                // TODO: I think we could check whether it would be possible
                //       to swap idx and min_idx so the insert is possible...
                //
                SNAP_LOG_ERROR
                    << "rule \""
                    << r->get_name()
                    << "\" was required to be before \""
                    << name
                    << "\" and after \""
                    << f_rules[min_idx - 1]
                    << "\" at the same, only those rules are not sorted in such a way that this is currently possible."
                    << SNAP_LOG_SEND;
                f_section->mark_invalid();
            }
            else
            {
                f_rules.insert(f_rules.begin() + idx, r);
            }
            return;
        }
    }

    // not inserted yet, add at the end
    //
    f_rules.push_back(r);
}


rule::vector_t const & section_reference::get_rules() const
{
    return f_rules;
}


std::string const & section_reference::get_name() const
{
    return f_section->get_name();
}


advgetopt::string_list_t const & section_reference::get_before() const
{
    return f_section->get_before();
}


advgetopt::string_list_t const & section_reference::get_after() const
{
    return f_section->get_after();
}


bool section_reference::get_default() const
{
    return f_section->get_default();
}



// vim: ts=4 sw=4 et
