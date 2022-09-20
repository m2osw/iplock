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


// snapdev
//
#include    <snapdev/join_strings.h>


// C++
//
#include    <iostream>


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


bool section_reference::empty() const
{
    for(auto const & r : f_rules)
    {
        if(!r->empty())
        {
            return false;
        }
    }
    return true;
}


void section_reference::add_rule(rule::pointer_t r)
{
    f_rules.push_back(r);
}


int section_reference::count_levels(
      rule::vector_t const & dependencies
    , rule::set_t seen_rules) const
{
    int cnt(1);
    for(auto const & d : dependencies)
    {
        auto const status(seen_rules.insert(d));
        if(!status.second)
        {
            SNAP_LOG_ERROR
                << "detected a dependency loop for "
                << d->get_name()
                << SNAP_LOG_SEND;
            return -1;
        }
        int const r(count_levels(d->get_dependencies(), seen_rules));
        if(r < 0)
        {
            return -1;
        }
        cnt = std::max(cnt, r + 1);
    }
    return cnt;
}


bool section_reference::sort_rules()
{
    bool valid(true);

    for(auto & r : f_rules)
    {
        advgetopt::string_list_t before(r->get_before());
        for(auto const & name : before)
        {
            auto it(std::find_if(
                  f_rules.begin()
                , f_rules.end()
                , [name](auto const & other)
                    {
                        return other->get_name() == name;
                    }));
            if(it != f_rules.end())
            {
                (*it)->add_after(r->get_name());
            }
            // else -- ignore missing, it may be available in a different chain
        }
    }

    for(auto & r : f_rules)
    {
        advgetopt::string_list_t after(r->get_after());
        for(auto const & name : after)
        {
            auto it(std::find_if(
                  f_rules.begin()
                , f_rules.end()
                , [name](auto const & other)
                    {
                        return other->get_name() == name;
                    }));
            if(it == f_rules.end())
            {
                // no such target, ignore
                //
                continue;
            }

            r->add_dependency(*it);
        }
    }

    int max_level(0);
    for(auto & r : f_rules)
    {
        rule::set_t seen_rules({r});
        int const level(count_levels(r->get_dependencies(), seen_rules));
        r->set_level(level);
        max_level = std::max(level, max_level);
    }

    rule::vector_t ordered;
    for(int l(1); l <= max_level; ++l)
    {
        for(auto it(f_rules.begin()); it != f_rules.end(); ++it)
        {
            it = std::find_if(
                      it
                    , f_rules.end()
                    , [l](auto q)
                    {
                        return l == q->get_level();
                    });
            if(it == f_rules.end())
            {
                break;
            }
            ordered.push_back(*it);
        }
    }

    // save the ordered list back in the input vector
    //
    f_rules = std::move(ordered);

    return valid;
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


void section_reference::add_after(std::string const & name)
{
    f_section->add_after(name);
}


bool section_reference::get_default() const
{
    return f_section->get_default();
}



// vim: ts=4 sw=4 et
