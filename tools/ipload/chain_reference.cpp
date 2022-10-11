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
 * scripts and upload those scripts using iptables.
 */


// self
//
#include    "chain_reference.h"


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



chain_reference::chain_reference(chain::pointer_t s)
    : f_chain(s)
{
}


bool chain_reference::is_valid() const
{
    return f_chain->is_valid();
}


bool chain_reference::empty(std::string const & table_name) const
{
    if(f_chain->get_policy(table_name) != policy_t::POLICY_ACCEPT)
    {
        return false;
    }

    for(auto const & s : f_section_references)
    {
        if(!s->empty())
        {
            return false;
        }
    }
    return true;
}


void chain_reference::add_section_reference(section_reference::pointer_t section_reference)
{
    // note: ipload sorts the sections first so here they get added
    //       in the correct order
    //
    f_section_references.push_back(section_reference);
    f_section_references_by_name[section_reference->get_name()] = section_reference;

    if(section_reference->get_default())
    {
        if(f_default_section_references != nullptr)
        {
            SNAP_LOG_ERROR
                << "found two sections marked as defaults: \""
                << f_default_section_references->get_name()
                << "\" and \""
                << section_reference->get_name()
                << "\"."
                << SNAP_LOG_SEND;
            f_valid = false;
        }
        else
        {
            f_default_section_references = section_reference;
        }
    }
}


bool chain_reference::add_rule(rule::pointer_t r)
{
    std::string const name(r->get_section());
    auto it(f_section_references_by_name.find(name));
    if(it == f_section_references_by_name.end())
    {
        if(f_default_section_references != nullptr)
        {
            // this is the default, add the rule there
            //
            if(f_chain->is_verbose())
            {
                SNAP_LOG_VERBOSE
                    << "rule \""
                    << r->get_name()
                    << "\" has no \"section = ...\" parameter so it is being added to default section \""
                    << f_default_section_references->get_name()
                    << "\"."
                    << SNAP_LOG_SEND;
            }
            f_default_section_references->add_rule(r);
            return true;
        }
        SNAP_LOG_RECOVERABLE_ERROR
            << "section \""
            << name
            << "\" not found and no section marked as the default section. Cannot add rule \""
            << r->get_name()
            << "\" to chain \""
            << f_chain->get_name()
            << "\"."
            << SNAP_LOG_SEND;
        f_valid = false;
        return false;
    }

    it->second->add_rule(r);
    return true;
}


section_reference::vector_t const & chain_reference::get_section_references() const
{
    return f_section_references;
}


std::string const & chain_reference::get_name() const
{
    return f_chain->get_name();
}


std::string const & chain_reference::get_exact_name() const
{
    return f_chain->get_exact_name();
}


bool chain_reference::get_condition() const
{
    return f_chain->get_condition();
}


policy_t chain_reference::get_policy(std::string const & table_name) const
{
    return f_chain->get_policy(table_name);
}


std::string chain_reference::get_policy_name(std::string const & table_name) const
{
    return f_chain->get_policy_name(table_name);
}


type_t chain_reference::get_type(std::string const & table_name) const
{
    return f_chain->get_type(table_name);
}


std::string const & chain_reference::get_log() const
{
    return f_chain->get_log();
}


bool chain_reference::is_system_chain() const
{
    return f_chain->is_system_chain();
}



// vim: ts=4 sw=4 et
