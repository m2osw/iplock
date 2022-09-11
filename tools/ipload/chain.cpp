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
#include    "chain.h"

#include    "utils.h"


// iplock
//
#include    <iplock/exception.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
#include    <snapdev/string_replace_many.h>


// C++
//
#include    <iostream>


// C
//
#include    <string.h>


// last include
//
#include    <snapdev/poison.h>







// TODO: the list of system chains varies depening on the table
//
std::set<std::string> g_system_chain_names =
{
    "FORWARD",
    "INPUT",
    "OUTPUT",
    "POSTROUTING",
    "PREROUTING",
};




/** \brief Initialize the ipchain object.
 *
 * This function saves the name of the iptable chain in this object.
 *
 * \param[in] it  The iterator to the chain name.
 */
chain::chain(
          advgetopt::conf_file::parameters_t::iterator & it
        , advgetopt::conf_file::parameters_t const & config_params
        , advgetopt::variables::pointer_t variables
        , bool verbose)
    : f_verbose(verbose)
{
    // parse all the parameters we can find
    //
    advgetopt::string_list_t name_list;
    advgetopt::split_string(it->first, name_list, {"::"});
    if(name_list.size() != 3)
    {
        throw iplock::logic_error("the chain name \"" + it->first + "\" is expected to be exactly three names: \"chain::<name>::<parameter>\"");
    }

    // this is the name of the chain
    //
    // it is used by the ipload tool to know in which iptables chain to save
    // rules that reference this chain
    //
    f_name = advgetopt::option_with_underscores(name_list[1]);

    f_is_system_chain = g_system_chain_names.find(f_name) != g_system_chain_names.end();

    std::string const complete_namespace("chain::" + name_list[1] + "::");
    for(; it != config_params.end(); ++it)
    {
        if(strncmp(it->first.c_str(), complete_namespace.c_str(), complete_namespace.length()) != 0)
        {
            // we've exhausted the list
            //
            break;
        }

        std::string value(variables->process_value(it->second));

        std::string_view const param_name(it->first.c_str() + complete_namespace.length(), it->first.length() - complete_namespace.length());
        bool found(true);
        switch(param_name[0])
        {
        case 'd':
            if(param_name == "description")
            {
                f_description = value;
            }
            else
            {
                found = false;
            }
            break;

        case 'l':
            if(param_name == "log")
            {
                f_log = value;
            }
            else
            {
                found = false;
            }
            break;

        case 'p':
            if(param_name == "policy")
            {
                value = to_lower(value);
                if(value == "accept")
                {
                    f_policy = policy_t::POLICY_ACCEPT;
                }
                else if(value == "drop")
                {
                    f_policy = policy_t::POLICY_DROP;
                }
                else
                {
                    SNAP_LOG_RECOVERABLE_ERROR
                        << "unknown chain policy \""
                        << value
                        << "\"."
                        << SNAP_LOG_SEND;
                }
            }
            else
            {
                found = false;
            }
            break;

        case 't':
            if(param_name == "type")
            {
                value = to_lower(value);
                if(value == "return")
                {
                    f_type = type_t::TYPE_RETURN;
                }
                else if(value == "drop")
                {
                    f_type = type_t::TYPE_DROP;
                }
                else if(value == "reject")
                {
                    f_type = type_t::TYPE_REJECT;
                }
                else if(value == "user_defined")
                {
                    f_type = type_t::TYPE_USER_DEFINED;
                }
                else
                {
                    SNAP_LOG_RECOVERABLE_ERROR
                        << "unknown chain type \""
                        << value
                        << "\"."
                        << SNAP_LOG_SEND;
                }
            }
            else
            {
                found = false;
            }
            break;

        default:
            found = false;
            break;

        }
        if(!found)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "unknown chain parameter \""
                << it->first
                << "\"."
                << SNAP_LOG_SEND;
        }
    }
}


bool chain::is_valid() const
{
    return f_valid;
}


bool chain::empty() const
{
    for(auto const & s : f_section_references)
    {
        if(!s->empty())
        {
            return false;
        }
    }
    return true;
}


void chain::add_section_reference(section_reference::pointer_t sr)
{
    // note: ipload sorts the sections first so here they get added
    //       in the correct order
    //
    f_section_references.push_back(sr);
    f_section_references_by_name[sr->get_name()] = sr;

    if(sr->get_default())
    {
        if(f_default_section_references != nullptr)
        {
            SNAP_LOG_ERROR
                << "found two sections marked as defaults: \""
                << f_default_section_references->get_name()
                << "\" and \""
                << sr->get_name()
                << "\"."
                << SNAP_LOG_SEND;
            f_valid = false;
        }
        else
        {
            f_default_section_references = sr;
        }
    }
}


section_reference::vector_t const & chain::get_section_references() const
{
    return f_section_references;
}


bool chain::add_rule(rule::pointer_t r)
{
    std::string const name(r->get_section());
    auto it(f_section_references_by_name.find(name));
    if(it == f_section_references_by_name.end())
    {
        if(f_default_section_references != nullptr)
        {
            // this is the default, add the rule there
            //
            if(f_verbose)
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
            << f_name
            << "\"."
            << SNAP_LOG_SEND;
        f_valid = false;
        return false;
    }

    it->second->add_rule(r);
    return true;
}


std::string chain::get_name() const
{
    return f_name;
}


bool chain::is_system_chain() const
{
    return f_is_system_chain;
}


policy_t chain::get_policy() const
{
    return f_policy;
}


std::string chain::get_policy_name() const
{
    switch(f_policy)
    {
    case policy_t::POLICY_ACCEPT:
        return "ACCEPT";

    case policy_t::POLICY_DROP:
        return "DROP";

    }

    throw iplock::logic_error("the f_policy parameter was somehow set to an unrecognized value.");
}


type_t chain::get_type() const
{
    return f_type;
}


std::string chain::get_log() const
{
    return f_log;
}



// vim: ts=4 sw=4 et
