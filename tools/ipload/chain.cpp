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
        , advgetopt::variables::pointer_t variables)
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


void chain::add_section_reference(section_reference::pointer_t sr)
{
    f_section_references_by_name[sr->get_name()] = sr;

    std::string const & name(sr->get_name());
    advgetopt::string_list_t const & before(sr->get_before());
    advgetopt::string_list_t const & after(sr->get_after());

    // compute the minimum position first
    //
    std::string other_name;
    std::int64_t min_idx(-1);
    {
        std::size_t idx(f_section_references.size());
        while(idx > 0)
        {
            --idx;
            other_name = f_section_references[idx]->get_name();
            if(std::find(after.begin(), after.end(), other_name) != after.end())
            {
                min_idx = idx;
                break;
            }
            advgetopt::string_list_t const & other_before(f_section_references[idx]->get_before());
            if(std::find(other_before.begin(), other_before.end(), name) != other_before.end())
            {
                min_idx = idx;
                break;
            }
        }
    }

    std::int64_t found(-1);
    for(std::size_t idx(0); idx < f_section_references.size(); ++idx)
    {
        other_name = f_section_references[idx]->get_name();
        if(std::find(before.begin(), before.end(), other_name) != before.end())
        {
            found = idx;
            break;
        }
        advgetopt::string_list_t const & other_after(f_section_references[idx]->get_after());
        if(std::find(other_after.begin(), other_after.end(), name) != other_after.end())
        {
            found = idx;
            break;
        }
    }

    if(found != -1)
    {
        if(found <= min_idx)
        {
            // TODO: I think we could check whether it would be possible
            //       to swap idx and min_idx so the insert is possible...
            //
            SNAP_LOG_ERROR
                << "section named \""
                << sr->get_name()
                << "\" was required to be before \""
                << name
                << "\" and after \""
                << f_section_references[min_idx]
                << "\" at the same, only those sections are not sorted in such a way that this is currently possible."
                << SNAP_LOG_SEND;
            f_valid = false;
        }
        else
        {
            f_section_references.insert(f_section_references.begin() + found, sr);
        }
        return;
    }

    // not inserted yet, add at the end
    //
    f_section_references.push_back(sr);
}


section_reference::vector_t const & chain::get_section_references() const
{
    return f_section_references;
}


bool chain::add_rule(rule::pointer_t r)
{
    std::string const name(snapdev::string_replace_many(r->get_section(), {{"_","-"}}));
    auto it(f_section_references_by_name.find(name));
    if(it == f_section_references_by_name.end())
    {
        for(auto const & s : f_section_references_by_name)
        {
            if(s.second->get_default())
            {
                // this is the default, add the rule there
                //
                s.second->add_rule(r);
                return true;
            }
        }
        SNAP_LOG_RECOVERABLE_ERROR
            << "section \""
            << name
            << "\" not found. Cannot add rule \""
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
