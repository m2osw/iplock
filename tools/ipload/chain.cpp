// Copyright (c) 2022-2024  Made to Order Software Corp.  All Rights Reserved
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
 * \param[in] config_params  The complete list of parameters.
 * \param[in] variables  A pointer to a set of variables.
 * \param[in] verbose  Whether the --verbose flag was specified.
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
    f_exact_name = f_name;

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
        case 'c':
            if(param_name == "condition"
            || param_name == "conditions")
            {
                f_condition = parse_condition(value, f_valid);
            }
            else
            {
                found = false;
            }
            break;

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

        case 'e':
            if(param_name == "exact-name")
            {
                f_exact_name = value;
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
                advgetopt::string_list_t policies;
                advgetopt::split_string(to_lower(value), policies, {","});
                for(auto const & p : policies)
                {
                    advgetopt::string_list_t table_policy;
                    advgetopt::split_string(p, table_policy, {":"});
                    if(table_policy.size() == 1)
                    {
                        table_policy.insert(table_policy.begin(), "*");
                    }
                    policy_t policy(policy_t::POLICY_DROP);
                    if(table_policy[1] == "accept"
                    || table_policy[1] == "allow")
                    {
                        policy = policy_t::POLICY_ACCEPT;
                    }
                    else if(table_policy[1] != "drop"
                         && table_policy[1] != "blackhole"
                         && table_policy[1] != "deny")
                    {
                        SNAP_LOG_RECOVERABLE_ERROR
                            << "unknown chain policy \""
                            << table_policy[1]
                            << "\"."
                            << SNAP_LOG_SEND;
                    }
                    if(f_policy.find(table_policy[0]) != f_policy.end())
                    {
                        SNAP_LOG_RECOVERABLE_ERROR
                            << "chain policy for table \""
                            << table_policy[0]
                            << "\" defined multiple times."
                            << SNAP_LOG_SEND;
                    }
                    f_policy[table_policy[0]] = policy;
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
                advgetopt::string_list_t types;
                advgetopt::split_string(to_lower(value), types, {","});
                for(auto const & t : types)
                {
                    advgetopt::string_list_t table_type;
                    advgetopt::split_string(t, table_type, {":"});
                    if(table_type.size() == 1)
                    {
                        table_type.insert(table_type.begin(), "*");
                    }
                    type_t type(type_t::TYPE_USER_DEFINED);
                    if(table_type[1] == "return")
                    {
                        type = type_t::TYPE_RETURN;
                    }
                    else if(table_type[1] == "drop")
                    {
                        type = type_t::TYPE_DROP;
                    }
                    else if(table_type[1] == "reject")
                    {
                        type = type_t::TYPE_REJECT;
                    }
                    else if(table_type[1] != "user_defined"
                         && table_type[1] != "user-defined"
                         && table_type[1] != "accept"
                         && table_type[1] != "allow"
                         && table_type[1] != "passthrough")
                    {
                        SNAP_LOG_RECOVERABLE_ERROR
                            << "unknown chain type \""
                            << value
                            << "\"."
                            << SNAP_LOG_SEND;
                    }
                    if(f_type.find(table_type[0]) != f_type.end())
                    {
                        SNAP_LOG_RECOVERABLE_ERROR
                            << "chain type for table \""
                            << table_type[0]
                            << "\" defined multiple times."
                            << SNAP_LOG_SEND;
                    }
                    f_type[table_type[0]] = type;
                }
            }
            else if(param_name == "table"
                 || param_name == "tables")
            {
                advgetopt::split_string(value, f_tables, {","});
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


std::string const & chain::get_name() const
{
    return f_name;
}


std::string const & chain::get_exact_name() const
{
    return f_exact_name;
}


bool chain::get_condition() const
{
    return f_condition;
}


bool chain::is_system_chain() const
{
    return f_is_system_chain;
}


bool chain::is_verbose() const
{
    return f_verbose;
}


policy_t chain::get_policy(std::string const & table_name) const
{
    auto it(f_policy.find(table_name));
    if(it == f_policy.end())
    {
        it = f_policy.find("*");
        if(it == f_policy.end())
        {
            return policy_t::POLICY_DROP;
        }
    }
    return it->second;
}


std::string chain::get_policy_name(std::string const & table_name) const
{
    switch(get_policy(table_name))
    {
    case policy_t::POLICY_ACCEPT:
        return "ACCEPT";

    case policy_t::POLICY_DROP:
        return "DROP";

    }

    throw iplock::logic_error("the f_policy parameter was somehow set to an unrecognized value.");
}


type_t chain::get_type(std::string const & table_name) const
{
    auto it(f_type.find(table_name));
    if(it == f_type.end())
    {
        it = f_type.find("*");
        if(it == f_type.end())
        {
            return type_t::TYPE_DROP;
        }
    }
    return it->second;
}


advgetopt::string_list_t const & chain::get_tables() const
{
    return f_tables;
}


std::string const & chain::get_log() const
{
    return f_log;
}



// vim: ts=4 sw=4 et
