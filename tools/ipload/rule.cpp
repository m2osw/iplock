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
#include    "rule.h"

#include    "utils.h"


// iplock
//
#include    <iplock/exception.h>


//// libaddr
////
//#include    <libaddr/addr_parser.h>
//
//
//// advgetopt
////
//#include    <advgetopt/exception.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
#include    <snapdev/join_strings.h>


//// boost
////
//#include    <boost/preprocessor/stringize.hpp>
//
//
//// C++
////
////#include    <iostream>
////#include    <fstream>
////#include    <sstream>


// C
//
#include    <string.h>


// last include
//
#include    <snapdev/poison.h>






rule::rule(
          advgetopt::conf_file::parameters_t::iterator name
        , advgetopt::conf_file::parameters_t const & config_params
        , advgetopt::variables::pointer_t variables)
{
    // parse all the parameters we can find
    //
    advgetopt::string_list_t name_list;
    advgetopt::split_string(name->first, name_list, {"::"});
    if(name_list.size() != 2)
    {
        throw iplock::logic_error("the rule name is expected to be exactly two parameters: \"rule>::<name>\"");
    }

    // this is the name of the rule
    // it is used by the ipload tool to sort the rules between each others
    // with the list of names in the before & after parameters
    //
    f_name = name_list[1];

    std::string const complete_namespace("rule::" + f_name + "::");
    ++name;
    for(auto it(name); it != config_params.end(); ++it)
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
        case 'a':
            if(param_name == "action")
            {
                parse_action(value);
            }
            else if(param_name == "after")
            {
                advgetopt::split_string(value, f_after, {","});
                list_to_lower(f_after);
                std::sort(f_after.begin(), f_after.end());
            }
            else
            {
                found = false;
            }
            break;

        case 'b':
            if(param_name == "before")
            {
                advgetopt::split_string(value, f_before, {","});
                list_to_lower(f_before);
                std::sort(f_before.begin(), f_before.end());
            }
            else
            {
                found = false;
            }
            break;

        case 'c':
            if(param_name == "chains")
            {
                advgetopt::split_string(value, f_chains, {","});
                list_to_lower(f_chains);
            }
            else if(param_name == "condition")
            {
                f_condition = value;
            }
            else
            {
                found = false;
            }
            break;

        case 'd':
            if(param_name == "destination_intefaces")
            {
                advgetopt::split_string(value, f_destination_interfaces, {","});
                list_to_lower(f_destination_interfaces);
            }
            else if(param_name == "destinations")
            {
                advgetopt::split_string(value, f_destinations, {","});
            }
            else if(param_name == "destination_ports")
            {
                advgetopt::split_string(value, f_destination_ports, {","});
            }
            else
            {
                found = false;
            }
            break;

        case 'e':
            if(param_name == "except_destinations")
            {
                advgetopt::split_string(value, f_except_destinations, {","});
            }
            else if(param_name == "except_sources")
            {
                advgetopt::split_string(value, f_except_sources, {","});
            }
            else
            {
                found = false;
            }
            break;

        case 'l':
            if(param_name == "limits")
            {
                advgetopt::split_string(value, f_limits, {","});
            }
            else if(param_name == "log")
            {
                f_log = value;
            }
            else
            {
                found = false;
            }
            break;

        case 'p':
            if(param_name == "protocols")
            {
                advgetopt::split_string(value, f_protocols, {","});
            }
            else
            {
                found = false;
            }
            break;

        case 's':
            if(param_name == "section")
            {
                f_section = value;
            }
            else if(param_name == "source_intefaces")
            {
                advgetopt::split_string(value, f_source_interfaces, {","});
            }
            else if(param_name == "sources")
            {
                advgetopt::split_string(value, f_sources, {","});
            }
            else if(param_name == "source_ports")
            {
                advgetopt::split_string(value, f_source_ports, {","});
            }
            else if(param_name == "states")
            {
                advgetopt::split_string(value, f_states, {","});
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
                << "unknown rule parameter \""
                << it->first
                << "\"."
                << SNAP_LOG_SEND;
        }
    }

    if(!f_except_sources.empty()
    && !f_sources.empty())
    {
        SNAP_LOG_ERROR
            << "a rule cannot have \"sources\" and \"except-sources\" at the same time."
            << SNAP_LOG_SEND;
        f_valid = false;
    }

    advgetopt::string_list_t common;
    std::set_intersection(
              f_after.begin()
            , f_after.end()
            , f_before.begin()
            , f_before.end()
            , std::back_inserter(common));
    if(!common.empty())
    {
        SNAP_LOG_ERROR
            << "a rule cannot before and after the same rule(s): "
            << snapdev::join_strings(common, ", ")
            << "."
            << SNAP_LOG_SEND;
        f_valid = false;
    }

    // TODO: test contradictory states
}


void rule::parse_action(std::string const & action)
{
    advgetopt::string_list_t action_param;
    advgetopt::split_string(action, action_param, {" "});

    // make the action case insensitive
    //
    std::string a;
    for(auto c : action_param[0])
    {
        if(c >= 'A' && c <= 'Z')
        {
            a += c | 0x020;
        }
        else
        {
            a += c;
        }
    }
    if(a.length() > 0 )
    {
        switch(a[0])
        {
        case 'a':
            if(a == "accept")
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"ACCEPT\" action does not support a parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_ACCEPT;
                }
                return;
            }
            break;

        case 'c':
            if(a == "call")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"CALL\" action must be used with exactly one parameter (chain name)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_CALL;
                    f_action_param = action_param[1];
                }
                return;
            }
            break;

        case 'd':
            if(a == "drop")
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"DROP\" action does not support a parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_DROP;
                }
                return;
            }
            break;

        case 'l':
            if(a == "log")
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"LOG\" action does not support a parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_LOG;
                }
                return;
            }
            break;

        case 'r':
            if(a == "reject")
            {
                if(action_param.size() > 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"REJECT\" action only supports zero or one parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_REJECT;
                    if(action_param.size() == 2)
                    {
                        f_action_param = action_param[1];
                    }
                }
                return;
            }
            break;

        }
    }

    SNAP_LOG_ERROR
        << "unknown action \""
        << action
        << "\"."
        << SNAP_LOG_SEND;
    f_valid = false;
}


bool rule::is_valid() const
{
    return f_valid;
}


std::string const & rule::get_name() const
{
    return f_name;
}


advgetopt::string_list_t const & rule::get_chains() const
{
    return f_chains;
}


std::string const & rule::get_section() const
{
    return f_section;
}


advgetopt::string_list_t const & rule::get_before() const
{
    return f_before;
}


advgetopt::string_list_t const & rule::get_after() const
{
    return f_after;
}


std::string const & rule::get_condition() const
{
    return f_condition;
}


advgetopt::string_list_t const & rule::get_source_interfaces() const
{
    return f_source_interfaces;
}


advgetopt::string_list_t const & rule::get_sources() const
{
    return f_sources;
}


advgetopt::string_list_t const & rule::get_except_sources() const
{
    return f_except_sources;
}


advgetopt::string_list_t const & rule::get_source_ports() const
{
    return f_source_ports;
}


advgetopt::string_list_t const & rule::get_destination_interfaces() const
{
    return f_destination_interfaces;
}


advgetopt::string_list_t const & rule::get_destinations() const
{
    return f_destinations;
}


advgetopt::string_list_t const & rule::get_except_destinations() const
{
    return f_except_destinations;
}


advgetopt::string_list_t const & rule::get_destination_ports() const
{
    return f_destination_ports;
}


advgetopt::string_list_t const & rule::get_protocols() const
{
    return f_protocols;
}


advgetopt::string_list_t const & rule::get_states() const
{
    return f_states;
}


advgetopt::string_list_t const & rule::get_limits() const
{
    return f_limits;
}


action_t rule::get_action() const
{
    return f_action;
}


std::string const & rule::get_log() const
{
    return f_log;
}



// vim: ts=4 sw=4 et
