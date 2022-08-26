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


//// advgetopt
////
//#include    <advgetopt/exception.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
//#include    <snapdev/join_strings.h>


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











/** \brief Initialize the ipchain object.
 *
 * This function saves the name of the iptable chain in this object.
 *
 * \param[in] name  The iterator to the chain name.
 */
chain::chain(
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
        throw iplock::logic_error("the chain name is expected to be exactly two parameters: \"chain::<name>\"");
    }

    // this is the name of the chain
    //
    // it is used by the ipload tool to know in which iptables chain to save
    // rules that reference this chain
    //
    f_name = name_list[1];

    std::string const complete_namespace("chain::" + f_name + "::");
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
                else if(value == "user_defined")
                {
                    f_type = type_t::TYPE_USER_DEFINED;
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
    advgetopt::string_list_t const & before(sr->get_before());
    advgetopt::string_list_t const & after(sr->get_after());

    // compute the minimum position first
    //
    std::size_t min_idx(0);
    {
        std::size_t idx(f_section_references.size());
        while(idx > 0)
        {
            std::string const & name(f_section_references[idx]->get_name());
            if(std::find(after.begin(), after.end(), name) != after.end())
            {
                min_idx = idx + 1;
                break;
            }
            --idx;
        }
    }

    for(std::size_t idx(0); idx < f_section_references.size(); ++idx)
    {
        std::string const & name(f_section_references[idx]->get_name());
        if(std::find(before.begin(), before.end(), name) != before.end())
        {
            if(idx < min_idx)
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
                    << f_section_references[min_idx - 1]
                    << "\" at the same, only those sections are not sorted in such a way that this is currently possible."
                    << SNAP_LOG_SEND;
                f_valid = false;
            }
            else
            {
                f_section_references.insert(f_section_references.begin() + idx, sr);
            }
            return;
        }
    }

    // not inserted yet, add at the end
    //
    f_section_references.push_back(sr);
}


section_reference::vector_t const & chain::get_section_references() const
{
    return f_section_references;
}



// vim: ts=4 sw=4 et
