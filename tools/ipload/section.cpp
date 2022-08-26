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
#include    "section.h"

#include    "utils.h"


//// iplock
////
//#include    <iplock/version.h>
//
//
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





section::section(
          advgetopt::conf_file::parameters_t::iterator name
        , advgetopt::conf_file::parameters_t const & config_params
        , advgetopt::variables::pointer_t variables)
{
    std::string const complete_namespace("section::");
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

        std::string_view const param_name(
                                  it->first.c_str() + complete_namespace.length()
                                , it->first.length() - complete_namespace.length());
        bool found(true);
        switch(param_name[0])
        {
        case 'a':
            if(param_name == "after")
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

        case 'd':
            if(param_name == "default")
            {
                f_default = advgetopt::is_true(value);
                if(!f_default && !advgetopt::is_false(value))
                {
                    SNAP_LOG_RECOVERABLE_ERROR
                        << "the \"default\" parameter must represent either \"true\" or \"false\"."
                        << SNAP_LOG_SEND;
                }
            }
            else
            {
                found = false;
            }
            break;

        case 'n':
            if(param_name == "name")
            {
                f_name = value;
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
            << "a section cannot before and after the same section(s): "
            << snapdev::join_strings(common, ", ")
            << "."
            << SNAP_LOG_SEND;
        f_valid = false;
    }

    // TODO: test contradictory states
}


bool section::is_valid() const
{
    return f_valid;
}


void section::mark_invalid()
{
    f_valid = false;
}


std::string const & section::get_name() const
{
    return f_name;
}


advgetopt::string_list_t const & section::get_before() const
{
    return f_before;
}


advgetopt::string_list_t const & section::get_after() const
{
    return f_after;
}


bool section::get_default() const
{
    return f_default;
}



// vim: ts=4 sw=4 et
