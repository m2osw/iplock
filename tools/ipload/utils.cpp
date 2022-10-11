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


// snaplogger
//
#include    <snaplogger/message.h>



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


bool parse_expr_string(char const * & s, std::string & str, bool & valid)
{
    char const quote(s[0]);
    if(quote != '"'
    && quote != '\'')
    {
        SNAP_LOG_ERROR
            << '\''
            << quote
            << "' is not a valid quote to start a string; try with \" or '."
            << SNAP_LOG_SEND;
        valid = false;
        return true;
    }

    ++s;
    char const *start(s);
    for(; *s != quote; ++s)
    {
        if(*s == '\0')
        {
            SNAP_LOG_ERROR
                << "string closing quote is missing."
                << SNAP_LOG_SEND;
            valid = false;
            return true;
        }
    }

    ++s;    // skip quote

    str = std::string(start, s);

    return true;
}


bool parse_condition(std::string const & expression, bool & valid)
{
    // TODO: replace with the as2js parser & optimizer
    //
    if(expression.empty())
    {
        return true;
    }

    char const * s(expression.c_str());

    std::string first;
    if(!parse_expr_string(s, first, valid))
    {
        return true;
    }

    while(isspace(*s))
    {
        ++s;
    }

    bool equal(true);
    if(*s == '!')
    {
        equal = false;
    }
    else if(*s != '=')
    {
        SNAP_LOG_ERROR
            << "expression ["
            << expression
            << "] operator missing (expected == or !=)."
            << SNAP_LOG_SEND;
        valid = false;
        return true;
    }
    ++s;
    if(*s != '=')
    {
        SNAP_LOG_ERROR
            << "expression ["
            << expression
            << "] operator missing (expected == or !=)."
            << SNAP_LOG_SEND;
        valid = false;
        return true;
    }
    ++s;   // skip second '='

    while(isspace(*s))
    {
        ++s;
    }

    std::string second;
    if(!parse_expr_string(s, second, valid))
    {
        return true;
    }

    while(isspace(*s) || *s == ';')
    {
        ++s;
    }

    if(*s != '\0')
    {
        SNAP_LOG_ERROR
            << "expression ["
            << expression
            << "] has spurious data at the end."
            << SNAP_LOG_SEND;
        valid = false;
        return true;
    }

    return (first == second) == equal;
}



// vim: ts=4 sw=4 et
