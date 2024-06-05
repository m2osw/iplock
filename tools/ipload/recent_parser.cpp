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
#include    "recent_parser.h"


// snaplogger
//
#include    <snaplogger/message.h>


// advgetopt
//
#include    <advgetopt/validator_duration.h>
#include    <advgetopt/validator_integer.h>


// snapdev
//
#include    <snapdev/not_reached.h>


// // C
// //
// #include    <netdb.h>


// last include
//
#include    <snapdev/poison.h>






// the recent feature supports the following in iptables:
//
// --name <name>
// [!] --set
// --rsource
// --rdest
// --mask netmask
// [!] --rcheck
// [!] --update
// [!] --remove
// --seconds <seconds>
// --reap
// --hitcount hits
// --rttl
//
// the following is our syntax instead:
//
//    start: not function name hitcount
//         | ttl
//         | ip-selection
//         | mask
//         | flags
//         | start start
//    not: <empty>
//       | '!'
//    function: "set"
//          | "check" | "rcheck"
//          | "update"
//          | "remove"
//    name: <identifier>
//    hitcount: <empty>
//            | <integer>    # only if function is "check" or "update"
//    ttl: <duration>
//    ip-selection: "source" | "rsource"
//                | "dest" | "rdest" | "destination" | "rdestination"
//    mask: '/' <integer>    # IPv6 CIDR mask
//    flags: "reap"
//         | "rttl"
//
// notes:
//
// - all keywords can be in lower- or uppercase
// - '!' used on "original" or "reply" swaps the words for "reply"/"orignal"



recent_parser::recent_parser()
{
}


bool recent_parser::parse(std::string const & expression)
{
    f_expression = expression;
    f_in = 0;

    next_token();
    for(;;)
    {
        // negate is allow for most everything so that way we can say
        // "reap" or "!reap" -- only the mask forbids it
        //
        bool const negate(f_last_token == token_t::TOKEN_NEGATE);
        if(negate)
        {
            next_token();
        }

        switch(f_last_token)
        {
        case token_t::TOKEN_EOF:
            return f_valid;

        case token_t::TOKEN_NEGATE:
            SNAP_LOG_ERROR
                << "Only one '!' can be used at a time."
                << SNAP_LOG_SEND;
            f_valid = false;
            next_token();
            break;

        case token_t::TOKEN_SLASH:
            // mask
            if(negate)
            {
                SNAP_LOG_ERROR
                    << "The recent mask does not support the '!' operator."
                    << SNAP_LOG_SEND;
                f_valid = false;
                next_token();
            }
            else
            {
                next_token();
                std::int64_t mask(0);
                if(advgetopt::validator_integer::convert_string(f_value, mask))
                {
                    // this is the TTL
                    //
                    f_mask = mask;
                    next_token();
                }
            }
            break;

        case token_t::TOKEN_IDENTIFIER:
            {
                double ttl(0.0);
                if(advgetopt::validator_duration::convert_string(
                              f_value
                            , advgetopt::validator_duration::VALIDATOR_DURATION_DEFAULT_FLAGS
                            , ttl))
                {
                    // this is the TTL
                    //
                    if(ttl <= 0.0)
                    {
                        SNAP_LOG_ERROR
                            << "The recent TTL must be a positive number."
                            << SNAP_LOG_SEND;
                        f_valid = false;
                    }
                    else
                    {
                        f_ttl = static_cast<std::int64_t>(ttl);
                    }
                    next_token();
                    break;
                }

                if(f_value == "rttl")
                {
                    f_rttl = !negate;
                    next_token();
                    break;
                }
                if(f_value == "reap")
                {
                    f_reap = !negate;
                    next_token();
                    break;
                }
                if(f_value == "source"
                || f_value == "rsource")
                {
                    f_destination = negate;
                    next_token();
                    break;
                }
                if(f_value == "dest"
                || f_value == "rdest"
                || f_value == "destination"
                || f_value == "rdestination")
                {
                    f_destination = !negate;
                    next_token();
                    break;
                }

                bool function(false);
                if(f_value == "set")
                {
                    f_recent = recent_t::RECENT_SET;
                    function = true;
                }
                else if(f_value == "check" || f_value == "rcheck")
                {
                    f_recent = recent_t::RECENT_CHECK;
                    function = true;
                }
                else if(f_value == "update")
                {
                    f_recent = recent_t::RECENT_UPDATE;
                    function = true;
                }
                else if(f_value == "remove")
                {
                    f_recent = recent_t::RECENT_REMOVE;
                    function = true;
                }
                if(function)
                {
                    f_negate = negate;
                    next_token();
                    if(f_last_token == token_t::TOKEN_IDENTIFIER)
                    {
                        f_name = f_value;
                        next_token();

                        if(f_recent == recent_t::RECENT_CHECK
                        || f_recent == recent_t::RECENT_UPDATE)
                        {
                            std::int64_t hitcount(0);
                            if(advgetopt::validator_integer::convert_string(f_value, hitcount))
                            {
                                // this is the number of hits within the TTL
                                //
                                if(hitcount > 255)
                                {
                                    SNAP_LOG_ERROR
                                        << "The hitcount of the recent extension is limited to 255."
                                        << SNAP_LOG_SEND;
                                    f_valid = false;
                                    f_hitcount = 255;
                                }
                                else
                                {
                                    f_hitcount = hitcount;
                                }
                                next_token();
                            }
                        }
                    }
                    else
                    {
                        SNAP_LOG_ERROR
                            << "a function (\"set\", \"check\", \"update\", or \"remove\") must be followed by the name of a set."
                            << SNAP_LOG_SEND;
                        f_valid = false;
                    }
                }
                else
                {
                    SNAP_LOG_ERROR
                        << "unknown identifier \""
                        << f_value
                        << "\"."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                    next_token();
                }
            }
            break;

        default:
            SNAP_LOG_ERROR
                << "recent parsing issue; got token "
                << static_cast<int>(f_last_token)
                << "; start just before \""
                << f_expression.substr(f_in)
                << "\"."
                << SNAP_LOG_SEND;
            f_valid = false;
            next_token();
            break;

        }
    }
    snapdev::NOT_REACHED();
}


int recent_parser::getc()
{
    int result(EOF);
    if(f_unget != '\0')
    {
        result = f_unget;
        f_unget = '\0';
    }
    else if(f_in < f_expression.length())
    {
        result = f_expression[f_in];
        ++f_in;
    }

    return result;
}


void recent_parser::ungetc(int c)
{
    if(f_unget != '\0')
    {
        throw std::runtime_error("unget already in use (one ungetc() call at a time).");
    }

    if(c != EOF)
    {
        f_unget = c;
    }
}


void recent_parser::next_token()
{
    f_value.clear();
    //f_integer = 0;
    for(;;)
    {
        int c(getc());
        switch(c)
        {
        case EOF:
            f_last_token = token_t::TOKEN_EOF;
            return;

        case ' ':
        case '\t':
        case '\n':
        case '\r':
            // ignore spaces
            continue;

        case '/':
            f_last_token = token_t::TOKEN_SLASH;
            return;

        case '!':
            f_last_token = token_t::TOKEN_NEGATE;
            return;

        default:
            f_last_token = token_t::TOKEN_IDENTIFIER;
            while((c >= 'a' && c <= 'z')
               || (c >= 'A' && c <= 'Z')
               || (c >= '0' && c <= '9')
               || c == '_'
               || c == '-')
            {
                if(c >= 'A' && c <= 'Z')
                {
                    f_value = c | 0x20; // lowercase
                }
                else
                {
                    if(c == '-')
                    {
                        c = '_';
                    }
                    f_value += c;
                }
                c = getc();
            }
            ungetc(c);
            return;

        }
        SNAP_LOG_ERROR
            << "found invalid character in the \"recent = ...\" input string '"
            << c
            << "'."
            << SNAP_LOG_SEND;
        f_value = false;
    }
}


bool recent_parser::get_valid() const
{
    return f_valid;
}


bool recent_parser::get_negate() const
{
    return f_negate;
}


bool recent_parser::get_destination() const
{
    return f_destination;
}


bool recent_parser::get_reap() const
{
    return f_reap;
}


bool recent_parser::get_rttl() const
{
    return f_rttl;
}


recent_t recent_parser::get_recent() const
{
    return f_recent;
}


std::string const & recent_parser::get_name() const
{
    return f_name;
}


std::int64_t recent_parser::get_ttl() const
{
    return f_ttl;
}


std::int64_t recent_parser::get_hitcount() const
{
    return f_hitcount;
}


std::int64_t recent_parser::get_mask() const
{
    return f_mask;
}



// vim: ts=4 sw=4 et
