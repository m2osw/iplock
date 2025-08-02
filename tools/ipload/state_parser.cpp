// Copyright (c) 2022-2025  Made to Order Software Corp.  All Rights Reserved
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
#include    "state_parser.h"

//#include    "utils.h"
//
//
//// iplock
////
//#include    <iplock/exception.h>
//
//
//// advgetopt
////
//#include    <advgetopt/validator_integer.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
//#include    <snapdev/join_strings.h>
#include    <snapdev/not_reached.h>


//// C
////
//#include    <string.h>


// last include
//
#include    <snapdev/poison.h>



/** \class state_parser
 * \brief This class is used to parse the state field.
 *
 * This state field is pretty complex. It allows for a set of states but
 * many are in conflict so we use an advanced parser to make sure that
 * we do not end up with an invalid entry.
 *
 * Also the state matches either the TCP flags or the `-m state` state.
 *
 * The currently supported syntax goes like this:
 *
 * \code
 * start: mask_compare
 *      | start ',' mask_compare
 *
 * mask_compare: flag_list
 *             | flag_list '=' flag_list
 *
 * flag_list: flag_name
 *          | flag_list '|' flag_name
 *
 * flag_name: 'syn'
 *          | 'ack'
 *          | 'fin'
 *          | 'rst'
 *          | 'urg'
 *          | 'psh'
 *          | 'new'
 *          | 'old'
 *          | 'all'
 *          | 'none'
 *          | 'established'
 *          | 'related'
 *          | 'timestamp-request'
 *          | 'timestamp-reply'
 *          | 'any'
 *          | 'tcpmss' INTEGER
 *          | '(' flag_list ')'
 *          | '!' flag_name
 * \endcode
 *
 * Although we use a different mechanism to detect errors (duplicates and
 * conflicting states).
 */



state_parser::state_parser(char const * in)
    : f_in(in)
{
}


state_result::vector_t state_parser::get_results() const
{
    return f_result_list;
}


bool state_parser::parse()
{
    next_token();
    start();

    if(f_last_token != TOKEN_EOF)
    {
        f_valid = false;
        SNAP_LOG_ERROR
            << "syntax error, unexpected token around \""
            << std::string(f_in)
            << "\"."
            << SNAP_LOG_SEND;
    }

    return f_valid;
}


void state_parser::start()
{
    // start: mask_compare
    //      | start ',' mask_compare
    //
    for(;;)
    {
        mask_compare();
        if(f_last_token != TOKEN_COMMA)
        {
            break;
        }
        next_token();
    }
}


void state_parser::mask_compare()
{
    // mask_compare: flag_list
    //             | flag_list '=' flag_list
    //
    f_result = {};

    flag_list();

    if(f_last_token == TOKEN_EQUAL)
    {
        next_token();

        // the first call to flag_list() defined a mask, not the compare
        // so swap the values
        //
        f_result.set_tcp_mask(f_result.get_tcp_compare());
        f_result.set_tcp_compare(TCP_UNDEFINED);

        flag_list();
    }
    else
    {
        if(f_result.get_tcp_mask() == TCP_UNDEFINED)
        {
            f_result.set_tcp_mask(TCP_ALL);
        }
    }

    if(f_result.is_valid())
    {
        auto const & it(std::find(
                  f_result_list.begin()
                , f_result_list.end()
                , f_result));
        if(it == f_result_list.end())
        {
            // only keep unique entries to avoid duplicity in the list of
            // rules to add to the iptabels (not efficient)
            //
            f_result_list.push_back(f_result);
        }
        else
        {
            SNAP_LOG_WARNING
                << "two sets of flags are equal; ignoring the second set."
                << SNAP_LOG_SEND;
        }
    }
    else
    {
        f_valid = false;
    }
}


void state_parser::flag_list()
{
    // flag_list: flag_name
    //           | flag_list '|' flag_name
    //
    f_standalone_flag_name = false;
    f_special_flag_name = false;
    for(;;)
    {
        flag_name();
        if(f_last_token != TOKEN_OR)
        {
            if(f_standalone_flag_name && f_special_flag_name)
            {
                SNAP_LOG_ERROR
                    << "special flags ('all', 'none', 'new', and 'old') cannot be used with the standard flags ('syn', 'ack', 'fin', 'rst', 'urg', 'psh')."
                    << SNAP_LOG_SEND;
            }
            return;
        }
        next_token();
    }
}


void state_parser::flag_name()
{
    // flags: 'syn'
    //      | 'ack'
    //      | 'fin'
    //      | 'rst'
    //      | 'urg'
    //      | 'psh'
    //      | 'new'
    //      | 'old'
    //      | 'invalid'
    //      | 'established'
    //      | 'related'
    //      | 'all'
    //      | 'tcpmss' <integer>
    //      | 'none'
    //      | '(' flag_list ')'
    //      | '!' flag_name
    //

    // whether we find a valid flag, we remove the "undefined" bit
    //
    f_result.set_tcp_compare(f_result.get_tcp_compare() & ~TCP_UNDEFINED);
    switch(f_last_token)
    {
    case TOKEN_SYN:
        f_standalone_flag_name = true;
        f_result.set_tcp_compare(f_result.get_tcp_compare() | TCP_SYN);
        break;

    case TOKEN_ACK:
        f_standalone_flag_name = true;
        f_result.set_tcp_compare(f_result.get_tcp_compare() | TCP_ACK);
        break;

    case TOKEN_FIN:
        f_standalone_flag_name = true;
        f_result.set_tcp_compare(f_result.get_tcp_compare() | TCP_FIN);
        break;

    case TOKEN_RST:
        f_standalone_flag_name = true;
        f_result.set_tcp_compare(f_result.get_tcp_compare() | TCP_RST);
        break;

    case TOKEN_URG:
        f_standalone_flag_name = true;
        f_result.set_tcp_compare(f_result.get_tcp_compare() | TCP_URG);
        break;

    case TOKEN_PSH:
        f_standalone_flag_name = true;
        f_result.set_tcp_compare(f_result.get_tcp_compare() | TCP_PSH);
        break;

    case TOKEN_NEW:
        f_special_flag_name = true;
        f_result.set_tcp_mask(TCP_SYN | TCP_RST | TCP_ACK | TCP_FIN);
        f_result.set_tcp_compare(TCP_SYN);
        break;

    case TOKEN_OLD:
        f_special_flag_name = true;
        f_result.set_tcp_negate(true);
        f_result.set_tcp_mask(TCP_SYN | TCP_RST | TCP_ACK | TCP_FIN);
        f_result.set_tcp_compare(TCP_SYN);
        break;

    case TOKEN_ESTABLISHED:
    case TOKEN_RELATED:
        f_result.set_established_related(true);
        break;

    case TOKEN_INVALID:
        f_result.set_invalid(true);
        break;

    case TOKEN_ALL:
        f_special_flag_name = true;
        f_result.set_tcp_compare(TCP_ALL);
        break;

    case TOKEN_ANY:
        f_result.set_icmp_type("any");
        break;

    case TOKEN_TIMESTAMP_REQUEST:
        f_result.set_icmp_type("timestamp-request");
        break;

    case TOKEN_TIMESTAMP_REPLY:
        f_result.set_icmp_type("timestamp-reply");
        break;

    case TOKEN_NONE:
        f_special_flag_name = true;
        f_result.set_tcp_compare(TCP_NONE);
        break;

    case token_t::TOKEN_OPEN_PARENTHESIS:
        next_token();
        flag_list();
        if(f_last_token == token_t::TOKEN_CLOSE_PARENTHESIS)
        {
            next_token();
        }
        else
        {
            f_valid = false;
            SNAP_LOG_ERROR
                << "expected a ')'."
                << SNAP_LOG_SEND;
        }
        break;

    case token_t::TOKEN_NEGATE:
        next_token();
        flag_name();
        f_result.set_tcp_negate(!f_result.get_tcp_negate());
        break;

    case token_t::TOKEN_TCPMSS:
        next_token();
        if(f_last_token == token_t::TOKEN_NEGATE)
        {
            f_result.set_tcpmss_negate(true);
            next_token();
        }
        if(f_last_token != token_t::TOKEN_INTEGER)
        {
            f_valid = false;
            SNAP_LOG_ERROR
                << "the 'tcpmss' state must be followed by an integer or a range."
                << SNAP_LOG_SEND;
            return;
        }
        f_result.set_tcpmss_min(f_integer);
        next_token();
        if(f_last_token == token_t::TOKEN_DASH)
        {
            next_token();
            if(f_last_token != token_t::TOKEN_INTEGER)
            {
                f_valid = false;
                SNAP_LOG_ERROR
                    << "the 'tcpmss' state range must include an integer after the dash."
                    << SNAP_LOG_SEND;
                return;
            }
            f_result.set_tcpmss_max(f_integer);
            next_token();
        }
        else
        {
            f_result.set_tcpmss_max(f_result.get_tcpmss_min());
        }
        break;

    default:
        f_valid = false;
        SNAP_LOG_ERROR
            << "expected the name of a TCP flag, '!' or '('; found token "
            << static_cast<int>(f_last_token)
            << " instead."
            << SNAP_LOG_SEND;
        return;

    }
    next_token();
}


int state_parser::getc()
{
    if(*f_in == '\0')
    {
        return EOF;
    }

    int const c(*f_in);
    ++f_in;
    return c;
}


void state_parser::unget_last()
{
    --f_in;
}


void state_parser::next_token()
{
    for(;;)
    {
        int c(getc());
        switch(c)
        {
        case EOF:
            f_last_token = TOKEN_EOF;
            return;

        case ' ':   // ignore spaces
        case '\t':
        case '\f':
        case '\v':
        case '\n':
        case '\r':
            break;

        case '!':
        case '(':
        case ')':
        case ',':
        case '|':
        case '=':
        case '-':
            f_last_token = static_cast<token_t>(c); // as is (it happens to match one to one)
            return;

        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            f_integer = c - '0';
            for(;;)
            {
                c = getc();
                if(c < '0' || c > '9')
                {
                    break;
                }
                f_integer = f_integer * 10 + c - '0';
            }
            if(c != EOF)
            {
                unget_last();
            }
            f_last_token = TOKEN_INTEGER;
            return;

        default:
            {
                std::string identifier;

                if(c >= 'A' && c <= 'Z')
                {
                    identifier += c | 0x20;
                }
                else if(c < 'a' || c > 'z')
                {
                    f_valid = false;
                    SNAP_LOG_ERROR
                        << "unexpected character '"
                        << static_cast<char>(c)
                        << "' in list of states."
                        << SNAP_LOG_SEND;
                    f_last_token = TOKEN_EOF;
                    return;
                }
                else
                {
                    identifier += c;
                }

                for(;;)
                {
                    c = getc();
                    if(c == '_')
                    {
                        identifier += '-';
                    }
                    else if(c >= 'A' && c <= 'Z')
                    {
                        identifier = c | 0x20;
                    }
                    else if((c >= 'a' && c <= 'z')
                         || c == '-')
                    {
                        identifier += c;
                    }
                    else
                    {
                        if(c != EOF)
                        {
                            unget_last();
                        }

                        switch(identifier[0])
                        {
                        case 'a':
                            if(identifier == "all")
                            {
                                f_last_token = TOKEN_ALL;
                                return;
                            }
                            else if(identifier == "any")
                            {
                                f_last_token = TOKEN_ANY;
                                return;
                            }
                            else if(identifier == "ack")
                            {
                                f_last_token = TOKEN_ACK;
                                return;
                            }
                            break;

                        case 'e':
                            if(identifier == "established")
                            {
                                f_last_token = TOKEN_ESTABLISHED;
                                return;
                            }
                            break;

                        case 'f':
                            if(identifier == "fin")
                            {
                                f_last_token = TOKEN_FIN;
                                return;
                            }
                            break;

                        case 'i':
                            if(identifier == "invalid")
                            {
                                f_last_token = TOKEN_INVALID;
                                return;
                            }
                            break;

                        case 'n':
                            if(identifier == "new")
                            {
                                f_last_token = TOKEN_NEW;
                                return;
                            }
                            else if(identifier == "none")
                            {
                                f_last_token = TOKEN_NONE;
                                return;
                            }
                            break;

                        case 'o':
                            if(identifier == "old")
                            {
                                f_last_token = TOKEN_OLD;
                                return;
                            }
                            break;

                        case 'p':
                            if(identifier == "psh")
                            {
                                f_last_token = TOKEN_PSH;
                                return;
                            }
                            break;

                        case 'r':
                            if(identifier == "related")
                            {
                                f_last_token = TOKEN_RELATED;
                                return;
                            }
                            else if(identifier == "rst")
                            {
                                f_last_token = TOKEN_RST;
                                return;
                            }
                            break;

                        case 's':
                            if(identifier == "syn")
                            {
                                f_last_token = TOKEN_SYN;
                                return;
                            }
                            break;

                        case 't':
                            if(identifier == "timestamp-request")
                            {
                                f_last_token = TOKEN_TIMESTAMP_REQUEST;
                                return;
                            }
                            else if(identifier == "timestamp-reply")
                            {
                                f_last_token = TOKEN_TIMESTAMP_REPLY;
                                return;
                            }
                            else if(identifier == "tcpmss")
                            {
                                f_last_token = TOKEN_TCPMSS;
                                return;
                            }
                            break;

                        case 'u':
                            if(identifier == "urg")
                            {
                                f_last_token = TOKEN_URG;
                                return;
                            }
                            break;

                        }

                        f_valid = false;
                        SNAP_LOG_ERROR
                            << "unknown identifier '"
                            << identifier
                            << "' in list of states."
                            << SNAP_LOG_SEND;
                        f_last_token = TOKEN_EOF;
                        return;
                    }
                }
            }
            snapdev::NOT_REACHED();
            break;

        }
    }
}



// vim: ts=4 sw=4 et
