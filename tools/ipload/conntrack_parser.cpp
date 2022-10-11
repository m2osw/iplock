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
#include    "conntrack_parser.h"


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
#include    <snapdev/not_reached.h>


// C
//
#include    <netdb.h>


// last include
//
#include    <snapdev/poison.h>






// the conntrack feature supports the following in iptables:
//
// [!] --ctstate INVALID | NEW | ESTABLISHED | RELATED | UNTRACKED | SNAT | DNAT
// [!] --ctproto l4proto
// [!] --ctorigsrc address[/mask]
// [!] --ctorigdst address[/mask]
// [!] --ctreplsrc address[/mask]
// [!] --ctrepldst address[/mask]
// [!] --ctorigsrcport port[:port]
// [!] --ctorigdstport port[:port]
// [!] --ctreplsrcport port[:port]
// [!] --ctrepldstport port[:port]
// [!] --ctstatus NONE | EXPECTED | SEEN_REPLY | ASSURED | CONFIRMED
// [!] --ctexpire time[:time]
// --ctdir {ORIGINAL|REPLY}
//
// the following is our syntax instead:
//
//    start: state
//         | status
//         | packet_direction
//         | addresses
//         | ports
//         | expire
//         | l4proto
//         | start start
//    state: "invalid"
//         | "new"
//         | "established"
//         | "related"
//         | "untracked"
//         | "snat"
//         | "dnat"
//    status: "none"
//          | "expected"
//          | "seen_reply"
//          | "assured"
//          | "confirmed"
//    packet_direction: "original"
//                    | "reply"
//    addresses: direction <address>
//             | direction <address> '/' <mask>
//    ports: direction <port>
//         | direction <port> ':' <port>
//    expire: <time>
//          | <time> ':' <time>
//          | '!' <time>
//          | '!' <time> ':' <time>
//    l4proto: "tcp"
//           | "udp"
//           | ... (see the /etc/protocols list)
//    direction: dir
//             | '!' dir
//    dir: '*<'
//       | '*>'
//       | '|<'
//       | '|>'
//
// notes:
//
// - IPv6 addresses must be written between square brackets (i.e. [::1]/64)
// - all keywords can be in lower- or uppercase
// - '!' used on "original" or "reply" swaps the words for "reply"/"orignal"



conntrack_parser::conntrack_parser()
{
    // verify that the tokens and negate values match
    //
    // note: this is done inside the constructor because the tokens are
    //       private to the conntrack_parser class
    //
    static_assert(static_cast<int>(token_t::TOKEN_ORIGINAL_SOURCE)      == static_cast<int>(negate_t::NEGATE_ORIGINAL_SRC_ADDRESS));
    static_assert(static_cast<int>(token_t::TOKEN_ORIGINAL_DESTINATION) == static_cast<int>(negate_t::NEGATE_ORIGINAL_DST_ADDRESS));
    static_assert(static_cast<int>(token_t::TOKEN_REPLY_SOURCE)       == static_cast<int>(negate_t::NEGATE_REPLY_SRC_ADDRESS));
    static_assert(static_cast<int>(token_t::TOKEN_REPLY_DESTINATION)  == static_cast<int>(negate_t::NEGATE_REPLY_DST_ADDRESS));

    static_assert(static_cast<int>(token_t::TOKEN_ORIGINAL_SOURCE) + 4      == static_cast<int>(negate_t::NEGATE_ORIGINAL_SRC_PORTS));
    static_assert(static_cast<int>(token_t::TOKEN_ORIGINAL_DESTINATION) + 4 == static_cast<int>(negate_t::NEGATE_ORIGINAL_DST_PORTS));
    static_assert(static_cast<int>(token_t::TOKEN_REPLY_SOURCE) + 4       == static_cast<int>(negate_t::NEGATE_REPLY_SRC_PORTS));
    static_assert(static_cast<int>(token_t::TOKEN_REPLY_DESTINATION) + 4  == static_cast<int>(negate_t::NEGATE_REPLY_DST_PORTS));
}


bool conntrack_parser::parse(std::string const & expression)
{
    f_expression = expression;
    f_in = f_expression.c_str();

    next_token();
    for(;;)
    {
        switch(f_last_token)
        {
        case token_t::TOKEN_EOF:
            return f_valid;

        case token_t::TOKEN_NEGATE:
            next_token();
            switch(f_last_token)
            {
            case token_t::TOKEN_OPEN_PARENTHESIS:
                // parenthesis allow a set of items to all be negated
                //
                next_token();
                for(;;)
                {
                    if(f_last_token == token_t::TOKEN_CLOSE_PARENTHESIS)
                    {
                        next_token();
                        break;
                    }
                    switch(f_last_token)
                    {
                    case token_t::TOKEN_EOF:
                        SNAP_LOG_ERROR
                            << "end of conntrack expression with a still opened parenthesis."
                            << SNAP_LOG_SEND;
                        f_valid = false;
                        return false;

                    case token_t::TOKEN_ORIGINAL_SOURCE:
                    case token_t::TOKEN_ORIGINAL_DESTINATION:
                    case token_t::TOKEN_REPLY_SOURCE:
                    case token_t::TOKEN_REPLY_DESTINATION:
                        parse_address_port(true);
                        break;

                    case token_t::TOKEN_INTEGER:
                        parse_time(true);
                        break;

                    case token_t::TOKEN_IDENTIFIER:
                        parse_state_status_protocol(true);
                        break;

                    default:
                        SNAP_LOG_ERROR
                            << "unexpected token within a group '!(...)' operator"
                            << SNAP_LOG_SEND;
                        f_valid = false;
                        break;

                    }
                }
                break;

            case token_t::TOKEN_ORIGINAL_SOURCE:
            case token_t::TOKEN_ORIGINAL_DESTINATION:
            case token_t::TOKEN_REPLY_SOURCE:
            case token_t::TOKEN_REPLY_DESTINATION:
                parse_address_port(true);
                break;

            case token_t::TOKEN_INTEGER:
                parse_time(true);
                break;

            case token_t::TOKEN_IDENTIFIER:
                parse_state_status_protocol(true);
                break;

            default:
                SNAP_LOG_ERROR
                    << "unexpected token after a '!' operator"
                    << SNAP_LOG_SEND;
                f_valid = false;
                break;

            }
            break;

        case token_t::TOKEN_ORIGINAL_SOURCE:
        case token_t::TOKEN_ORIGINAL_DESTINATION:
        case token_t::TOKEN_REPLY_SOURCE:
        case token_t::TOKEN_REPLY_DESTINATION:
            parse_address_port(false);
            break;

        case token_t::TOKEN_INTEGER:
            parse_time(false);
            break;

        case token_t::TOKEN_IDENTIFIER:
            parse_state_status_protocol(false);
            break;

        default:
            SNAP_LOG_ERROR
                << "conntrack parsing issue; got token "
                << static_cast<int>(f_last_token)
                << "; start just before \""
                << f_in
                << "\"."
                << SNAP_LOG_SEND;
            f_valid = false;
            next_token();
            break;

        }
    }
    snapdev::NOT_REACHED();
}


void conntrack_parser::parse_address_port(bool negate)
{
    int const index(static_cast<int>(f_last_token));

    next_token();

    switch(f_last_token)
    {
    case token_t::TOKEN_INTEGER:
        f_negate[index + 4] = negate;
        f_start_port[index] = f_integer;
        next_token();
        if(f_last_token == token_t::TOKEN_COLON)
        {
            next_token();
            if(f_last_token == token_t::TOKEN_INTEGER)
            {
                f_end_port[index] = f_integer;

                next_token();
            }
            else
            {
                SNAP_LOG_ERROR
                    << "port range must end with an integer."
                    << SNAP_LOG_SEND;
                f_valid = false;
            }
        }
        return;

    case token_t::TOKEN_ADDRESS:
    case token_t::TOKEN_IDENTIFIER:
        break;

    default:
        SNAP_LOG_ERROR
            << "direction (*<, *>, |<, or |>) must be followed by a port number of an address."
            << SNAP_LOG_SEND;
        f_valid = false;
        return;

    }

    addr::addr_parser p;
    p.set_protocol(IPPROTO_TCP);    // otherwise we get "many" addresses...
    p.set_allow(addr::allow_t::ALLOW_REQUIRED_ADDRESS, true);
    p.set_allow(addr::allow_t::ALLOW_MASK, true);
    addr::addr_range::vector_t addresses(p.parse(f_value));
    if(p.has_errors())
    {
        SNAP_LOG_ERROR
            << "address \""
            << f_value
            << "\" could not be parsed."
            << SNAP_LOG_SEND;
        f_valid = false;
        next_token();
        return;
    }
    if(addresses.size() != 1)
    {
        // note: this should not happen since we prevent multiple addresses
        //
        SNAP_LOG_ERROR
            << "address \""
            << f_value
            << "\" represents more than one address, which is not supported."
            << SNAP_LOG_SEND;
        f_valid = false;
        next_token();
        return;
    }
    addr::addr_range const & range(addresses[0]);
    if(!range.has_from()
    || range.has_to())
    {
        // note: this should not happen since we prevent ranges
        //
        SNAP_LOG_ERROR
            << "address \""
            << f_value
            << "\" represents an address range, which is not supported."
            << SNAP_LOG_SEND;
        f_valid = false;
        next_token();
        return;
    }
    addr::addr a(range.get_from());

    if(a.get_port_defined())
    {
        // we have a port included in the address, move it to the port
        // definition (no "end" port in this case--once libaddr supports
        // port ranges, we may want to update this here)
        //
        f_negate[index + 4] = negate;
        f_start_port[index] = a.get_port();
        a.set_port_defined(false);
    }

    f_negate[index] = negate;
    f_address[index] = a;

    next_token();
}


void conntrack_parser::parse_time(bool negate)
{
    if(f_expire_start_time >= 0
    || f_expire_end_time >= 0)
    {
        SNAP_LOG_ERROR
            << "conntrack only supports one expire time definition."
            << SNAP_LOG_SEND;
        next_token();
        return;
    }

    f_negate[static_cast<int>(negate_t::NEGATE_EXPIRE)] = negate;
    f_expire_start_time = f_integer;

    next_token();

    if(f_last_token == token_t::TOKEN_COLON)
    {
        // TTL range
        //
        next_token();
        if(f_last_token != token_t::TOKEN_INTEGER)
        {
            SNAP_LOG_ERROR
                << "expiration range of conntrack is expected to end with an integer."
                << SNAP_LOG_SEND;
        }
        else
        {
            f_expire_end_time = f_integer;

            next_token();
        }
    }
}


void conntrack_parser::parse_state_status_protocol(bool negate)
{
    bool state(false);
    bool status(false);
    switch(f_value[0])
    {
    case 'a':
        if(f_value == "assured")
        {
            status = true;
        }
        break;

    case 'b':
        if(f_value == "both-directions")
        {
            if(negate)
            {
                SNAP_LOG_ERROR
                    << "the \"both-direction\" flag cannot be negated."
                    << SNAP_LOG_SEND;
            }
            f_direction = direction_t::DIRECTION_BOTH;
            next_token();
            return;
        }
        break;

    case 'c':
        if(f_value == "confirm")
        {
            status = true;
        }
        break;

    case 'd':
        if(f_value == "dnat")
        {
            state = true;
        }
        break;

    case 'e':
        if(f_value == "established")
        {
            state = true;
        }
        else if(f_value == "expected")
        {
            status = true;
        }
        break;

    case 'i':
        if(f_value == "invalid")
        {
            state = true;
        }
        break;

    case 'n':
        if(f_value == "new")
        {
            state = true;
        }
        else if(f_value == "none")
        {
            status = true;
        }
        break;

    case 'o':
        if(f_value == "original")
        {
            if(negate)
            {
                f_direction = direction_t::DIRECTION_REPLY;
            }
            else
            {
                f_direction = direction_t::DIRECTION_ORIGINAL;
            }
            next_token();
            return;
        }
        break;

    case 'r':
        if(f_value == "related")
        {
            state = true;
        }
        else if(f_value == "reply")
        {
            if(negate)
            {
                f_direction = direction_t::DIRECTION_ORIGINAL;
            }
            else
            {
                f_direction = direction_t::DIRECTION_REPLY;
            }
            next_token();
            return;
        }
        break;

    case 's':
        if(f_value == "snat")
        {
            state = true;
        }
        else if(f_value == "seen_reply")
        {
            status = true;
        }
        break;

    case 'u':
        if(f_value == "untracked")
        {
            state = true;
        }
        break;

    }

    if(state)
    {
        if(f_states.empty())
        {
            f_negate[static_cast<int>(negate_t::NEGATE_STATES)] = negate;
        }
        else if(f_negate[static_cast<int>(negate_t::NEGATE_STATES)] != negate)
        {
            SNAP_LOG_ERROR
                << "all conntrack states must not be negated (no !) or all must be negated (use ! for each one)."
                << SNAP_LOG_SEND;
            f_valid = false;
        }
        auto it(f_states.insert(f_value));
        if(!it.second)
        {
            SNAP_LOG_WARNING
                << "conntrack state \""
                << f_value
                << "\" defined twice."
                << SNAP_LOG_SEND;
        }
    }
    else if(status)
    {
        f_negate[static_cast<int>(negate_t::NEGATE_STATUSES)] = negate;
        auto it(f_statuses.insert(f_value));
        if(!it.second)
        {
            SNAP_LOG_WARNING
                << "conntrack status \""
                << f_value
                << "\" defined twice."
                << SNAP_LOG_SEND;
        }
    }
    else
    {
        // maybe a protocol?
        //
        auto const p(getprotobyname(f_value.c_str()));
        if(p == nullptr)
        {
            SNAP_LOG_ERROR
                << "conntrack identifier \""
                << f_value
                << "\" not recognized as a state, a status, or a protocol."
                << SNAP_LOG_SEND;
            f_valid = false;
        }
        else
        {
            f_negate[static_cast<int>(negate_t::NEGATE_PROTOCOL)] = negate;
            f_protocol = p->p_proto;
        }
    }

    next_token();
}


int conntrack_parser::getc()
{
    int result(EOF);
    if(f_unget != '\0')
    {
        result = f_unget;
        f_unget = '\0';
    }
    else if(*f_in != '\0')
    {
        result = *f_in;
        ++f_in;
    }

    return result;
}


void conntrack_parser::ungetc(int c)
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


void conntrack_parser::next_token()
{
    f_value.clear();
    f_integer = 0;
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

        case '!':
            f_last_token = token_t::TOKEN_NEGATE;
            return;

        case '(':
            f_last_token = token_t::TOKEN_OPEN_PARENTHESIS;
            return;

        case ')':
            f_last_token = token_t::TOKEN_CLOSE_PARENTHESIS;
            return;

        case ':':
            f_last_token = token_t::TOKEN_COLON;
            return;

        case '/':
            f_last_token = token_t::TOKEN_SLASH;
            return;

        case '*':
            c = getc();
            if(c == '<')
            {
                f_last_token = token_t::TOKEN_ORIGINAL_SOURCE;
                return;
            }
            else if(c == '>')
            {
                f_last_token = token_t::TOKEN_ORIGINAL_DESTINATION;
                return;
            }
            ungetc(c);
            break;

        case '|':
            c = getc();
            if(c == '<')
            {
                f_last_token = token_t::TOKEN_REPLY_SOURCE;
                return;
            }
            else if(c == '>')
            {
                f_last_token = token_t::TOKEN_REPLY_DESTINATION;
                return;
            }
            ungetc(c);
            break;

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
            do
            {
                f_value += c;
                f_integer = f_integer * 10 + c - '0';
                c = getc();
            }
            while(c >= '0' && c <= '9');
            if(c == '.')
            {
                goto parse_as_identifier;
            }
            ungetc(c);
            f_last_token = token_t::TOKEN_INTEGER;
            return;

        default:
parse_as_identifier:
            f_last_token = token_t::TOKEN_IDENTIFIER;
            while((c >= 'a' && c <= 'z')
               || (c >= 'A' && c <= 'Z')
               || (c >= '0' && c <= '9') // we know the first character won't be a digit
               || c == '_'
               || c == '-'
               || c == '.'      // for IPv4
               || c == ':'      // for IPv6 (the ':' is "overloaded", make sure to write IPv6 addresses inside square brackets -- TODO: make it work without the square brackets)
               || c == '/'      // mask comes within the identifier
               || c == '['
               || c == ']')
            {
                if(c >= 'A' && c <= 'Z')
                {
                    f_value = c | 0x20; // lowercase
                }
                else
                {
                    switch(c)
                    {
                    case '.':
                    case ':':
                    case '[':
                    case ']':
                        f_last_token = token_t::TOKEN_ADDRESS;
                        break;

                    case '-':
                        c = '_';
                        break;

                    }

                    f_value += c;
                }
                c = getc();
            }
            ungetc(c);
            return;

        }
        SNAP_LOG_ERROR
            << "found invalid character in the conntrack input string '"
            << c
            << "'."
            << SNAP_LOG_SEND;
        f_value = false;
    }
}


bool conntrack_parser::get_negate(negate_t idx) const
{
    return f_negate[static_cast<int>(idx)];
}


advgetopt::string_set_t const & conntrack_parser::get_states() const
{
    return f_states;
}


advgetopt::string_set_t const & conntrack_parser::get_statuses() const
{
    return f_statuses;
}


int conntrack_parser::get_protocol() const
{
    return f_protocol;
}


addr::addr const & conntrack_parser::get_address(int index) const
{
    return f_address[index];
}


int conntrack_parser::get_start_port(int index) const
{
    return f_start_port[index];
}


int conntrack_parser::get_end_port(int index) const
{
    return f_end_port[index];
}


std::int64_t conntrack_parser::get_expire_start_time() const
{
    return f_expire_start_time;
}


std::int64_t conntrack_parser::get_expire_end_time() const
{
    return f_expire_end_time;
}


direction_t conntrack_parser::get_direction() const
{
    return f_direction;
}



// vim: ts=4 sw=4 et
