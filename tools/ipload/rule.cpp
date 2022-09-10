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

#include    "state_parser.h"
#include    "utils.h"


// iplock
//
#include    <iplock/exception.h>


// libaddr
//
#include    <libaddr/addr_parser.h>


// advgetopt
//
#include    <advgetopt/validator_integer.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
#include    <snapdev/join_strings.h>
#include    <snapdev/not_reached.h>
#include    <snapdev/remove_duplicates.h>
#include    <snapdev/string_replace_many.h>


// C
//
#include    <string.h>


// last include
//
#include    <snapdev/poison.h>



namespace
{



std::string address_with_mask(addr::addr const & a)
{
    std::string ip(a.to_ipv4or6_string(addr::string_ip_t::STRING_IP_ONLY));
    int mask_size(a.get_mask_size());
    if(mask_size >= 0
    && mask_size != 128)
    {
        if(a.is_ipv4())
        {
            mask_size -= 96;
        }
        ip += '/';
        ip += std::to_string(mask_size);
    }
    return ip;
}



}


rule::line_builder::line_builder(std::string const & chain_name)
    : f_generating_for_chain_name(chain_name)
{
    if(f_generating_for_chain_name.empty())
    {
        throw iplock::logic_error("chain name cannot be an empty string in rule::line_builder");
    }
}


//rule::line_builder::line_builder(line_builder const & rhs)
//{
//    *this = rhs;
//}


std::string rule::line_builder::get_add_chain() const
{
    return "-A " + f_generating_for_chain_name;
}


bool rule::line_builder::is_chain_name(char const * chain_name) const
{
    return f_generating_for_chain_name == chain_name;
}


void rule::line_builder::set_protocol(std::string const & protocol)
{
    if(!f_generating_for_protocol.empty())
    {
        throw iplock::logic_error("the protocol is already set in this line_builder object; it can't be replaced.");
    }

    // "ipv6-icmp" gets transformed to "icmpv6" early on,
    // so it should not occur here, but just in case...
    //
    if(protocol == "icmpv6"
    || protocol == "ipv6-icmp")
    {
        set_ipv6();
        f_generating_for_protocol = "icmpv6";
    }
    else
    {
        f_generating_for_protocol = protocol;
    }
}


std::string const & rule::line_builder::get_protocol() const
{
    return f_generating_for_protocol;
}


void rule::line_builder::set_ipv4()
{
    if(f_ipv6)
    {
        throw iplock::logic_error("set_ipv4() called on a line which is already set as an IPv6 specific line.");
    }
    f_ipv4 = true;
}


bool rule::line_builder::is_ipv4() const
{
    return f_ipv4;
}


void rule::line_builder::set_ipv6()
{
    if(f_ipv4)
    {
        throw iplock::logic_error("set_ipv6() called on a line which is already set as an IPv4 specific line.");
    }
    f_ipv6 = true;
}


bool rule::line_builder::is_ipv6() const
{
    return f_ipv6;
}


void rule::line_builder::append_ipv4line(std::string const & s, bool set)
{
    if(set)
    {
        set_ipv4();
    }
    if(!f_ipv6)
    {
        f_ipv4line += s;
    }
}


void rule::line_builder::append_ipv6line(std::string const & s, bool set)
{
    if(set)
    {
        set_ipv6();
    }
    if(!f_ipv4)
    {
        f_ipv6line += s;
    }
}


void rule::line_builder::append_both(std::string const & s)
{
    append_ipv4line(s);
    append_ipv6line(s);
}


std::string const & rule::line_builder::get_ipv4line() const
{
    return f_ipv4line;
}


std::string const & rule::line_builder::get_ipv6line() const
{
    return f_ipv6line;
}









void rule::result_builder::append_line(line_builder const & line)
{
    // if the rule is not specific to IPv4 or IPv6, apply it to both
    //
    bool is_ipv4(line.is_ipv4());
    bool is_ipv6(line.is_ipv6());
    if(!is_ipv4 && !is_ipv6)
    {
        is_ipv4 = true;
        is_ipv6 = true;
    }

    std::string const & chain(line.get_add_chain());
std::cerr << "ADD CHAIN = [" << chain << "]\n";
    f_result += chain;

    if(is_ipv4
    && is_ipv6
    && line.get_ipv4line() == line.get_ipv6line())
    {
        // no need for the --ipv4 or --ipv6
        //
        f_result += line.get_ipv4line();
    }
    else
    {
        // either we only have an IPv4 or an IPv6 rule or there are some
        // differences in the rule and thus we have to distinguish both
        //
        if(is_ipv4)
        {
            f_result += " --ipv4" + line.get_ipv4line();
        }
        if(is_ipv6)
        {
            f_result += " --ipv6" + line.get_ipv6line();
        }
    }
}


std::string const & rule::result_builder::get_result() const
{
    return f_result;
}











rule::rule(
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
        throw iplock::logic_error("the rule name \"" + it->first + "\" is expected to be exactly three names: \"rule::<name>::<parameter>\".");
    }

    // this is the name of the rule
    //
    // it is used by the ipload tool to sort the rules between each others
    // using the list of names in the before & after parameters
    //
    f_name = advgetopt::option_with_underscores(name_list[1]);

    std::string const complete_namespace("rule::" + name_list[1] + "::");
    advgetopt::string_list_t sources;
    advgetopt::string_list_t except_sources;
    advgetopt::string_list_t destinations;
    advgetopt::string_list_t except_destinations;
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
        case 'a':
            if(param_name == "action")
            {
                parse_action(value);
            }
            else if(param_name == "after")
            {
                advgetopt::split_string(value, f_after, {","});
                list_to_lower(f_after);
                snapdev::remove_duplicates(f_after);
                if(std::binary_search(f_after.begin(), f_after.end(), f_name))
                {
                    SNAP_LOG_ERROR
                        << "a rule cannot depend on itself (found \""
                        << f_name
                        << "\" in its \"before=...\" parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
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
                snapdev::remove_duplicates(f_before);
                if(std::binary_search(f_before.begin(), f_before.end(), f_name))
                {
                    SNAP_LOG_ERROR
                        << "a rule cannot depend on itself (found \""
                        << f_name
                        << "\" in its \"before=...\" parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
            }
            else
            {
                found = false;
            }
            break;

        case 'c':
            if(param_name == "chain"
            || param_name == "chains")
            {
                advgetopt::split_string(value, f_chains, {","});
            }
            else if(param_name == "condition"
                 || param_name == "conditions")
            {
                f_condition = parse_expression(value);
            }
            else
            {
                found = false;
            }
            break;

        case 'd':
            if(param_name == "destination-interface"
            || param_name == "destination-interfaces")
            {
                advgetopt::split_string(value, f_destination_interfaces, {","});
                list_to_lower(f_destination_interfaces);
            }
            else if(param_name == "destination"
                 || param_name == "destinations")
            {
                advgetopt::split_string(value, destinations, {","});
            }
            else if(param_name == "destination-port"
                 || param_name == "destination-ports")
            {
                advgetopt::split_string(value, f_destination_ports, {","});
            }
            else if(param_name == "description")
            {
                f_description = value;
            }
            else
            {
                found = false;
            }
            break;

        case 'e':
            if(param_name == "except-destination"
            || param_name == "except-destinations")
            {
                advgetopt::split_string(value, except_destinations, {","});
            }
            else if(param_name == "except-source"
                 || param_name == "except-sources")
            {
                advgetopt::split_string(value, except_sources, {","});
            }
            else
            {
                found = false;
            }
            break;

        case 'i':
            if(param_name == "interface"
            || param_name == "interfaces")
            {
                advgetopt::split_string(value, f_interfaces, {","});
                list_to_lower(f_interfaces);
            }
            else
            {
                found = false;
            }
            break;

        case 'l':
            if(param_name == "limit"
            || param_name == "limits")
            {
                advgetopt::split_string(value, f_limits, {","});
                if(f_limits.size() > 2)
                {
                    SNAP_LOG_ERROR
                        << "a rule limit must be 0, 1, or 2 numbers."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
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
            if(param_name == "protocol"
            || param_name == "protocols")
            {
                advgetopt::split_string(value, f_protocols, {","});
                for(auto & p : f_protocols)
                {
                    if(p == "ipv6-icmp")
                    {
                        p = "icmpv6";
                    }
                }
            }
            else
            {
                found = false;
            }
            break;

        case 's':
            if(param_name == "set")
            {
                advgetopt::split_string(value, f_set, {","});
            }
            else if(param_name == "section")
            {
                f_section = value;
            }
            else if(param_name == "source-interface"
                 || param_name == "source-interfaces")
            {
                advgetopt::split_string(value, f_source_interfaces, {","});
                list_to_lower(f_source_interfaces);
            }
            else if(param_name == "source"
                 || param_name == "sources")
            {
                advgetopt::split_string(value, sources, {","});
            }
            else if(param_name == "source-port"
                 || param_name == "source-ports")
            {
                advgetopt::split_string(value, f_source_ports, {","});
            }
            else if(param_name == "state"
                 || param_name == "states")
            {
                state_parser state(value.c_str());
                if(state.parse())
                {
                    f_states = state.get_results();
                }
                else
                {
                    SNAP_LOG_RECOVERABLE_ERROR
                        << "invalid states in \""
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
                << "unknown rule parameter \""
                << it->first
                << "\"."
                << SNAP_LOG_SEND;
        }
    }

    if(f_action == action_t::ACTION_UNDEFINED)
    {
        SNAP_LOG_ERROR
            << "a rule action must be defined."
            << SNAP_LOG_SEND;
        f_valid = false;
    }

    if(!f_except_sources.empty()
    && !sources.empty())
    {
        SNAP_LOG_ERROR
            << "rule \""
            << f_name
            << "\" cannot have \"sources\" and \"except_sources\" at the same time."
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
            << "rule \""
            << f_name
            << "\" cannot before and after the same rule(s): "
            << snapdev::join_strings(common, ", ")
            << "."
            << SNAP_LOG_SEND;
        f_valid = false;
    }

    if((!f_source_interfaces.empty() || !f_destination_interfaces.empty())
    && !f_interfaces.empty())
    {
        SNAP_LOG_ERROR
            << "rule \""
            << f_name
            << "\" cannot use 'source_interfaces' and 'destination_interfaces' along with 'interfaces'."
            << SNAP_LOG_SEND;
        f_valid = false;
    }

    parse_addresses(
          sources
        , f_sources
        , f_source_ranges);

    parse_addresses(
          destinations
        , f_destinations
        , f_destination_ranges);

    parse_addresses(
          except_sources
        , f_except_sources
        , f_except_source_ranges);

    parse_addresses(
          except_destinations
        , f_except_destinations
        , f_except_destination_ranges);
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
            else if(a == "dnat")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"DNAT\" action requires the destination parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_DNAT;
                    f_action_param = action_param[1];
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

        case 'm':
            if(a == "masquerade")
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"MASQUERADE\" action does not support a parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_MASQUERADE;
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
            else if(a == "redirect")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"REDIRECT\" action requires a port parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_REDIRECT;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "return")
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"RETURN\" action does not support a parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_RETURN;
                }
                return;
            }
            break;

        case 's':
            if(a == "snat")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"SNAT\" action requires the source parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_SNAT;
                    f_action_param = action_param[1];
                }
                return;
            }
        }
    }

    SNAP_LOG_ERROR
        << "unknown action \""
        << action
        << "\"."
        << SNAP_LOG_SEND;
    f_valid = false;
}


bool rule::parse_expression(std::string const & expression)
{
    if(expression.empty())
    {
        return true;
    }

    char const * s(expression.c_str());
    char quote(s[0]);
    if(quote != '"'
    && quote != '\'')
    {
        SNAP_LOG_ERROR
            << "expression ["
            << expression
            << "] does not start with a valid quote (\" or ')."
            << SNAP_LOG_SEND;
        f_valid = false;
        return true;
    }

    ++s;
    char const *first_start(s);
    for(; *s != quote; ++s)
    {
        if(*s == '\0')
        {
            SNAP_LOG_ERROR
                << "expression ["
                << expression
                << "] closing quote is missing."
                << SNAP_LOG_SEND;
            f_valid = false;
            return true;
        }
    }
    char const *first_end(s);

    ++s;    // skip quote

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
        f_valid = false;
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
        f_valid = false;
        return true;
    }
    ++s;   // skip second '='

    while(isspace(*s))
    {
        ++s;
    }

    quote = s[0];
    if(quote != '"'
    && quote != '\'')
    {
        SNAP_LOG_ERROR
            << "second string in ["
            << expression
            << "] does not start with a valid quote (\" or ')."
            << SNAP_LOG_SEND;
        f_valid = false;
        return true;
    }

    ++s;
    char const * second_start(s);
    for(; *s != quote; ++s)
    {
        if(*s == '\0')
        {
            SNAP_LOG_ERROR
                << "second string in ["
                << expression
                << "] closing quote is missing."
                << SNAP_LOG_SEND;
            f_valid = false;
            return true;
        }
    }
    char const * second_end(s);

    ++s;    // skip quote

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
            f_valid = false;
            return true;
    }

    return (std::string_view(first_start, first_end - first_start)
        == std::string_view(second_start, second_end - second_start)) == equal;
}


void rule::parse_addresses(
      advgetopt::string_list_t const & in
    , addr::addr::vector_t & out_addresses
    , addr::addr_range::vector_t & out_ranges)
{
    // we already have the addresses separated by commas in separate strings
    // so we will not allow multi-addresses in the libaddr parser
    //
    // here we allow the beginning of the address to include a protocol like
    // in a URI (i.e. "tcp://" or "udp://"); note that we won't properly
    // support protocols such as HTTP because that is not compatible with
    // iptables (although we could make them work too)
    //
    advgetopt::string_list_t const input(std::move(in));
    for(auto const & in_addr : input)
    {
        std::string ip(in_addr);
        std::string protocol;
        std::string::size_type const pos(ip.find("://"));
        if(pos != std::string::npos)
        {
            protocol = ip.substr(0, pos);
            if(protocol.empty())
            {
                SNAP_LOG_ERROR
                    << "protocol in address \""
                    << in_addr
                    << "\" cannot be empty."
                    << SNAP_LOG_SEND;
                f_valid = false;
                return;
            }
            ip = ip.substr(pos + 3);
            if(ip.empty())
            {
                SNAP_LOG_ERROR
                    << "address in \""
                    << in_addr
                    << "\" cannot be empty."
                    << SNAP_LOG_SEND;
                f_valid = false;
                return;
            }
        }
        addr::addr_parser parser;
        if(!protocol.empty())
        {
            parser.set_protocol(protocol);
        }
        else
        {
            // most IPs in a firewall are TCP or UDP, although this just
            // means we're reading an IP address
            //
            parser.set_protocol(IPPROTO_TCP);
            parser.set_allow(addr::allow_t::ALLOW_ADDRESS_RANGE, true);
        }
        parser.set_allow(addr::allow_t::ALLOW_MASK, true);

        // TODO: look into adding support for port lists or ranges
        //       (not yet implemented in the libaddr)

        addr::addr_range::vector_t ranges(parser.parse(ip));
        for(auto const & r : ranges)
        {
            if(protocol.empty()
            && r.has_from()
            && !r.has_to()
            && !r.get_from().get_port_defined())
            {
                // these addresses get mixed with the f_protocols and f_ports
                //
                out_addresses.push_back(r.get_from());
            }
            else
            {
                out_ranges.push_back(r);
            }
        }
    }
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


void rule::add_after(std::string const & after)
{
    // avoid duplicates
    //
    if(std::find(f_after.begin(), f_after.end(), after) == f_after.end())
    {
        f_after.push_back(after);
    }
}


bool rule::get_condition() const
{
    return f_condition;
}


advgetopt::string_list_t const & rule::get_set() const
{
    return f_set;
}


advgetopt::string_list_t const & rule::get_source_interfaces() const
{
    return f_source_interfaces;
}


//addr::addr::vector_t const & rule::get_sources() const
//{
//    return f_sources;
//}


//addr::addr::vector_t const & rule::get_except_sources() const
//{
//    return f_except_sources;
//}


advgetopt::string_list_t const & rule::get_source_ports() const
{
    return f_source_ports;
}


advgetopt::string_list_t const & rule::get_destination_interfaces() const
{
    return f_destination_interfaces;
}


//addr::addr::vector_t const & rule::get_destinations() const
//{
//    return f_destinations;
//}


//addr::addr::vector_t const & rule::get_except_destinations() const
//{
//    return f_except_destinations;
//}


advgetopt::string_list_t const & rule::get_destination_ports() const
{
    return f_destination_ports;
}


advgetopt::string_list_t const & rule::get_protocols() const
{
    return f_protocols;
}


state_result::vector_t const & rule::get_states() const
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


std::string rule::get_action_name() const
{
    switch(f_action)
    {
    case action_t::ACTION_UNDEFINED:
        throw iplock::logic_error("action still undefined");

    case action_t::ACTION_ACCEPT:
        return "ACCEPT";

    case action_t::ACTION_CALL:
        return std::string();

    case action_t::ACTION_DNAT:
        return "DNAT";

    case action_t::ACTION_DROP:
        return "DROP";

    case action_t::ACTION_LOG:
        return "LOG";

    case action_t::ACTION_MASQUERADE:
        return "MASQUERADE";

    case action_t::ACTION_REDIRECT:
        return "REDIRECT";

    case action_t::ACTION_REJECT:
        return "REJECT";

    case action_t::ACTION_RETURN:
        return "RETURN";

    case action_t::ACTION_SNAT:
        return "SNAT";

    }

    snapdev::NOT_REACHED();
}


std::string const & rule::get_log() const
{
    return f_log;
}


void rule::set_log_introducer(std::string const & introducer)
{
    f_log_introducer = introducer;
}


void rule::add_dependency(pointer_t r)
{
    f_dependencies.push_back(r);
}


rule::vector_t const & rule::get_dependencies() const
{
    return f_dependencies;
}


int rule::get_level() const
{
    return f_level;
}


void rule::set_level(int level)
{
    f_level = level;
}


/** \brief Generate the iptables rules.
 *
 * This function recursively goes through all the data found in this rule
 * and generate the corresponding code for the iptables-restore and
 * ip6tables-restore commands.
 *
 * \todo
 * If the chain does not allow source interfaces, do not generate the "-i".
 * If the chain does not allow source interfaces, do not generate the "-o".
 *
 * \param[in] chain_name  The name of the chain for which this rule is being
 * generated.
 *
 * \return The iptables rules as a script for iptables-restore.
 */
std::string rule::to_iptables_rules(std::string const & chain_name)
{
    result_builder result;
    line_builder line(chain_name);

    if(f_source_interfaces.empty())
    {
        to_iptables_destination_interfaces(result, line);
    }
    else
    {
        for(auto const & s : f_source_interfaces)
        {
            line_builder sub_line(line);
            sub_line.append_both(" -i " + s);
            to_iptables_destination_interfaces(result, sub_line);
        }
    }

    return result.get_result();
}


void rule::to_iptables_destination_interfaces(result_builder & result, line_builder const & line)
{
    if(f_destination_interfaces.empty())
    {
        to_iptables_interfaces(result, line);
    }
    else
    {
        for(auto const & s : f_destination_interfaces)
        {
            line_builder sub_line(line);
            sub_line.append_both(" -o " + s);
            to_iptables_interfaces(result, sub_line);
        }
    }
}


void rule::to_iptables_interfaces(result_builder & result, line_builder const & line)
{
    if(f_interfaces.empty())
    {
        to_iptables_protocols(result, line);
    }
    else
    {
        // in this case, we may use -i, -o, or both depending on the table
        //
        // for user defined tables, we use both even if not allowed; it is
        // up to the user to fix the issue if it should only be a source or
        // a destination
        //
        constexpr int IN_OUT_IN  = 0x01;
        constexpr int IN_OUT_OUT = 0x02;
        int in_out(0);
        if(line.is_chain_name("OUTPUT"))
        {
            in_out = IN_OUT_OUT;
        }
        else if(line.is_chain_name("FORWARD"))
        {
            in_out = IN_OUT_IN | IN_OUT_OUT;
        }
        switch(in_out)
        {
        case IN_OUT_IN:
        case 0:     // for all others, the input is the default
            for(auto const & s : f_interfaces)
            {
                line_builder sub_line(line);
                sub_line.append_both(" -i " + s);
                to_iptables_protocols(result, sub_line);
            }
            break;

        case IN_OUT_OUT:
            for(auto const & s : f_interfaces)
            {
                line_builder sub_line(line);
                sub_line.append_both(" -o " + s);
                to_iptables_protocols(result, sub_line);
            }
            break;

        case IN_OUT_IN | IN_OUT_OUT:
            for(auto const & s : f_interfaces)
            {
                line_builder sub_line(line);
                sub_line.append_both(" -i " + s + " -o " + s);
                to_iptables_protocols(result, sub_line);
            }
            break;

        }
    }
}


void rule::to_iptables_protocols(result_builder & result, line_builder const & line)
{
    if(f_protocols.empty())
    {
        if(!f_source_ports.empty()
        || !f_destination_ports.empty())
        {
            SNAP_LOG_ERROR
                << "usage of one or more ports requires rule \""
                << f_name
                << "\" to include a valid protocol."
                << SNAP_LOG_SEND;
            f_valid = false;
        }

        to_iptables_sources(result, line);
    }
    else
    {
        bool is_established_related(false);
        for(auto const & s : f_states)
        {
            if(s.is_valid()
            && s.get_established_related())
            {
                is_established_related = true;
                break;
            }
        }
        for(auto const & s : f_protocols)
        {
            if(s != "icmpv6")
            {
                line_builder sub_line(line);

                sub_line.set_protocol(s);

                sub_line.append_both(" -p " + s);
                if(is_established_related)
                {
                    sub_line.append_both(" -m state --state ESTABLISHED,RELATED");
                }
                if(f_source_ports.size() > 1
                || f_destination_ports.size() > 1)
                {
                    sub_line.append_both(" -m multiport");
                }
                sub_line.append_both(" -m " + s);
                to_iptables_sources(result, sub_line);
            }

            if(s == "icmp"
            || s == "icmpv6")
            {
                line_builder sub_line(line);

                sub_line.set_protocol("icmpv6"); // this forces IPv6

                sub_line.append_ipv6line(" -p icmpv6");
                if(is_established_related)
                {
                    sub_line.append_ipv6line(" -m state --state ESTABLISHED,RELATED");
                }
                if(f_source_ports.size() > 1
                || f_destination_ports.size() > 1)
                {
                    sub_line.append_ipv6line(" -m multiport");
                }
                sub_line.append_ipv6line(" -m icmpv6");
                to_iptables_sources(result, sub_line);
            }
        }
    }
}


void rule::to_iptables_sources(result_builder & result, line_builder const & line)
{
    if(f_sources.empty())
    {
        if(f_except_sources.empty())
        {
            if(!f_source_ranges.empty()
            || !f_except_source_ranges.empty())
            {
                // this rule uses ranges, this is not a case of an empty
                // sources input so here we just return
                //
                return;
            }

            to_iptables_source_ports(result, line);
        }
        else
        {
            for(auto const & s : f_except_sources)
            {
                if(s.is_ipv4())
                {
                    if(!line.is_ipv6())
                    {
                        line_builder sub_line(line);
                        std::string const ip(address_with_mask(s));
                        sub_line.append_ipv4line(" ! -s " + ip, true);
                        to_iptables_source_ports(result, sub_line);
                    }
                }
                else
                {
                    if(!line.is_ipv4())
                    {
                        line_builder sub_line(line);
                        std::string const ip(address_with_mask(s));
                        sub_line.append_ipv6line(" ! -s " + ip, true);
                        to_iptables_source_ports(result, sub_line);
                    }
                }
            }
        }
    }
    else
    {
        for(auto const & s : f_sources)
        {
            if(s.is_default())
            {
                // the default IP applies to both: IPv4 and IPv6
                //
                if(!line.is_ipv6())
                {
                    line_builder sub_line(line);
                    sub_line.append_ipv4line(" -s 0.0.0.0", true);
                    to_iptables_source_ports(result, sub_line);
                }
                if(!line.is_ipv4())
                {
                    line_builder sub_line(line);
                    sub_line.append_ipv6line(" -s ::", true);
                    to_iptables_source_ports(result, sub_line);
                }
            }
            else if(s.is_ipv4())
            {
                if(!line.is_ipv6())
                {
                    line_builder sub_line(line);
                    std::string const ip(address_with_mask(s));
                    sub_line.append_ipv4line(" -s " + ip, true);
                    to_iptables_source_ports(result, sub_line);
                }
            }
            else
            {
                if(!line.is_ipv4())
                {
                    line_builder sub_line(line);
                    std::string const ip(address_with_mask(s));
                    sub_line.append_ipv6line(" -s " + ip, true);
                    to_iptables_source_ports(result, sub_line);
                }
            }
        }
    }
}


void rule::to_iptables_source_ports(result_builder & result, line_builder const & line)
{
    if(f_source_ports.empty())
    {
        to_iptables_destinations(result, line);
    }
    else
    {
        if(f_source_ports.size() == 1)
        {
            // for just one port, use --sport
            //
            line_builder sub_line(line);
            sub_line.append_both(" --sport " + f_source_ports[0]);
            to_iptables_destinations(result, sub_line);
        }
        else
        {
            // the maximum number of ports with -m multiport is 15 so here
            // we have to generate blocks of 15 or less
            //
            for(std::size_t idx(0); idx < f_source_ports.size(); idx += 15)
            {
                std::string l(" --sports ");
                std::size_t const max(std::min(idx + 15, f_source_ports.size()));
                l += snapdev::join_strings(f_source_ports.begin() + idx, f_source_ports.begin() + max, ",");
                line_builder sub_line(line);
                sub_line.append_both(l);
                to_iptables_destinations(result, sub_line);
            }
        }
    }
}


void rule::to_iptables_destinations(result_builder & result, line_builder const & line)
{
    if(f_destinations.empty())
    {
        if(f_except_destinations.empty())
        {
            if(!f_destination_ranges.empty()
            || !f_except_destination_ranges.empty())
            {
                // this rule uses ranges, this is not a case of an empty
                // destinations input so here we just return
                //
                return;
            }

            to_iptables_destination_ports(result, line);
        }
        else
        {
            for(auto const & s : f_except_destinations)
            {
                if(s.is_ipv4())
                {
                    if(!line.is_ipv6())
                    {
                        line_builder sub_line(line);
                        std::string const ip(address_with_mask(s));
                        sub_line.append_ipv4line(" ! -d " + ip, true);
                        to_iptables_destination_ports(result, sub_line);
                    }
                }
                else
                {
                    if(!line.is_ipv4())
                    {
                        line_builder sub_line(line);
                        std::string const ip(address_with_mask(s));
                        sub_line.append_ipv6line(" ! -d " + ip, true);
                        to_iptables_destination_ports(result, sub_line);
                    }
                }
            }
        }
    }
    else
    {
        for(auto const & s : f_destinations)
        {
            if(s.is_default())
            {
                // the default IP applies to both, IPv4 and IPv6
                //
                if(!line.is_ipv6())
                {
                    line_builder sub_line(line);
                    sub_line.append_ipv4line(" -d 0.0.0.0", true);
                    to_iptables_destination_ports(result, sub_line);
                }
                if(!line.is_ipv4())
                {
                    line_builder sub_line(line);
                    sub_line.append_ipv6line(" -d ::", true);
                    to_iptables_destination_ports(result, sub_line);
                }
            }
            else if(s.is_ipv4())
            {
                if(!line.is_ipv6())
                {
                    line_builder sub_line(line);
                    std::string const ip(address_with_mask(s));
                    sub_line.append_ipv4line(" -d " + ip, true);
                    to_iptables_destination_ports(result, sub_line);
                }
            }
            else
            {
                if(!line.is_ipv4())
                {
                    line_builder sub_line(line);
                    std::string const ip(address_with_mask(s));
                    sub_line.append_ipv6line(" -d " + ip, true);
                    to_iptables_destination_ports(result, sub_line);
                }
            }
        }
    }
}


void rule::to_iptables_destination_ports(result_builder & result, line_builder const & line)
{
    if(f_destination_ports.empty())
    {
        to_iptables_set(result, line);
    }
    else
    {
        if(f_destination_ports.size() == 1)
        {
            // for just one port, use --dport
            //
            line_builder sub_line(line);
            sub_line.append_both(" --dport " + f_destination_ports[0]);
            to_iptables_set(result, sub_line);
        }
        else
        {
            // the maximum number of ports with -m multiport is 15 so here
            // we have to generate blocks of 15 or less
            //
            // TBD: see whether having exactly 16 ports is an issue for
            //      the second rule which will get a single port
            //
            for(std::size_t idx(0); idx < f_destination_ports.size(); idx += 15)
            {
                std::string l(" --dports ");
                std::size_t const max(std::min(idx + 15, f_destination_ports.size()));
                for(std::size_t p(idx); p < max; ++p)
                {
                    if(p != idx)
                    {
                        l += ',';
                    }
                    l += f_destination_ports[p];
                }
                line_builder sub_line(line);
                sub_line.append_both(l);
                to_iptables_set(result, sub_line);
            }
        }
    }
}


void rule::to_iptables_set(result_builder & result, line_builder const & line)
{
    if(f_set.empty())
    {
        to_iptables_limits(result, line);
    }
    else
    {
        for(auto const & s : f_set)
        {
            line_builder sub_line(line);
            sub_line.append_both(" -m set --match-set " + s + " src");
            to_iptables_limits(result, sub_line);
        }
    }
}


void rule::to_iptables_limits(result_builder & result, line_builder const & line)
{
    if(f_limits.empty())
    {
        to_iptables_states(result, line);
    }
    else
    {
        // the limits are numbers optionally preceeded by operators
        //
        // the first is: [ '<=' | '<' | '>' ] number
        //
        // the second is: [ '<-' | '->' ] number
        //
        bool less_equal(true);
        std::int64_t count(0);
        {
            char const * s(f_limits[0].c_str());
            if(*s == '<')
            {
                ++s;
                if(*s == '=')
                {
                    ++s;
                }
            }
            else if(*s == '>')
            {
                less_equal = false;
                ++s;
            }
            while(isspace(*s))
            {
                ++s;
            }
            if(!advgetopt::validator_integer::convert_string(s, count))
            {
                SNAP_LOG_ERROR
                    << "the first number in the rule limit must be a valid integer number preceeeded by one of '<', '<=', '>' or no operator. \""
                    << f_limits[0]
                    << "\" is not valid."
                    << SNAP_LOG_SEND;
                f_valid = false;
            }
            else if(count <= 0)
            {
                SNAP_LOG_ERROR
                    << "the first number in the rule limit must be a positive number. \""
                    << f_limits[0]
                    << "\" is not valid."
                    << SNAP_LOG_SEND;
                f_valid = false;
            }
        }

        bool source_group(true);
        std::int64_t mask(-1);
        if(f_limits.size() == 2)
        {
            char const * s(f_limits[1].c_str());
            if(*s == '-')
            {
                ++s;
                if(*s == '>')
                {
                    ++s;
                }
                else
                {
                    SNAP_LOG_ERROR
                        << "the second number in the rule limit can be preceeded by '->' or '<-'. \""
                        << f_limits[1]
                        << "\" is not valid."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
            }
            else if(*s == '<')
            {
                source_group = false;
                ++s;
                if(*s == '-')
                {
                    ++s;
                }
                else
                {
                    SNAP_LOG_ERROR
                        << "the second number in the rule limit can be preceeded by '->' or '<-'. \""
                        << f_limits[1]
                        << "\" is not valid."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
            }
            while(isspace(*s))
            {
                ++s;
            }
            if(!advgetopt::validator_integer::convert_string(s, mask))
            {
                SNAP_LOG_ERROR
                    << "the second number in the rule limit must be a valid integer number preceeeded by one of '<-', '->', or no operator. \""
                    << f_limits[1]
                    << "\" is not valid."
                    << SNAP_LOG_SEND;
                f_valid = false;
            }
            else if(mask < 0 || mask > 128) // make it IPv4 or IPv6 max.
            {
                SNAP_LOG_ERROR
                    << "the second number in the rule limit must be between 0 and 128. \""
                    << f_limits[1]
                    << "\" is not valid."
                    << SNAP_LOG_SEND;
                f_valid = false;
            }
        }

        std::string l;
        if(less_equal)
        {
            l += " --connlimit-upto " + std::to_string(count);
        }
        else
        {
            l += " --connlimit-above " + std::to_string(count);
        }
        if(mask != -1)
        {
            l += " --connlimit-mask " + std::to_string(mask);
        }
        if(!source_group)
        {
            l += " --connlimit-daddr";
        }

        line_builder sub_line(line);
        if(mask > 32)
        {
            // a mask of more than 32 bits is only supported by IPv6
            //
            if(line.is_ipv4())
            {
                SNAP_LOG_ERROR
                    << "the second number in the rule limit must be between 0 and 32 for IPv4 addresses. \""
                    << f_limits[1]
                    << "\" is not valid."
                    << SNAP_LOG_SEND;
                f_valid = false;

                // allow continuation, the user already knows somethings is wrong
                //
                sub_line.append_both(l);
            }
            else
            {
                sub_line.append_ipv6line(l, true);
            }
        }
        else
        {
            sub_line.append_both(l);
        }
        to_iptables_states(result, sub_line);
    }
}


void rule::to_iptables_states(result_builder & result, line_builder const & line)
{
    if(f_states.empty())
    {
        to_iptables_target(result, line);
    }
    else
    {
        for(auto const & s : f_states)
        {
            if(!s.is_valid())
            {
                continue;
            }

            line_builder sub_line(line);
            sub_line.append_both(s.to_iptables_options(line.get_protocol()));
            to_iptables_target(result, sub_line);
        }
    }
}


void rule::to_iptables_target(result_builder & result, line_builder const & line)
{
    // the LOG action must appear first
    //
    if(!f_log.empty())
    {
        // the total length of the prefix is 29 or less
        //
        std::string prefix(
                  f_log_introducer
                + ' '
                + f_log);
        prefix = snapdev::string_replace_many(
                  prefix
                , {{"\"", "'"}});
        if(prefix.length() > 28) // 28 + ':' = 29
        {
            prefix = prefix.substr(0, 28);
        }
        prefix += ':';

        line_builder log_line(line);
        log_line.append_both(
              " -j LOG --log-prefix \""
            + prefix
            + "\" --log-uid\n");
        result.append_line(log_line);
    }

    if(f_action == action_t::ACTION_LOG)
    {
        // user only wanted a LOG, so we're done
        //
        return;
    }

    line_builder final_line(line);
    final_line.append_both(" -j " + get_action_name());

    switch(f_action)
    {
    case action_t::ACTION_CALL:
        // we need to add the name of the user chain to call
        //
        final_line.append_both(f_action_param);
        break;

    case action_t::ACTION_DNAT:
        final_line.append_both(" --to-destination " + f_action_param);
        break;

    case action_t::ACTION_REDIRECT:
        final_line.append_both(" --to-port " + f_action_param);
        break;

    case action_t::ACTION_REJECT:
        if(!f_action_param.empty())
        {
            final_line.append_both(" --reject-with " + f_action_param);
        }
        break;

    case action_t::ACTION_SNAT:
        final_line.append_both(" --to-source " + f_action_param);
        break;

    default:
        break;

    }
    final_line.append_both("\n");

    result.append_line(final_line);
}


// vim: ts=4 sw=4 et
