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
#include    "rule.h"

#include    "conntrack_parser.h"
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
#include    <advgetopt/validator_duration.h>
#include    <advgetopt/validator_integer.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
#include    <snapdev/file_contents.h>
#include    <snapdev/join_strings.h>
#include    <snapdev/not_reached.h>
#include    <snapdev/remove_duplicates.h>
#include    <snapdev/safe_variable.h>
#include    <snapdev/string_replace_many.h>


// C++
//
#include    <cmath>


// C
//
#include    <string.h>


// last include
//
#include    <snapdev/poison.h>



namespace
{


constexpr int       REJECT_OPTION_IPV4          = 0x0001;
constexpr int       REJECT_OPTION_IPV6          = 0x0002;
constexpr int       REJECT_OPTION_USE_PREVIOUS  = 0x0004;

struct reject_option {
    char const *    f_alias = nullptr;
    char const *    f_ipv4_name = nullptr;
    char const *    f_ipv6_name = nullptr;
};

constexpr char const * const        g_reject_icmp6_no_route = "icmp6-no-route";
constexpr char const * const        g_reject_no_route = "no-route";
constexpr char const * const        g_reject_icmp6_adm_prohibited = "icmp6-adm-prohibited";
constexpr char const * const        g_reject_icmp_adm_prohibited = "icmp-adm-prohibited";
constexpr char const * const        g_reject_icmp_admin_prohibited = "icmp-admin-prohibited";
constexpr char const * const        g_reject_adm_prohibited = "adm-prohibited";
constexpr char const * const        g_reject_icmp6_addr_unreachable = "icmp6-addr-unreachable";
constexpr char const * const        g_reject_addr_unreach = "addr-unreach";
constexpr char const * const        g_reject_addr_unreachable = "addr-unreachable";
constexpr char const * const        g_reject_icmp6_port_unreachable = "icmp6-port-unreachable";
constexpr char const * const        g_reject_icmp_port_unreachable = "icmp-port-unreachable";
constexpr char const * const        g_reject_port_unreachable = "port-unreachable";
constexpr char const * const        g_reject_icmp_net_unreachable = "icmp-net-unreachable";
constexpr char const * const        g_reject_net_unreachable = "net-unreachable";
constexpr char const * const        g_reject_icmp_net_prohibited = "icmp-net-prohibited";
constexpr char const * const        g_reject_net_prohibited = "net-prohibited";
constexpr char const * const        g_reject_icmp_host_unreachable = "icmp-host-unreachable";
constexpr char const * const        g_reject_host_unreachable = "host-unreachable";
constexpr char const * const        g_reject_host_unreach = "host-unreach";
constexpr char const * const        g_reject_icmp_proto_unreachable = "icmp-proto-unreachable";
constexpr char const * const        g_reject_proto_unreachable = "proto-unreachable";
constexpr char const * const        g_reject_proto_unreach = "proto-unreach";
constexpr char const * const        g_reject_tcp_reset = "tcp-reset";
constexpr char const * const        g_reject_icmp_tcp_reset = "icmp-tcp-reset";
constexpr char const * const        g_reject_icmp6_tcp_reset = "icmp6-tcp-reset";

reject_option g_reject_options[] =
{
    // no route
    { g_reject_icmp6_no_route,         nullptr,                         g_reject_icmp6_no_route },
    { g_reject_no_route,               nullptr,                         g_reject_no_route       },

    // adm prohibited
    { g_reject_icmp6_adm_prohibited,   nullptr,                         g_reject_icmp6_adm_prohibited },
    { g_reject_icmp_adm_prohibited,    g_reject_icmp_admin_prohibited,  nullptr                       },
    { g_reject_icmp_admin_prohibited,  g_reject_icmp_admin_prohibited,  nullptr                       },
    { g_reject_adm_prohibited,         g_reject_icmp_admin_prohibited,  g_reject_adm_prohibited       },

    // addr unreachable
    { g_reject_icmp6_addr_unreachable, nullptr,                         g_reject_icmp6_addr_unreachable },
    { g_reject_addr_unreach,           nullptr,                         g_reject_icmp6_addr_unreachable },
    { g_reject_addr_unreachable,       nullptr,                         g_reject_icmp6_addr_unreachable },   // our extension

    // port unreachable (default if unspecified)
    { g_reject_icmp6_port_unreachable, nullptr,                         g_reject_icmp6_port_unreachable },
    { g_reject_icmp_port_unreachable,  g_reject_icmp_port_unreachable,  nullptr                         },
    { g_reject_port_unreachable,       g_reject_icmp_port_unreachable,  g_reject_icmp6_port_unreachable },   // our extension

    // net unreachable
    { g_reject_icmp_net_unreachable,   g_reject_icmp_net_unreachable,   nullptr },
    { g_reject_net_unreachable,        g_reject_icmp_net_unreachable,   nullptr },   // our extension

    // net prohibited
    { g_reject_icmp_net_prohibited,    g_reject_icmp_net_prohibited,    nullptr },
    { g_reject_net_prohibited,         g_reject_icmp_net_prohibited,    nullptr },   // our extension

    // host unreachable
    { g_reject_icmp_host_unreachable,  g_reject_icmp_host_unreachable,  nullptr },
    { g_reject_host_unreachable,       g_reject_icmp_host_unreachable,  nullptr },   // our extension
    { g_reject_host_unreach,           g_reject_icmp_host_unreachable,  nullptr },   // our extension

    // proto unreachable
    { g_reject_icmp_proto_unreachable, g_reject_icmp_proto_unreachable, nullptr },
    { g_reject_proto_unreachable,      g_reject_icmp_proto_unreachable, nullptr },   // our extension
    { g_reject_proto_unreach,          g_reject_icmp_proto_unreachable, nullptr },   // our extension

    // tcp reset
    { g_reject_tcp_reset,              g_reject_tcp_reset,              g_reject_tcp_reset },
    { g_reject_icmp_tcp_reset,         g_reject_icmp_tcp_reset,         nullptr            },   // our extension
    { g_reject_icmp6_tcp_reset,        nullptr,                         g_reject_tcp_reset },   // our extension
};


constexpr char const * const g_original_reply[] =
{
    "origsrc",
    "origdst",
    "replsrc",
    "repldst"
};


std::string address_with_mask(addr::addr const & a)
{
    return a.to_ipv4or6_string(addr::STRING_IP_ADDRESS | addr::STRING_IP_MASK_IF_NEEDED);
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


std::string rule::line_builder::get_chain_name() const
{
    return f_generating_for_chain_name;
}


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
    else if(protocol == "icmp")
    {
        set_ipv4();
        f_generating_for_protocol = "icmp";
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


void rule::line_builder::set_next_func(to_iptables_func_t f)
{
    f_next_func = f;
}


rule::to_iptables_func_t rule::line_builder::get_next_func() const
{
    return f_next_func;
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
        , advgetopt::variables::pointer_t variables
        , std::string const & path_to_drop_lists)
    : f_path_to_drop_lists(path_to_drop_lists)
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
                snapdev::sort_and_remove_duplicates(f_after);
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
                snapdev::sort_and_remove_duplicates(f_before);
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
                for(auto ch(f_chains.begin()); ch != f_chains.end(); )
                {
                    if(*ch == "ipv4")
                    {
                        ch = f_chains.erase(ch);
                        f_force_ipv4 = true;
                    }
                    else if(*ch == "ipv6")
                    {
                        ch = f_chains.erase(ch);
                        f_force_ipv6 = true;
                    }
                    else
                    {
                        ++ch;
                    }
                }
            }
            else if(param_name == "comment")
            {
                f_comment = snapdev::string_replace_many(
                          value
                        , {{"\"", "'"}}).substr(0, 256);
            }
            else if(param_name == "condition"
                 || param_name == "conditions")
            {
                f_condition = parse_condition(value, f_valid);
            }
            else if(param_name == "conntrack")
            {
                advgetopt::string_list_t conntracks;
                advgetopt::split_string(value, conntracks, {","});
                for(auto const & c : conntracks)
                {
                    conntrack_parser::pointer_t ct(std::make_shared<conntrack_parser>());
                    if(!ct->parse(c))
                    {
                        SNAP_LOG_ERROR
                            << "an error occurred parsing \""
                            << c
                            << "\" as a conntrack declaration."
                            << SNAP_LOG_SEND;
                        f_valid = false;
                    }
                    f_conntrack.push_back(ct);
                }
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
            if(param_name == "enable"
            || param_name == "enabled")
            {
                f_enabled = advgetopt::is_true(value);
            }
            else if(param_name == "except-destination"
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

        case 'k':
            if(param_name == "knock"
            || param_name == "knocks")
            {
                std::string const error(iplock::parse_ports(value, f_knock_ports));
                if(!error.empty())
                {
                    SNAP_LOG_ERROR
                        << '"'
                        << value
                        << "\" is not a valid set of knock ports: "
                        << error
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else if(sorted_ports(f_knock_ports))
                {
                    SNAP_LOG_ERROR
                        << "the ports in \""
                        << value
                        << "\" are in forward or backward order. Please shuffle the ports."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                if(!unique_ports(f_knock_ports))
                {
                    SNAP_LOG_ERROR
                        << "each port in \""
                        << value
                        << "\" must be unique. Please replace duplicates."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
            }
            else if(param_name == "knock-clear")
            {
                advgetopt::split_string(value, f_knock_clear, {","});
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

        case 'r':
            if(param_name == "recent")
            {
                // one rule can include "as many" `-m recent` entries as
                // required by that rule to function properly
                //
                // the recent parser manages one rule, here we split the
                // rules on commas and parse each entry individually;
                // the order matters so we save the results in a vector
                //
                advgetopt::string_list_t recent_entries;
                advgetopt::split_string(value, recent_entries, {","});
                for(auto const & r : recent_entries)
                {
                    recent_parser p;
                    p.parse(r);
                    if(p.get_valid())
                    {
                        if(p.get_recent() != recent_t::RECENT_NONE)
                        {
                            f_recent.push_back(p);
                        }
                    }
                    else
                    {
                        f_valid = false;
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
            else if(param_name == "set-data")
            {
                advgetopt::split_string(value, f_set_data, {","});
            }
            else if(param_name == "set-from-file")
            {
                load_file(value, f_set_data);
            }
            else if(param_name == "set-type")
            {
                std::string::size_type colon(value.find(':'));
                if(colon == std::string::npos)
                {
                    // user did not specify the structure type, force to "hash"
                    //
                    //     [<structure-type>:]<data-type>[,<data-type>,...]
                    //
                    value = "hash:" + value;
                    colon = 4;
                }
                f_set_type = value;

                f_set_has_ip = false;
                advgetopt::string_list_t types;
                advgetopt::split_string(f_set_type.substr(colon + 1), types, {","});
                for(auto const & t : types)
                {
                    if(t == "ip"
                    || t == "net")
                    {
                        f_set_has_ip = true;
                        break;
                    }
                }
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

        case 't':
            if(param_name == "table"
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

    if(f_force_ipv4 && f_force_ipv6)
    {
        SNAP_LOG_ERROR
            << "found rules that force IPv4 an IPv6 at the same time (i.e. chains = ipv4, ipv6; reject = IPv4/6 ICMP contradicts your chain definition, etc.)."
            << SNAP_LOG_SEND;
        f_valid = false;
    }

    // TODO: this is not quite correct; it has to be with the INPUT chain
    //       but could be in a user defined chain called from the INPUT chain...
    //
    //if(!f_knock_ports.empty()
    //&& f_chains.find("INPUT") == f_chains.end())
    //{
    //    SNAP_LOG_ERROR
    //        << "knocks = ... parameter can only be used with the INPUT chain."
    //        << SNAP_LOG_SEND;
    //    f_valid = false;
    //}

    if(!f_knock_ports.empty()
    && !f_recent.empty())
    {
        SNAP_LOG_ERROR
            << "the \"knocks = ...\" and \"recent = ...\" parameters cannot be used together."
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
    if(a.length() > 0)
    {
        switch(a[0])
        {
        case 'a':
            if(a == "accept"
            || a == "allow")  // synonym
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"ACCEPT\" (ALLOW) action does not support a parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_ACCEPT;
                }
                return;
            }
            else if(a == "audit")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"AUDIT\" action must be used with exactly one parameter (accept, drop, reject)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_AUDIT;
                    f_action_param = action_param[1];
                }
                return;
            }
            break;

        case 'b':
            if(a == "blackhole") // DROP synonym
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"DROP\" (DENY, BLACKHOLE) action does not support a parameter."
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
            else if(a == "checksum")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"CHECKSUM\" action must be used with exactly one parameter (fill)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_CHECKSUM;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "classify")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"CLASSIFY\" action must be used with exactly one parameter (major:minor)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_CLASSIFY;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "clusterip")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"CLUSTERIP\" action must be used with exactly one parameter (new, sourceip, sourceip-sourceport, sourceip-sourceport-destport, a mac address, +node-count, #node-number, seed-number)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_CLUSTERIP;
                    f_action_param = action_param[1];
                    f_force_ipv4 = true;
                }
                return;
            }
            else if(a == "connmark")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"CONNMARK\" action must be used with exactly one parameter (mark)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_CONNMARK;
                    f_action_param = action_param[1];
                }
            }
            else if(a == "connsecmark")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"CONNSECMARK\" action must be used with exactly one parameter (mark)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_CONNSECMARK;
                    f_action_param = action_param[1];
                }
            }
            else if(a == "ct")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"CT\" action must be used with exactly one parameter (notrack, ...)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_CT;
                    f_action_param = action_param[1];
                }
                return;
            }
            break;

        case 'd':
            if(a == "drop"
            || a == "deny") // synonym
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"DROP\" (DENY, BLACKHOLE) action does not support a parameter."
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
                        << "the \"DNAT\" action requires the destination parameter (ipaddress:port, random, persistent)."
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
            else if(a == "dnpt")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"DNPT\" action must be used with exactly one parameter (< or > followed by an IPv6 address with a mask)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_DNPT;
                    f_action_param = action_param[1];
                    f_force_ipv6 = true;
                }
                return;
            }
            else if(a == "dscp")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"DSCP\" action must be used with exactly one parameter (number of class name)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_DSCP;
                    f_action_param = action_param[1];
                }
                return;
            }
            break;

        case 'e':
            if(a == "ecn")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"ECN\" action must be used with exactly one parameter (remove)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_ECN;
                    f_action_param = action_param[1];
                    f_force_ipv4 = true;
                }
                return;
            }
            break;

        case 'h':
            if(a == "hl")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"HL\" action must be used with exactly one parameter ([=]num, +num, -num)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_HL;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "hmark")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"HMARK\" action must be used with exactly one parameter (src, dst, sport, dport, spi, ct, ...)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_HMARK;
                    f_action_param = action_param[1];
                }
                return;
            }
            break;

        case 'i':
            if(a == "idletimer")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"IDLETIMER\" action must be used with exactly one parameter (identifier or number)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_IDLETIMER;
                    f_action_param = action_param[1];
                }
                return;
            }
            break;

        case 'l':
            if(a == "led")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"LED\" action must be used with exactly one parameter (a name, a number, \"blink\")."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_LED;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "log")
            {
                if(action_param.size() != 1)
                {
                    // TODO: there are actually parameters: level, prefix, sequence, options, uid
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
            if(a == "mark")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"MARK\" action must be used with exactly one parameter (mark)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_MARK;
                    f_action_param = action_param[1];
                }
            }
            else if(a == "masquerade")
            {
                if(action_param.size() > 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"MASQUERADE\" action does not support a parameter (port, port range, random)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_MASQUERADE;
                    if(action_param.size() == 2)
                    {
                        f_action_param = action_param[1];
                    }
                }
                return;
            }
            break;

        case 'n':
            if(a == "netmap")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"NETMAP\" action must be used with exactly one parameter (address/mask)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_NETMAP;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "nflog")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"NFLOG\" action must be used with exactly one parameter (...)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_NFLOG;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "nfqueue")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"NFQUEUE\" action must be used with exactly one parameter (number, number:number, bypass, cpu-fanout)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_NFQUEUE;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "notrack")
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"NOTRACK\" action does not support parameters."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_NOTRACK;
                }
                return;
            }
            else if(a == "none")
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"NONE\" action does not support parameters."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_NONE;
                }
                return;
            }
            break;

        case 'r':
            if(a == "rateest")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"RATEEST\" action must be used with exactly one parameter (name, duration, number)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_RATEEST;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "redirect")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"REDIRECT\" action requires a port parameter or \"random\"."
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
            else if(a == "reject")
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
                        parse_reject_action();
                    }
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
            if(a == "secmark")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"SECMARK\" action must be used with exactly one parameter (mark)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_SECMARK;
                    f_action_param = action_param[1];
                }
            }
            else if(a == "set")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"SET\" action must be used with exactly one parameter (TODO)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_SET;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "snat")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"SNAT\" action requires the source parameter"
                           " or one of \"persistent\", \"random\","
                           " \"random-fully\", or \"fully-random\"."
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
            else if(a == "snpt")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"SNPT\" action must be used with exactly one parameter (<address, >address)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_SNPT;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "synproxy")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"SYNPROXY\" action must be used with exactly one parameter (...)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_SYNPROXY;
                    f_action_param = action_param[1];
                }
                return;
            }
            break;

        case 't':
            if(a == "tcpmss")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"TCPMSS\" action must be used with exactly one parameter (mss, \"clamp\")."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_TCPMSS;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "tcpoptstrip")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"TCPOPTSTRIP\" action must be used with exactly one parameter (option names)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_TCPOPTSTRIP;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "tee")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"TEE\" action must be used with exactly one parameter (address)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_TEE;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "tos")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"TOS\" action must be used with exactly one parameter (type of service)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_TOS;
                    f_action_param = action_param[1];
                }
            }
            else if(a == "tproxy")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"TPROXY\" action must be used with exactly one parameter (port, address, value/mask)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_TPROXY;
                    f_action_param = action_param[1];
                }
                return;
            }
            else if(a == "trace")
            {
                if(action_param.size() != 1)
                {
                    SNAP_LOG_ERROR
                        << "the \"TRACE\" action does not accept any parameter."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_TRACE;
                }
                return;
            }
            else if(a == "ttl")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"TTL\" action must be used with exactly one parameter (time to live)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_TTL;
                    f_action_param = action_param[1];
                }
            }
            break;

        case 'u':
            if(a == "ulog")
            {
                if(action_param.size() != 2)
                {
                    SNAP_LOG_ERROR
                        << "the \"ULOG\" action must be used with exactly one parameter (...)."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
                else
                {
                    f_action = action_t::ACTION_ULOG;
                    f_action_param = action_param[1];
                    f_force_ipv4 = true;
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
    advgetopt::string_list_t const input(in);
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
            && !r.get_from().is_port_defined())
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


void rule::parse_reject_action()
{
    if(f_action_param.empty())
    {
        return;
    }

    for(std::size_t idx(0); idx < std::size(g_reject_options); ++idx)
    {
        if(strcmp(g_reject_options[idx].f_alias, f_action_param.c_str()) == 0)
        {
            f_action_param = g_reject_options[idx].f_ipv4_name;
            f_action_param2 = g_reject_options[idx].f_ipv6_name;
            if(f_action_param.empty())
            {
                if(f_action_param2.empty())
                {
                    throw iplock::logic_error("REJECT action option #" + std::to_string(idx) + " has no IPv4 and no IPv6 names.");
                }
                f_force_ipv6 = true;
            }
            else if(f_action_param2.empty())
            {
                f_force_ipv4 = true;
            }
            // else -- both are valid, no force IPv4 or IPv6 necessary
            return;
        }
    }

    SNAP_LOG_ERROR
        << "unrecognized \"REJECT\" action \""
        << f_action_param
        << "\"."
        << SNAP_LOG_SEND;
    f_valid = false;
}


void rule::load_file(std::string const & filename, advgetopt::string_list_t & data)
{
    if(filename.empty())
    {
        return;
    }
    std::string fullname(filename);

    auto invalid_file = [&](std::string const & msg)
        {
            SNAP_LOG_ERROR
                << "could not read file \""
                << fullname
                << "\": "
                << msg
                << SNAP_LOG_SEND;
            f_valid = false;
        };

    if(access(fullname.c_str(), R_OK) != 0)
    {
        if(filename[0] == '/')
        {
            invalid_file(strerror(errno));
            return;
        }

        bool found(false);
        advgetopt::string_list_t drop_paths;
        advgetopt::split_string(f_path_to_drop_lists, drop_paths, {":"});
        for(auto const & path : drop_paths)
        {
            fullname = path + "/" + filename;
            if(access(fullname.c_str(), R_OK) == 0)
            {
                found = true;
                break;
            }
        }
        if(!found)
        {
            invalid_file("not found anywhere");
            return;
        }
    }

    snapdev::file_contents in(fullname);
    if(!in.read_all())
    {
        invalid_file(in.last_error());
        return;
    }

    addr::addr::vector_t list;

    addr::addr_parser p;
    p.set_protocol(IPPROTO_TCP);
    p.set_allow(addr::allow_t::ALLOW_PORT, false);
    p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_NEWLINES, true);
    p.set_allow(addr::allow_t::ALLOW_COMMENT_SEMICOLON, true);
    p.set_allow(addr::allow_t::ALLOW_MASK, true);
    addr::addr_range::vector_t ranges(p.parse(in.contents()));
    for(auto const & r : ranges)
    {
        if(!r.has_from())
        {
            SNAP_LOG_ERROR
                << "somehow a range does not include a 'from' address when it should; found in \""
                << fullname
                << "\"."
                << SNAP_LOG_SEND;
            f_valid = false;
            continue;
        }
        addr::addr const & a(r.get_from());
        list.push_back(a);
    }
    addr::optimize_vector(list);
    for(auto const & l : list)
    {
        data.push_back(l.to_ipv4or6_string(addr::STRING_IP_BRACKET_ADDRESS | addr::STRING_IP_MASK));
    }
}


/** \brief Whether this rule can use the multi-port extension.
 *
 * For some reason, the multi-port extension only supports source or
 * destination ports or ranges of ports. Any other mix and the rule
 * fails.
 *
 * This function checks that we can indeed use multi-port. If not
 * then the system reverts to using one port for the source and one
 * port for the destination. If you do have many ports (counting
 * ranges as 1), then you may want to switch to using a set instead.
 *
 * \return true if this rule supports the multi-port feature.
 */
bool rule::is_multi_port() const
{
    return f_source_ports.size() > 1 && f_destination_ports.empty()
        || f_destination_ports.size() > 1 && f_source_ports.empty();
}


bool rule::is_valid() const
{
    return f_valid;
}


bool rule::empty() const
{
    return !f_valid || !f_condition || !f_enabled;
}


std::string const & rule::get_name() const
{
    return f_name;
}


std::string const & rule::get_description() const
{
    return f_description;
}


advgetopt::string_list_t const & rule::get_tables() const
{
    return f_tables;
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


advgetopt::string_list_t const & rule::get_set_data() const
{
    return f_set_data;
}


std::string const & rule::get_set_type() const
{
    return f_set_type;
}


bool rule::set_has_ip() const
{
    return f_set_has_ip;
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
    case action_t::ACTION_NONE:
        throw iplock::logic_error("action still undefined or set to NONE");

    case action_t::ACTION_ACCEPT:
        return "ACCEPT";

    case action_t::ACTION_AUDIT:
        return "AUDIT";

    case action_t::ACTION_CALL:
        return std::string();

    case action_t::ACTION_CHECKSUM:
        return "CHECKSUM";

    case action_t::ACTION_CLASSIFY:
        return "CLASSIFY";

    case action_t::ACTION_CLUSTERIP:
        return "CLUSTERIP";

    case action_t::ACTION_CONNMARK:
        return "CONNMARK";

    case action_t::ACTION_CONNSECMARK:
        return "CONNSECMARK";

    case action_t::ACTION_CT:
        return "CT";

    case action_t::ACTION_DNAT:
        return "DNAT";

    case action_t::ACTION_DNPT:
        return "DNPT";

    case action_t::ACTION_DSCP:
        return "DSCP";

    case action_t::ACTION_DROP:
        return "DROP";

    case action_t::ACTION_ECN:
        return "ECN";

    case action_t::ACTION_HL:
        return "HL";

    case action_t::ACTION_HMARK:
        return "HMARK";

    case action_t::ACTION_IDLETIMER:
        return "IDLETIMER";

    case action_t::ACTION_LED:
        return "LED";

    case action_t::ACTION_LOG:
        return "LOG";

    case action_t::ACTION_MARK:
        return "MARK";

    case action_t::ACTION_MASQUERADE:
        return "MASQUERADE";

    case action_t::ACTION_NETMAP:
        return "NETMAP";

    case action_t::ACTION_NFLOG:
        return "NFLOG";

    case action_t::ACTION_NFQUEUE:
        return "NFQUEUE";

    case action_t::ACTION_NOTRACK:
        return "NOTRACK";

    case action_t::ACTION_RATEEST:
        return "RATEEST";

    case action_t::ACTION_REDIRECT:
        return "REDIRECT";

    case action_t::ACTION_REJECT:
        return "REJECT";

    case action_t::ACTION_RETURN:
        return "RETURN";

    case action_t::ACTION_SECMARK:
        return "SECMARK";

    case action_t::ACTION_SET:
        return "SET";

    case action_t::ACTION_SNAT:
        return "SNAT";

    case action_t::ACTION_SNPT:
        return "SNPT";

    case action_t::ACTION_SYNPROXY:
        return "SYNPROXY";

    case action_t::ACTION_TCPMSS:
        return "TCPMSS";

    case action_t::ACTION_TCPOPTSTRIP:
        return "TCPOPTSTRIP";

    case action_t::ACTION_TEE:
        return "TEE";

    case action_t::ACTION_TPROXY:
        return "TPROXY";

    case action_t::ACTION_TOS:
        return "TOS";

    case action_t::ACTION_TRACE:
        return "TRACE";

    case action_t::ACTION_TTL:
        return "TTL";

    case action_t::ACTION_ULOG:
        return "ULOG";

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
    f_dependencies.insert(r);
}


rule::set_t const & rule::get_dependencies() const
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

    if(f_force_ipv4)
    {
        line.set_ipv4();
    }
    else if(f_force_ipv6)
    {
        line.set_ipv6();
    }

    to_iptables_knocks(result, line);

    return result.get_result();
}


void rule::to_iptables_knocks(result_builder & result, line_builder const & line)
{
    // the basic knock rules skip on interfaces, sources/destinations, etc.
    // the main rules have them so it is still very safe and that way we
    // avoid a lot of unnecessary duplication
    //
    std::size_t const count(f_knock_ports.size());
    if(count == 0)
    {
        to_iptables_source_interfaces(result, line);
    }
    else
    {
        // the rules should only apply to an INPUT rule, unfortunately
        // with user defined chains, we just cannot currently guarantee

        // verify that destination ports and knock ports do not overlap
        // because that would cause problems
        //
        // why is that an issue?
        //   there are delays to allow the next connection; if you do not
        //   wait long enough, the port knocking will fail because it will
        //   allow the connection to the destination port when it should
        //   let go and go through the port knocking rule instead
        //
        for(auto const & p : f_destination_ports)
        {
            for(auto const & pp : f_knock_ports)
            {
                // TODO: strengthen this test, the 'p' string could be a
                //       port name (i.e. "ssh")
                //
                // TODO: this loop ignores the protocol; if the connection
                //       on destination ports is TCP and the port knocking
                //       is UDP, then we should not prevent the reuse
                //
                if(p == std::to_string(pp.f_port))
                {
                    SNAP_LOG_ERROR
                        << "knock port \""
                        << p
                        << "\" should not be used since it is one of the destination port."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
            }
        }

        // the following sequence must remain in order

        // if specified, first remove user from blocking lists when they
        // successeed with the knocking sequence
        //
        // this is practical for you to write a test which blocks your
        // IP address, then knock and try again from "scratch"
        //
        snapdev::safe_variable const safe_action(f_action, action_t::ACTION_NONE);
        if(!f_knock_clear.empty())
        {
            // this rule has no need for a separate f_recent since we bypass
            // all of that by calling to_iptables_limits() directly
            //
            std::string clear(" -m recent --rcheck --seconds ");
            clear += std::to_string(f_knock_ports[count - 1].f_duration);
            clear += " --name knock";
            clear += std::to_string(count);
            for(auto const & c : f_knock_clear)
            {
                clear += " -m recent --remove --name ";
                clear += c;
            }

            line_builder clear_lists(line.get_chain_name());
            clear_lists.append_both(clear);
            to_iptables_limits(result, clear_lists);
        }

        // second, apply the user rules with a verification against
        // that knock<N> rule
        //
        f_action = safe_action.saved_value();
        line_builder sub_line(line);
        //{
        //    recent_parser p;
        //    p.parse("check knock" + std::to_string(count) + " 10s");
        //    if(!p.get_valid())
        //    {
        //        throw logic_error("the recent parser failed with \"check knock<#> 10s\"");
        //    }
        //    f_recent.push_back(p);
        //}
        sub_line.append_both(
                  " -m recent --rcheck --seconds "
                + std::to_string(f_knock_ports[count - 1].f_duration)
                + " --name knock"
                + std::to_string(count));
        to_iptables_source_interfaces(result, sub_line);
        //to_iptables_source_interfaces(result, line);

        f_action = action_t::ACTION_NONE;
        snapdev::safe_variable safe_destination_ports(f_destination_ports, {});
        snapdev::safe_variable safe_protocols(f_protocols, {});
        for(std::size_t idx(count); idx > 1; --idx)
        {
            // also, the -m recent entries must appear after the -m tcp entries
            // to make sure that things work as expected; this means here we save
            // the data in the f_recent and let the to_iptables_recent() rule
            // output the actual data
            //
            line_builder knock(line);
            {
                recent_parser p;
                p.parse("check knock" + std::to_string(idx - 1)
                      + " "
                      + std::to_string(f_knock_ports[idx - 2].f_duration) + "s");
                if(!p.get_valid())
                {
                    throw iplock::logic_error("the recent parser failed with \"check knock<#> <duration>s\"");
                }
                f_recent.push_back(p);
            }
            {
                recent_parser p;
                p.parse("set knock" + std::to_string(idx));
                if(!p.get_valid())
                {
                    throw iplock::logic_error("the recent parser failed with \"set knock<#>\"");
                }
                f_recent.push_back(p);
            }
            //knock.append_both(
            //          " -m recent --rcheck --seconds 10 --name knock"
            //        + std::to_string(idx - 1)
            //        + " -m recent --set --name knock"
            //        + std::to_string(idx));
            knock.set_next_func(std::bind(
                      &rule::to_iptables_destination_ports
                    , this
                    , std::placeholders::_1
                    , std::placeholders::_2));
            f_destination_ports = { std::to_string(f_knock_ports[idx - 1].f_port) };
            if(f_knock_ports[idx - 1].f_protocol != IPPROTO_IP)
            {
                f_protocols = { f_knock_ports[idx - 1].protocol_name() };
            }
            else
            {
                f_protocols = safe_protocols.saved_value();
            }
            to_iptables_protocols(result, knock);

            f_recent.clear();

            line_builder remover(line.get_chain_name());
            //{
            //    recent_parser p;
            //    p.parse("remove knock" + std::to_string(idx - 1));
            //    if(!p.get_valid())
            //    {
            //        throw iplock::logic_error("the recent parser failed with \"remove knock<#>\"");
            //    }
            //    f_recent.push_back(p);
            //}
            remover.append_both(
                      " -m recent --remove --name knock"
                    + std::to_string(idx - 1));
            to_iptables_limits(result, remover);
        }

        // add first knock entry
        //
        line_builder first_knock(line);
        {
            recent_parser p;
            p.parse("set knock1");
            if(!p.get_valid())
            {
                throw iplock::logic_error("the recent parser failed with \"remove knock<#>\"");
            }
            f_recent.push_back(p);
        }
        //first_knock.append_both(" -m recent --set --name knock1");
        first_knock.set_next_func(std::bind(
                  &rule::to_iptables_destination_ports
                , this
                , std::placeholders::_1
                , std::placeholders::_2));
        f_destination_ports = { std::to_string(f_knock_ports[0].f_port) };
        if(f_knock_ports[0].f_protocol != IPPROTO_IP)
        {
            f_protocols = { f_knock_ports[0].protocol_name() };
        }
        else
        {
            f_protocols = safe_protocols.saved_value();
        }
        to_iptables_protocols(result, first_knock);

        f_recent.clear();

        //f_protocols = save_protocols;
        //f_destination_ports = save_destination_ports;
        //f_action = save_action;
    }
}


void rule::to_iptables_source_interfaces(result_builder & result, line_builder const & line)
{
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
    to_iptables_func_t next(line.get_next_func());
    if(next == nullptr)
    {
        next = std::bind(
                  &rule::to_iptables_sources
                , this
                , std::placeholders::_1
                , std::placeholders::_2);
    }

    bool is_established_related(false);
    bool is_invalid(false);
    for(auto const & s : f_states)
    {
        if(s.is_valid())
        {
            if(s.get_established_related())
            {
                is_established_related = true;
            }
            if(s.get_invalid())
            {
                is_invalid = true;
            }
        }
    }

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

        if(is_established_related || is_invalid)
        {
            line_builder sub_line(line);
            sub_line.append_both(" -m state");
            if(is_established_related)
            {
                sub_line.append_both(" --state ESTABLISHED,RELATED");
            }
            if(is_invalid)
            {
                sub_line.append_both(" --state INVALID");
            }
            next(result, sub_line);
        }
        else
        {
            next(result, line);
        }
    }
    else
    {
        for(auto const & s : f_protocols)
        {
            line_builder sub_line(line);

            if(s != "icmpv6")
            {
                sub_line.set_protocol(s); // if "icmp", this forces IPv4

                sub_line.append_both(" -p " + s);
                if(is_established_related || is_invalid)
                {
                    sub_line.append_both(" -m state");
                    if(is_established_related)
                    {
                        sub_line.append_both(" --state ESTABLISHED,RELATED");
                    }
                    if(is_invalid)
                    {
                        sub_line.append_both(" --state INVALID");
                    }
                }
                if(is_multi_port())
                {
                    sub_line.append_both(" -m multiport");
                }
                next(result, sub_line);
            }
            else //if(s == "icmpv6")
            {
                sub_line.set_protocol("icmpv6"); // this forces IPv6

                sub_line.append_ipv6line(" -p icmpv6");
                if(is_established_related || is_invalid)
                {
                    sub_line.append_ipv6line(" -m state");
                    if(is_established_related)
                    {
                        sub_line.append_ipv6line(" --state ESTABLISHED,RELATED");
                    }
                    if(is_invalid)
                    {
                        sub_line.append_ipv6line(" --state INVALID");
                    }
                }
                if(is_multi_port())
                {
                    sub_line.append_ipv6line(" -m multiport");
                }
                next(result, sub_line);
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
            if(!s.is_mask_defined()
            && s.is_default())
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
        if(!is_multi_port())
        {
            // when multi-port cannot be used
            //
            for(std::size_t idx(0); idx < f_source_ports.size(); ++idx)
            {
                line_builder sub_line(line);
                sub_line.append_both(" --sport " + f_source_ports[idx]);
                to_iptables_destinations(result, sub_line);
            }
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
            if(!s.is_mask_defined()
            && s.is_default())
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
                // here we want to handle the very special case of:
                //    'ffff:0.0.0.0/96'
                // which we want to output as such in the IPv6 table
                //
                if(s.is_default()
                && s.get_mask_size() == 96
                && !line.is_ipv4())
                {
                    line_builder sub_line(line);
                    sub_line.append_ipv6line(" -d ::ffff:0.0.0.0/96", true);
                    to_iptables_destination_ports(result, sub_line);
                }
                else
                {
                    if(!line.is_ipv6())
                    {
                        line_builder sub_line(line);
                        std::string const ip(address_with_mask(s));
                        sub_line.append_ipv4line(" -d " + ip, true);
                        to_iptables_destination_ports(result, sub_line);
                    }
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
        if(!is_multi_port())
        {
            // when multi-port cannot be used
            //
            for(std::size_t idx(0); idx < f_destination_ports.size(); ++idx)
            {
                line_builder sub_line(line);
                sub_line.append_both(" --dport " + f_destination_ports[idx]);
                to_iptables_set(result, sub_line);
            }
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
        to_iptables_track(result, line);
    }
    else
    {
        for(auto const & s : f_set)
        {
            if(f_set_has_ip)
            {
                if(!line.is_ipv6())
                {
                    line_builder sub_line(line);
                    sub_line.append_ipv4line(" -m set --match-set " + s + "_ipv4 src", true);
                    to_iptables_track(result, sub_line);
                }
                if(!line.is_ipv4())
                {
                    line_builder sub_line(line);
                    sub_line.append_ipv6line(" -m set --match-set " + s + "_ipv6 src", true);
                    to_iptables_track(result, sub_line);
                }
            }
            else
            {
                line_builder sub_line(line);
                sub_line.append_both(" -m set --match-set " + s + " src");
                to_iptables_track(result, sub_line);
            }
        }
    }
}


void rule::to_iptables_track(result_builder & result, line_builder const & line)
{
    if(f_conntrack.empty())
    {
        to_iptables_limits(result, line);
    }
    else
    {
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

        for(auto const & ct : f_conntrack)
        {
            std::string l(" -m conntrack");
            advgetopt::string_set_t states(ct->get_states());
            if(!states.empty())
            {
                if(ct->get_negate(negate_t::NEGATE_STATES))
                {
                    l += " !";
                }
                l += " --ctstate " + snapdev::join_strings(
                                                  states.begin()
                                                , states.end()
                                                , ",");
            }

            int protocol(ct->get_protocol());
            if(protocol != -1)
            {
                if(ct->get_negate(negate_t::NEGATE_PROTOCOL))
                {
                    l += " !";
                }
                l += " --ctproto " + std::to_string(protocol);
            }

            bool force_ipv4(false);
            bool force_ipv6(false);
            for(int idx(0); idx < 4; ++idx)
            {
                addr::addr const & a(ct->get_address(idx));
                if(!a.is_default())
                {
                    if(ct->get_negate(static_cast<negate_t>(static_cast<int>(negate_t::NEGATE_ORIGINAL_SRC_ADDRESS) + idx)))
                    {
                        l += " !";
                    }
                    l += " --ct"
                       + std::string(g_original_reply[idx])
                       + ' '
                       + address_with_mask(a); //.to_ipv4or6_string(addr::string_ip_t::STRING_IP_MASK);
                    if(a.is_ipv4())
                    {
                        force_ipv4 = true;
                    }
                    else
                    {
                        force_ipv6 = true;
                    }
                }
                int p(ct->get_start_port(idx));
                if(p != -1)
                {
                    if(ct->get_negate(static_cast<negate_t>(static_cast<int>(negate_t::NEGATE_ORIGINAL_SRC_PORTS) + idx)))
                    {
                        l += " !";
                    }
                    l += " --ct"
                       + std::string(g_original_reply[idx])
                       + "port "
                       + std::to_string(p);
                    p = ct->get_end_port(idx);
                    if(p != -1)
                    {
                        l += ':';
                        l += std::to_string(p);
                    }
                }
            }
            if(force_ipv4 && force_ipv6)
            {
                SNAP_LOG_ERROR
                    << "a conntrack definition includes IPv4 and IPv6 addresses mixed together."
                      " This is not allowed. We need the IPv4 addresses in the iptables and the"
                      " IPv6 addresses in the ip6tables."
                    << SNAP_LOG_SEND;
                f_valid = false;
                continue;
            }

            advgetopt::string_set_t statuses(ct->get_statuses());
            if(!states.empty())
            {
                if(ct->get_negate(negate_t::NEGATE_STATUSES))
                {
                    l += " !";
                }
                l += " --ctstatus " + snapdev::join_strings(
                                                  statuses.begin()
                                                , statuses.end()
                                                , ",");
            }

            std::int64_t time(ct->get_expire_start_time());
            if(time != -1)
            {
                if(ct->get_negate(negate_t::NEGATE_EXPIRE))
                {
                    l += " !";
                }
                l += " --ctexpire "
                   + std::to_string(time);
                time = ct->get_expire_end_time();
                if(time != -1)
                {
                    l += ':';
                    l += std::to_string(time);
                }
            }

            direction_t dir(ct->get_direction());
            if(dir != direction_t::DIRECTION_BOTH)
            {
                l += " --ctdir ";
                l += (dir == direction_t::DIRECTION_ORIGINAL
                            ? "ORIGINAL"
                            : "REPLY");
            }

            line_builder sub_line(line);
            if(force_ipv4)
            {
                sub_line.set_ipv4();
            }
            if(force_ipv6)
            {
                sub_line.set_ipv6();
            }
            sub_line.append_both(l);
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
        line_builder sub_line(line);

        std::string::size_type const slash(f_limits[0].find('/'));
        if(slash != std::string::npos)
        {
            // with a slash, we have a -m limit rate
            // and if there is a second number it's the burst
            //
            std::int64_t rate(0);
            std::string const rate_number(f_limits[0].substr(0, slash));
            if(!advgetopt::validator_integer::convert_string(rate_number, rate))
            {
                SNAP_LOG_ERROR
                    << "the first number in the rule limit must be a valid integer number and a unit separated by a slash (/). \""
                    << f_limits[0]
                    << "\" is not valid."
                    << SNAP_LOG_SEND;
                f_valid = false;
            }
            std::string rate_unit(f_limits[0].substr(slash + 1));
            if(rate_unit != "second"
            && rate_unit != "minute"
            && rate_unit != "hour"
            && rate_unit != "day")
            {
                SNAP_LOG_ERROR
                    << "the rate unit must be one of \"second\", \"minute\", \"hour\", \"day\". \""
                    << f_limits[0]
                    << "\" is not valid."
                    << SNAP_LOG_SEND;
                f_valid = false;
                rate_unit = "second";
            }

            std::int64_t burst(0);
            if(f_limits.size() >= 2)
            {
                if(!advgetopt::validator_integer::convert_string(f_limits[1], burst))
                {
                    SNAP_LOG_ERROR
                        << "the second number in the rule limit must be a valid integer number. \""
                        << f_limits[1]
                        << "\" is not valid."
                        << SNAP_LOG_SEND;
                    f_valid = false;
                }
            }

            if(rate > 0
            || burst > 0)
            {
                sub_line.append_both(" -m limit");
            }
            if(rate > 0)
            {
                sub_line.append_both(" --limit " + std::to_string(rate) + '/' + rate_unit);
            }
            if(burst > 0)
            {
                sub_line.append_both(" --limit-burst " + std::to_string(burst));
            }
        }
        else
        {
            // the connection limits are numbers optionally preceeded by operators
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
        }

        to_iptables_states(result, sub_line);
    }
}


void rule::to_iptables_states(result_builder & result, line_builder const & line)
{
    if(f_states.empty()
    || line.get_protocol().empty())
    {
        to_iptables_recent(result, line);
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

            // tcpmss needs separate handling
            //
            // TODO: make sure that the current protocol is TCP
            // TODO: verify that the chain is PREROUTING or ...
            // TODO: verify that the table is MANGLE
            //
            if(s.get_tcpmss_min() != -1)
            {
                sub_line.append_both(" -m tcpmss");
                if(s.get_tcpmss_negate())
                {
                    sub_line.append_both(" !");
                }
                sub_line.append_both(" --mss " + std::to_string(s.get_tcpmss_min()));
                if(s.get_tcpmss_min() != s.get_tcpmss_max()
                && s.get_tcpmss_max() != -1)
                {
                    sub_line.append_both(':' + std::to_string(s.get_tcpmss_max()));
                }
            }

            // the state may still be optional
            //
            std::string const & protocol(sub_line.get_protocol());
            std::string const state(s.to_iptables_options(protocol, sub_line.is_ipv6()));
            if(!state.empty())
            {
                sub_line.append_both(state);
            }

            to_iptables_recent(result, sub_line);
        }
    }
}


void rule::to_iptables_recent(result_builder & result, line_builder const & line)
{
    if(f_recent.empty())
    {
        to_iptables_comment(result, line);
    }
    else
    {
        line_builder sub_line(line);
        for(auto const & r : f_recent)
        {
            sub_line.append_both(" -m recent");
            if(r.get_negate())
            {
                sub_line.append_both(" !");
            }
            switch(r.get_recent())
            {
            case recent_t::RECENT_SET:
                sub_line.append_both(" --set");
                break;

            case recent_t::RECENT_CHECK:
                sub_line.append_both(" --rcheck");
                break;

            case recent_t::RECENT_UPDATE:
                sub_line.append_both(" --update");
                break;

            case recent_t::RECENT_REMOVE:
                sub_line.append_both(" --remove");
                break;

            default:
                throw iplock::logic_error("added a new recent_t type and did not write the handling in this switch?");

            }

            // there is always a name, if not defined on the command, iptables
            // uses the "DEFAULT" name
            //
            sub_line.append_both(" --name ");
            sub_line.append_both(r.get_name());

            if(r.get_destination())
            {
                sub_line.append_both(" --rdest");
            }
            if(r.get_ttl() > 0)
            {
                sub_line.append_both(" --seconds ");
                sub_line.append_both(std::to_string(r.get_ttl()));
            }
            if(r.get_reap())
            {
                sub_line.append_both(" --reap");
            }
            if(r.get_hitcount() > 0)
            {
                sub_line.append_both(" --hitcount ");
                sub_line.append_both(std::to_string(r.get_hitcount()));
            }
            if(r.get_rttl())
            {
                sub_line.append_both(" --rttl");
            }
            std::int64_t const mask(r.get_mask());
            if(mask > 0
            && mask < 128)
            {
                addr::addr a;
                a.set_mask_count(mask);
                if(!a.is_mask_ipv4_compatible())
                {
                    // mask incompatible with IPv4
                    //
                    sub_line.append_both(" --mask ");
                    sub_line.append_ipv6line(a.to_ipv6_string(addr::STRING_IP_MASK_AS_ADDRESS), true);
                }
                else
                {
                    if(mask == 96)
                    {
                        // no need for --mask 255.255.255.255 in IPv4
                        //
                        line_builder sub_ipv4line(sub_line);
                        sub_ipv4line.append_both(" --mask ");
                        sub_ipv4line.append_ipv4line(a.to_ipv4_string(addr::STRING_IP_MASK_AS_ADDRESS), true);
                        to_iptables_states(result, sub_ipv4line);
                    }
                    else
                    {
                        line_builder sub_ipv4line(sub_line);
                        sub_ipv4line.append_both(" --mask ");
                        sub_ipv4line.append_ipv4line(a.to_ipv4_string(addr::STRING_IP_MASK_AS_ADDRESS), true);
                        to_iptables_states(result, sub_ipv4line);
                    }

                    // no need for --mask 128 in IPv6
                    //
                    sub_line.append_both(" --mask ");
                    sub_line.append_ipv6line(a.to_ipv6_string(addr::STRING_IP_MASK_AS_ADDRESS), true);
                }
            }
        }
        to_iptables_comment(result, sub_line);
    }
}


void rule::to_iptables_comment(result_builder & result, line_builder const & line)
{
    if(f_comment.empty())
    {
        to_iptables_target(result, line);
    }
    else
    {
        line_builder sub_line(line);
        sub_line.append_both(
                  " -m comment --comment \""
                + f_comment
                + "\"");
        to_iptables_target(result, sub_line);
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

    if(f_action != action_t::ACTION_NONE)
    {
        final_line.append_both(" -j " + get_action_name());
    }

    switch(f_action)
    {
    case action_t::ACTION_AUDIT:
        final_line.append_both(" --type " + f_action_param);
        break;

    case action_t::ACTION_CALL:
        // we need to add the name of the user chain to call
        //
        final_line.append_both(f_action_param);
        break;

    case action_t::ACTION_CHECKSUM:
        if(f_action_param == "fill")
        {
            final_line.append_both(" --checksum-fill");
        }
        break;

    case action_t::ACTION_CLASSIFY:
        final_line.append_both(" --set-class " + f_action_param);
        break;

    case action_t::ACTION_CLUSTERIP:
        {
            advgetopt::string_list_t options;
            advgetopt::split_string(f_action_param, options, {","});
            for(auto const & o : options)
            {
                if(o == "new")
                {
                    final_line.append_both(" --new");
                    if(options.size() != 1)
                    {
                        SNAP_LOG_ERROR
                            << "the CLUSTERIP \"new\" must be used by itself."
                            << SNAP_LOG_SEND;
                        f_valid = false;
                    }
                }
                else if(o == "sourceip"
                     || o == "sourceip-sourceport"
                     || o == "sourceip-sourceport-destport")
                {
                    final_line.append_both(" --hashmode " + o);
                }
                else if(o[0] == '+')
                {
                    final_line.append_both(" --total-nodes " + o.substr(1));
                }
                else if(o[0] == '#')
                {
                    final_line.append_both(" --local-node " + o.substr(1));
                }
                else
                {
                    advgetopt::string_list_t mac;
                    advgetopt::split_string(o, mac, {":"});
                    if(mac.size() == 14)
                    {
                        final_line.append_both(" --clustermac " + o);
                    }
                    else
                    {
                        std::int64_t rnd(0);
                        bool const valid(advgetopt::validator_integer::convert_string(o, rnd));
                        if(!valid)
                        {
                            SNAP_LOG_ERROR
                                << "the CLUSTERIP \""
                                << o
                                << "\" option was not recognized."
                                << SNAP_LOG_SEND;
                            f_valid = false;
                        }
                        else
                        {
                            final_line.append_both(" --hash-init " + o);
                        }
                    }
                }
            }
        }
        break;

    case action_t::ACTION_CONNMARK:
        final_line.append_both(" --todo ... " + f_action_param);
        break;

    case action_t::ACTION_CONNSECMARK:
        if(f_action_param == "save"
        || f_action_param == "restore")
        {
            final_line.append_both(" --" + f_action_param);
        }
        else
        {
            SNAP_LOG_ERROR
                << "the CONNSECMARK \""
                << f_action_param
                << "\" option was not recognized."
                << SNAP_LOG_SEND;
            f_valid = false;
        }
        break;

    case action_t::ACTION_CT:
        final_line.append_both(" --todo ... " + f_action_param);
        break;

    case action_t::ACTION_DNAT:
        if(f_action_param == "random")
        {
            final_line.append_both(" --random");
        }
        else if(f_action_param == "persistent")
        {
            final_line.append_both(" --persistent");
        }
        else
        {
            final_line.append_both(" --to-destination " + f_action_param);
        }
        break;

    case action_t::ACTION_DNPT:
        if(!f_action_param.empty())
        {
            if(f_action_param[0] == '>')
            {
                if(f_action_param.length() == 1)
                {
                    final_line.append_both(" --dst-pfx");
                }
                else
                {
                    final_line.append_both(" --dst-pfx " + f_action_param.substr(1));
                }
            }
            else
            {
                if(f_action_param[0] == '<')
                {
                    f_action_param = f_action_param.substr(1);
                }
                if(f_action_param.empty())
                {
                    final_line.append_both(" --src-pfx");
                }
                else
                {
                    final_line.append_both(" --src-pfx " + f_action_param);
                }
            }
        }
        break;

    case action_t::ACTION_DSCP:
        {
            std::int64_t value(0);
            if(advgetopt::validator_integer::convert_string(f_action_param, value))
            {
                final_line.append_both(" --set-dscp " + f_action_param);
            }
            else
            {
                final_line.append_both(" --set-dscp-class " + f_action_param);
            }
        }
        break;

    case action_t::ACTION_ECN:
        if(f_action_param == "remove")
        {
            final_line.append_both(" --enc-tcp-remove");
        }
        break;

    case action_t::ACTION_HL:
        switch(f_action_param[0])
        {
        case '=':
            final_line.append_both(" --hl-set " + f_action_param.substr(1));
            break;

        case '+':
            final_line.append_both(" --hl-inc " + f_action_param.substr(1));
            break;

        case '-':
            final_line.append_both(" --hl-dec " + f_action_param.substr(1));
            break;

        default:
            final_line.append_both(" --hl-set " + f_action_param);
            break;

        }
        break;

    case action_t::ACTION_HMARK:
        final_line.append_both(" --todo " + f_action_param);
        break;

    case action_t::ACTION_IDLETIMER:
        {
            std::int64_t value(0);
            if(advgetopt::validator_integer::convert_string(f_action_param, value))
            {
                final_line.append_both(" --timeout " + f_action_param);
            }
            else
            {
                final_line.append_both(" --label " + f_action_param);
            }
        }
        break;

    case action_t::ACTION_LED:
        {
            advgetopt::string_list_t options;
            advgetopt::split_string(f_action_param, options, {","});
            for(auto const & o : options)
            {
                if(o == "blink")
                {
                    final_line.append_both(" --led-always-blink");
                }
                else
                {
                    double duration(0.0);
                    if(advgetopt::validator_duration::convert_string(
                                  o
                                , advgetopt::validator_duration::VALIDATOR_DURATION_DEFAULT_FLAGS
                                , duration))
                    {
                        final_line.append_both(
                                  " --led-delay "
                                + std::to_string(static_cast<std::int64_t>(floor(duration * 1000.0))));
                    }
                    else
                    {
                        final_line.append_both(" --led-trigger-id " + f_action_param);
                    }
                }
            }
        }
        break;

    case action_t::ACTION_MARK:
        final_line.append_both(" --todo " + f_action_param);
        break;

    case action_t::ACTION_MASQUERADE:
        if(f_action_param == "random")
        {
            final_line.append_both(" --random");
        }
        else if(!f_action_param.empty())
        {
            final_line.append_both(" --to-ports " + f_action_param);
        }
        break;

    case action_t::ACTION_NETMAP:
        final_line.append_both(" --to " + f_action_param);
        break;

    case action_t::ACTION_NFLOG:
        final_line.append_both(" --todo " + f_action_param);
        break;

    case action_t::ACTION_NFQUEUE:
        {
            advgetopt::string_list_t options;
            advgetopt::split_string(f_action_param, options, {","});
            for(auto const & o : options)
            {
                if(o == "bypass")
                {
                    final_line.append_both(" --queue-bypass");
                }
                else if(o == "cpu-fanout")
                {
                    final_line.append_both(" --queue-cpu-fanout");
                }
                else if(o.find(':') == std::string::npos)
                {
                    final_line.append_both(" --queue-num " + f_action_param);
                }
                else
                {
                    final_line.append_both(" --queue-balance " + f_action_param);
                }
            }
        }
        break;

    case action_t::ACTION_RATEEST:
        {
            advgetopt::string_list_t options;
            advgetopt::split_string(f_action_param, options, {","});
            for(auto const & o : options)
            {
                std::int64_t value(0);
                if(advgetopt::validator_integer::convert_string(o, value))
                {
                    final_line.append_both(" --rateest-ewmalog " + f_action_param);
                }
                else
                {
                    double duration(0.0);
                    if(advgetopt::validator_duration::convert_string(
                              o
                            , advgetopt::validator_duration::VALIDATOR_DURATION_DEFAULT_FLAGS
                            , duration))
                    {
                        final_line.append_both(
                                  " --rateest-intervalf "
                                + std::to_string(static_cast<std::int64_t>(floor(duration * 1000'000.0)))
                                + "us");
                    }
                    else
                    {
                        final_line.append_both(" --rateest-name " + f_action_param);
                    }
                }
            }
        }
        break;

    case action_t::ACTION_REDIRECT:
        if(f_action_param == "random")
        {
            final_line.append_both(" --random");
        }
        else
        {
            final_line.append_both(" --to-port " + f_action_param);
        }
        break;

    case action_t::ACTION_REJECT:
        if(!f_action_param.empty())
        {
            final_line.append_ipv4line(" --reject-with " + f_action_param);
        }
        if(!f_action_param2.empty())
        {
            final_line.append_ipv6line(" --reject-with " + f_action_param2);
        }
        break;

    case action_t::ACTION_SECMARK:
        final_line.append_both(" --selctx " + f_action_param);
        break;

    case action_t::ACTION_SET:
        final_line.append_both(" --todo " + f_action_param);
        break;

    case action_t::ACTION_SNAT:
        if(f_action_param == "persistent")
        {
            final_line.append_both(" --persistent");
        }
        else if(f_action_param == "random")
        {
            final_line.append_both(" --random");
        }
        else if(f_action_param == "random-fully"
             || f_action_param == "fully-random")
        {
            final_line.append_both(" --random-fully");
        }
        else
        {
            final_line.append_both(" --to-source " + f_action_param);
        }
        break;

    case action_t::ACTION_SNPT:
        if(!f_action_param.empty())
        {
            if(f_action_param[0] == '>')
            {
                if(f_action_param.length() == 1)
                {
                    final_line.append_both(" --dst-pfx");
                }
                else
                {
                    final_line.append_both(" --dst-pfx " + f_action_param.substr(1));
                }
            }
            else
            {
                if(f_action_param[0] == '<')
                {
                    f_action_param = f_action_param.substr(1);
                }
                if(f_action_param.empty())
                {
                    final_line.append_both(" --src-pfx");
                }
                else
                {
                    final_line.append_both(" --src-pfx " + f_action_param);
                }
            }
        }
        break;

    case action_t::ACTION_SYNPROXY:
        final_line.append_both(" --todo " + f_action_param);
        break;

    case action_t::ACTION_TCPMSS:
        if(f_action_param == "clamp")
        {
            final_line.append_both(" --clamp-mss-to-pmtu");
        }
        else
        {
            final_line.append_both(" --set-mss " + f_action_param);
        }
        break;

    case action_t::ACTION_TCPOPTSTRIP:
        if(!f_action_param.empty())
        {
            final_line.append_both(" --strip-options " + f_action_param);
        }
        break;

    case action_t::ACTION_TEE:
        if(!f_action_param.empty())
        {
            final_line.append_both(" --gateway " + f_action_param);
        }
        break;

    case action_t::ACTION_TOS:
        final_line.append_both(" --todo " + f_action_param);
        break;

    case action_t::ACTION_TPROXY:
        {
            advgetopt::string_list_t options;
            advgetopt::split_string(f_action_param, options, {","});
            for(auto const & o : options)
            {
                std::int64_t value(0);
                if(advgetopt::validator_integer::convert_string(o, value))
                {
                    final_line.append_both(" --on-port " + f_action_param);
                }
                else
                {
                    if(o.find('/') == std::string::npos)
                    {
                        final_line.append_both(" --tproxy-mark " + f_action_param);
                    }
                    else
                    {
                        final_line.append_both(" --on-ip " + f_action_param);
                    }
                }
            }
        }
        break;

    case action_t::ACTION_TTL:
        switch(f_action_param[0])
        {
        case '=':
            final_line.append_both(" --ttl-set " + f_action_param.substr(1));
            break;

        case '+':
            final_line.append_both(" --ttl-inc " + f_action_param.substr(1));
            break;

        case '-':
            final_line.append_both(" --ttl-dec " + f_action_param.substr(1));
            break;

        default:
            final_line.append_both(" --ttl-set " + f_action_param);
            break;

        }
        break;

    case action_t::ACTION_ULOG:
        final_line.append_both(" --todo " + f_action_param);
        break;

    default:
        break;

    }
    final_line.append_both("\n");

    result.append_line(final_line);
}


// vim: ts=4 sw=4 et
