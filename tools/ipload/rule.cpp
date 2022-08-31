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
#include    <snapdev/string_replace_many.h>


// C
//
#include    <string.h>


// last include
//
#include    <snapdev/poison.h>



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
        throw iplock::logic_error("the rule name \"" + it->first + "\" is expected to be exactly three names: \"rule::<name>::<parameter>\"");
    }

    // this is the name of the rule
    //
    // it is used by the ipload tool to sort the rules between each others
    // using the list of names in the before & after parameters
    //
    f_name = advgetopt::option_with_underscores(name_list[1]);

    std::string const complete_namespace("rule::" + name_list[1] + "::");
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
                advgetopt::split_string(value, f_destinations, {","});
            }
            else if(param_name == "destination-port"
                 || param_name == "destination-ports")
            {
                advgetopt::split_string(value, f_destination_ports, {","});
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
                advgetopt::split_string(value, f_except_destinations, {","});
            }
            else if(param_name == "except-source"
                 || param_name == "except-sources")
            {
                advgetopt::split_string(value, f_except_sources, {","});
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
            else if(param_name == "source-interface"
                 || param_name == "source-interfaces")
            {
                advgetopt::split_string(value, f_source_interfaces, {","});
                list_to_lower(f_source_interfaces);
            }
            else if(param_name == "source"
                 || param_name == "sources")
            {
                advgetopt::split_string(value, f_sources, {","});
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
    && !f_sources.empty())
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


bool rule::get_condition() const
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


/** \brief Generate the iptables rules.
 *
 * This function recursively goes through all the data found in this rule
 * and generate the corresponding code for the iptables-restore command.
 *
 * \todo
 * Work on generating rules for both: iptables and ip6tables.
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
    f_generating_for_chain_name = chain_name;

    std::string result;
    std::string line;

    line += "-A " + chain_name;

    if(f_source_interfaces.empty())
    {
        to_iptables_destination_interfaces(result, line);
    }
    else
    {
        for(auto const & s : f_source_interfaces)
        {
            to_iptables_destination_interfaces(result, line + " -i " + s);
        }
    }

    return result;
}


void rule::to_iptables_destination_interfaces(std::string & result, std::string const & line)
{
    if(f_destination_interfaces.empty())
    {
        to_iptables_interfaces(result, line);
    }
    else
    {
        for(auto const & s : f_destination_interfaces)
        {
            to_iptables_interfaces(result, line + " -o " + s);
        }
    }
}


void rule::to_iptables_interfaces(std::string & result, std::string const & line)
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
        if(f_generating_for_chain_name == "OUTPUT")
        {
            in_out = IN_OUT_OUT;
        }
        else if(f_generating_for_chain_name == "FORWARD")
        {
            in_out = IN_OUT_IN | IN_OUT_OUT;
        }
        switch(in_out)
        {
        case IN_OUT_IN:
        case 0:     // for all others, the input is the default
            for(auto const & s : f_interfaces)
            {
                to_iptables_protocols(result, line + " -i " + s);
            }
            break;

        case IN_OUT_OUT:
            for(auto const & s : f_interfaces)
            {
                to_iptables_protocols(result, line + " -o " + s);
            }
            break;

        case IN_OUT_IN | IN_OUT_OUT:
            for(auto const & s : f_interfaces)
            {
                to_iptables_protocols(result, line + " -i " + s + " -o " + s);
            }
            break;

        }
    }
}


void rule::to_iptables_protocols(std::string & result, std::string const & line)
{
    if(f_protocols.empty())
    {
        f_generating_for_protocol = "";
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
            std::string l(line + " -p " + s);
            if(is_established_related)
            {
                l += " -m state --state ESTABLISHED,RELATED";
            }
            if(f_source_ports.size() > 1
            || f_destination_ports.size() > 1)
            {
                l += " -m multiport";
            }
            f_generating_for_protocol = s;
            to_iptables_sources(result, l + " -m " + s);
        }
    }
}


void rule::to_iptables_sources(std::string & result, std::string const & line)
{
    if(f_sources.empty())
    {
        if(f_except_sources.empty())
        {
            to_iptables_source_ports(result, line);
        }
        else
        {
            for(auto const & s : f_except_sources)
            {
                to_iptables_source_ports(result, line + " ! -s " + s);
            }
        }
    }
    else
    {
        for(auto const & s : f_sources)
        {
            to_iptables_source_ports(result, line + " -s " + s);
        }
    }
}


void rule::to_iptables_source_ports(std::string & result, std::string const & line)
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
            to_iptables_destinations(result, line + " --sport " + f_source_ports[0]);
        }
        else
        {
            // the maximum number of ports with -m multiport is 15 so here
            // we have to generate blocks of 15 or less
            //
            for(std::size_t idx(0); idx < f_source_ports.size(); idx += 15)
            {
                std::string l(line + " --sports ");
                std::size_t const max(std::min(idx + 15, f_source_ports.size()));
                for(std::size_t p(idx); p < max; ++p)
                {
                    if(p != idx)
                    {
                        l += ',';
                    }
                    l += f_source_ports[p];
                }
                to_iptables_destinations(result, l);
            }
        }
    }
}


void rule::to_iptables_destinations(std::string & result, std::string const & line)
{
    if(f_destinations.empty())
    {
        if(f_except_destinations.empty())
        {
            to_iptables_destination_ports(result, line);
        }
        else
        {
            for(auto const & s : f_except_destinations)
            {
                to_iptables_destination_ports(result, line + " ! -d " + s);
            }
        }
    }
    else
    {
        for(auto const & s : f_destinations)
        {
            if(s == "any")
            {
                // TODO: once I have ip6tables we need to use '::' here
                //
                to_iptables_destination_ports(result, line + " -d 0.0.0.0");
            }
            else
            {
                to_iptables_destination_ports(result, line + " -d " + s);
            }
        }
    }
}


void rule::to_iptables_destination_ports(std::string & result, std::string const & line)
{
    if(f_destination_ports.empty())
    {
        to_iptables_limits(result, line);
    }
    else
    {
        if(f_destination_ports.size() == 1)
        {
            // for just one port, use --dport
            //
            to_iptables_limits(result, line + " --dport " + f_destination_ports[0]);
        }
        else
        {
            // the maximum number of ports with -m multiport is 15 so here
            // we have to generate blocks of 15 or less
            //
            for(std::size_t idx(0); idx < f_destination_ports.size(); idx += 15)
            {
                std::string l(line + " --dports ");
                std::size_t const max(std::min(idx + 15, f_destination_ports.size()));
                for(std::size_t p(idx); p < max; ++p)
                {
                    if(p != idx)
                    {
                        l += ',';
                    }
                    l += f_destination_ports[p];
                }
                to_iptables_limits(result, l);
            }
        }
    }
}


void rule::to_iptables_limits(std::string & result, std::string const & line)
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

        std::string l(line);
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

        to_iptables_states(result, l);
    }
}


void rule::to_iptables_states(std::string & result, std::string const & line)
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

            to_iptables_target(result, line + s.to_iptables_options(f_generating_for_protocol));
        }
    }
}


void rule::to_iptables_target(std::string & result, std::string const & line)
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
        if(prefix.length() > 28)
        {
            prefix = prefix.substr(0, 28);
        }
        prefix += ':';

        result += line
                + " -j LOG --log-prefix \""
                + prefix
                + "\" --log-uid\n";
    }

    if(f_action == action_t::ACTION_LOG)
    {
        // user only wanted a LOG, so we're done
        //
        return;
    }

    result += line + " -j " + get_action_name();

    switch(f_action)
    {
    case action_t::ACTION_CALL:
        // we need to add the name of the user chain to call
        //
        result += f_action_param;
        break;

    case action_t::ACTION_DNAT:
        result += " --to-destination " + f_action_param;
        break;

    case action_t::ACTION_REDIRECT:
        result += " --to-port " + f_action_param;
        break;

    case action_t::ACTION_REJECT:
        if(!f_action_param.empty())
        {
            result += " --reject-with " + f_action_param;
        }
        break;

    case action_t::ACTION_SNAT:
        result += " --to-source " + f_action_param;
        break;

    default:
        break;

    }
    result += '\n';
}



// vim: ts=4 sw=4 et
