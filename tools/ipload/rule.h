// Copyright (c) 2014-2022  Made to Order Software Corp.  All Rights Reserved
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
#pragma once

/** \file
 * \brief Various definition of the iplock tool.
 *
 * The iplock is an object used to execute the command line instructions
 * as passed by the administrator.
 *
 * Depending on the command the system also loads configuration files
 * using the advgetopt library.
 */


// advgetopt
//
#include    <advgetopt/conf_file.h>



enum class action_t
{
    ACTION_UNDEFINED,
    ACTION_ACCEPT,
    ACTION_CALL,
    ACTION_DNAT,
    ACTION_DROP,
    ACTION_LOG,
    ACTION_MASQUERADE,
    ACTION_REDIRECT,
    ACTION_REJECT,
    ACTION_RETURN,
    ACTION_SNAT,
};


class rule
{
public:
    typedef std::shared_ptr<rule>       pointer_t;
    typedef std::vector<pointer_t>      vector_t;

                                        rule(
                                              advgetopt::conf_file::parameters_t::iterator & it
                                            , advgetopt::conf_file::parameters_t const & config_params
                                            , advgetopt::variables::pointer_t variables);

    bool                                is_valid() const;

    std::string const &                 get_name() const;
    advgetopt::string_list_t const &    get_chains() const;
    std::string const &                 get_section() const;
    advgetopt::string_list_t const &    get_before() const;
    advgetopt::string_list_t const &    get_after() const;
    std::string const &                 get_condition() const;        // TBD: what is that already?!

    advgetopt::string_list_t const &    get_source_interfaces() const;
    advgetopt::string_list_t const &    get_sources() const;
    advgetopt::string_list_t const &    get_except_sources() const;
    advgetopt::string_list_t const &    get_source_ports() const;

    advgetopt::string_list_t const &    get_destination_interfaces() const;
    advgetopt::string_list_t const &    get_destinations() const;
    advgetopt::string_list_t const &    get_except_destinations() const;
    advgetopt::string_list_t const &    get_destination_ports() const;

    advgetopt::string_list_t const &    get_protocols() const;
    advgetopt::string_list_t const &    get_states() const;
    bool                                includes_state(std::string const & name) const;
    advgetopt::string_list_t const &    get_limits() const;

    action_t                            get_action() const;
    std::string                         get_action_name() const;
    std::string const &                 get_log() const;

    void                                set_log_introducer(std::string const & introducer);
    std::string                         to_iptables_rules(std::string const & chain_name);

private:
    void                                parse_action(std::string const & action);
    void                                to_iptables_destination_interfaces(std::string & result, std::string const & line);
    void                                to_iptables_protocols(std::string & result, std::string const & line);
    void                                to_iptables_sources(std::string & result, std::string const & line);
    void                                to_iptables_source_ports(std::string & result, std::string const & line);
    void                                to_iptables_destinations(std::string & result, std::string const & line);
    void                                to_iptables_destination_ports(std::string & result, std::string const & line);
    void                                to_iptables_limits(std::string & result, std::string const & line);
    void                                to_iptables_states(std::string & result, std::string const & line);
    void                                to_iptables_target(std::string & result, std::string const & line);

    std::string                         f_name = std::string();
    bool                                f_valid = true;

    advgetopt::string_list_t            f_chains = advgetopt::string_list_t();
    std::string                         f_section = std::string();
    advgetopt::string_list_t            f_before = advgetopt::string_list_t();
    advgetopt::string_list_t            f_after = advgetopt::string_list_t();
    std::string                         f_condition = std::string();        // TBD: what is that already?! a JS expression against our variables?

    advgetopt::string_list_t            f_source_interfaces = advgetopt::string_list_t();
    advgetopt::string_list_t            f_sources = advgetopt::string_list_t();
    advgetopt::string_list_t            f_except_sources = advgetopt::string_list_t();
    advgetopt::string_list_t            f_source_ports = advgetopt::string_list_t();

    advgetopt::string_list_t            f_destination_interfaces = advgetopt::string_list_t();
    advgetopt::string_list_t            f_destinations = advgetopt::string_list_t();
    advgetopt::string_list_t            f_except_destinations = advgetopt::string_list_t();
    advgetopt::string_list_t            f_destination_ports = advgetopt::string_list_t();

    advgetopt::string_list_t            f_protocols = advgetopt::string_list_t();
    advgetopt::string_list_t            f_states = advgetopt::string_list_t();
    advgetopt::string_list_t            f_limits = advgetopt::string_list_t();

    action_t                            f_action = action_t::ACTION_UNDEFINED;
    std::string                         f_action_param = std::string();     // REJECT [<type>] or CALL <chain-name>
    std::string                         f_log = std::string();
    std::string                         f_log_introducer = "[iptables]";
};



// vim: ts=4 sw=4 et
