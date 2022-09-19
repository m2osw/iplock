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


// self
//
#include    "state_result.h"


// libaddr
//
#include    <libaddr/addr_range.h>


// advgetopt
//
#include    <advgetopt/conf_file.h>



enum class action_t
{
    ACTION_UNDEFINED,
    ACTION_NONE,            // no -j (for things like -m recent)
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
    bool                                empty() const;

    std::string const &                 get_name() const;
    advgetopt::string_list_t const &    get_chains() const;
    std::string const &                 get_section() const;
    advgetopt::string_list_t const &    get_before() const;
    advgetopt::string_list_t const &    get_after() const;
    void                                add_after(std::string const & after);
    bool                                get_condition() const;

    advgetopt::string_list_t const &    get_set() const;
    advgetopt::string_list_t const &    get_source_interfaces() const;
    //advgetopt::string_list_t const &    get_sources() const;
    //advgetopt::string_list_t const &    get_except_sources() const;
    advgetopt::string_list_t const &    get_source_ports() const;

    advgetopt::string_list_t const &    get_destination_interfaces() const;
    //advgetopt::string_list_t const &    get_destinations() const;
    //advgetopt::string_list_t const &    get_except_destinations() const;
    advgetopt::string_list_t const &    get_destination_ports() const;

    advgetopt::string_list_t const &    get_protocols() const;
    state_result::vector_t const &      get_states() const;
    advgetopt::string_list_t const &    get_limits() const;

    action_t                            get_action() const;
    std::string                         get_action_name() const;
    std::string const &                 get_log() const;
    void                                set_log_introducer(std::string const & introducer);

    void                                add_dependency(pointer_t s);
    vector_t const &                    get_dependencies() const;
    int                                 get_level() const;
    void                                set_level(int level);

    std::string                         to_iptables_rules(std::string const & chain_name);

private:
    class result_builder;
    class line_builder;
    typedef std::function<void(result_builder &, line_builder const &)>
                                        to_iptables_func_t;

    class line_builder
    {
    public:
        explicit            line_builder(std::string const & chain_name);

        line_builder &      operator = (line_builder const &) = delete;

        std::string         get_chain_name() const;
        std::string         get_add_chain() const;
        bool                is_chain_name(char const * chain_name) const;
        void                set_protocol(std::string const & protocol);
        std::string const & get_protocol() const;

        void                set_ipv4();
        bool                is_ipv4() const;
        void                set_ipv6();
        bool                is_ipv6() const;

        void                append_ipv4line(std::string const & s, bool set = false);
        void                append_ipv6line(std::string const & s, bool set = false);
        void                append_both(std::string const & s);

        std::string const & get_ipv4line() const;
        std::string const & get_ipv6line() const;

        void                set_next_func(to_iptables_func_t f);
        to_iptables_func_t  get_next_func() const;

    private:
        // if f_ipv4/6 is true then anything else on that line has to match
        // there is no choice here (i.e. if an ipv4 address is used then we
        // add that to the ipv4 firewall and not ipv6 and vice versa)
        //
        bool                f_ipv4 = false;
        bool                f_ipv6 = false;
        std::string         f_generating_for_chain_name = std::string();
        std::string         f_generating_for_protocol = std::string();

        std::string         f_ipv4line = std::string();
        std::string         f_ipv6line = std::string();
        to_iptables_func_t  f_next_func = to_iptables_func_t();
    };

    class result_builder
    {
    public:
        void                append_line(line_builder const & line);

        std::string const & get_result() const;

    private:
        std::string         f_result = std::string();
    };

    void                                parse_action(std::string const & action);
    void                                parse_addresses(
                                              advgetopt::string_list_t const & in
                                            , addr::addr::vector_t & addresses
                                            , addr::addr_range::vector_t & range);
    bool                                parse_expression(std::string const & expression);
    void                                parse_reject_action();

    void                                to_iptables_source_interfaces(result_builder & result, line_builder const & line);
    void                                to_iptables_destination_interfaces(result_builder & result, line_builder const & line);
    void                                to_iptables_interfaces(result_builder & result, line_builder const & line);
    void                                to_iptables_protocols(result_builder & result, line_builder const & line);
    void                                to_iptables_sources(result_builder & result, line_builder const & line);
    void                                to_iptables_source_ports(result_builder & result, line_builder const & line);
    void                                to_iptables_destinations(result_builder & result, line_builder const & line);
    void                                to_iptables_knocks(result_builder & result, line_builder const & line);
    void                                to_iptables_destination_ports(result_builder & result, line_builder const & line);
    void                                to_iptables_set(result_builder & result, line_builder const & line);
    void                                to_iptables_limits(result_builder & result, line_builder const & line);
    void                                to_iptables_states(result_builder & result, line_builder const & line);
    void                                to_iptables_comment(result_builder & result, line_builder const & line);
    void                                to_iptables_target(result_builder & result, line_builder const & line);

    std::string                         f_name = std::string();
    std::string                         f_description = std::string();
    bool                                f_valid = true;

    advgetopt::string_list_t            f_chains = advgetopt::string_list_t();
    std::string                         f_section = std::string();
    advgetopt::string_list_t            f_before = advgetopt::string_list_t();
    advgetopt::string_list_t            f_after = advgetopt::string_list_t();
    vector_t                            f_dependencies = vector_t();
    int                                 f_level = 0;
    bool                                f_condition = true;
    bool                                f_force_ipv4 = false;
    bool                                f_force_ipv6 = false;

    advgetopt::string_list_t            f_interfaces = advgetopt::string_list_t();

    advgetopt::string_list_t            f_set = advgetopt::string_list_t();
    advgetopt::string_list_t            f_source_interfaces = advgetopt::string_list_t();
    addr::addr::vector_t                f_sources = addr::addr::vector_t();
    addr::addr_range::vector_t          f_source_ranges = addr::addr_range::vector_t();
    addr::addr::vector_t                f_except_sources = addr::addr::vector_t();
    addr::addr_range::vector_t          f_except_source_ranges = addr::addr_range::vector_t();
    advgetopt::string_list_t            f_source_ports = advgetopt::string_list_t();
    advgetopt::string_list_t            f_knock_ports = advgetopt::string_list_t();

    advgetopt::string_list_t            f_destination_interfaces = advgetopt::string_list_t();
    addr::addr::vector_t                f_destinations = addr::addr::vector_t();
    addr::addr_range::vector_t          f_destination_ranges = addr::addr_range::vector_t();
    addr::addr::vector_t                f_except_destinations = addr::addr::vector_t();
    addr::addr_range::vector_t          f_except_destination_ranges = addr::addr_range::vector_t();
    advgetopt::string_list_t            f_destination_ports = advgetopt::string_list_t();

    advgetopt::string_list_t            f_protocols = advgetopt::string_list_t();
    state_result::vector_t              f_states = state_result::vector_t();
    advgetopt::string_list_t            f_limits = advgetopt::string_list_t();

    action_t                            f_action = action_t::ACTION_UNDEFINED;
    std::string                         f_action_param = std::string();     // REJECT [<type>] or CALL <chain-name>
    std::string                         f_comment = std::string();
    std::string                         f_log = std::string();
    std::string                         f_log_introducer = "[iptables]";
};



// vim: ts=4 sw=4 et
