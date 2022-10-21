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
#include    "table.h"


// advgetopt
//
#include    <advgetopt/advgetopt.h>
//#include    <advgetopt/conf_file.h>



class ipload
{
public:
    static constexpr int    COMMAND_FLUSH             = 0x0001;
    static constexpr int    COMMAND_LOAD              = 0x0002;
    static constexpr int    COMMAND_LOAD_BASIC        = 0x0004;
    static constexpr int    COMMAND_LOAD_DEFAULT      = 0x0008;
    static constexpr int    COMMAND_SHOW              = 0x0010;
    static constexpr int    COMMAND_SHOW_DEPENDENCIES = 0x0020;
    static constexpr int    COMMAND_VERIFY            = 0x0040;

                            ipload(int argc, char * argv[]);

    int                     run();

private:
    void                    make_root();
    bool                    load_data();
    void                    load_basic(bool force);
    bool                    create_sets();
    bool                    remove_from_iptables();
    bool                    load_to_iptables(std::string const & flag_name);
    void                    show();
    void                    show_dependencies();
    void                    load_conf_file(
                                  std::string const & filename
                                , advgetopt::conf_file::parameters_t & config_params);
    void                    create_defaults();
    bool                    convert();
    bool                    process_parameters();
    bool                    sort_sections(section::vector_t & sections);
    bool                    process_chains(chain::map_t const & chains);
    bool                    process_sections(section::vector_t const & sections);
    bool                    process_rules(rule::vector_t rules);
    bool                    generate_tables(std::ostream & out);
    bool                    generate_chain_name(std::ostream & out, chain_reference::pointer_t c);
    bool                    generate_chain(std::ostream & out, chain_reference::pointer_t c);
    bool                    generate_rules(
                                  std::ostream & out
                                , chain_reference::pointer_t c
                                , section_reference::pointer_t s
                                , int & count);
    bool                    sort_rules();
    int                     count_levels(section::vector_t const & dependencies, section::pointer_t section);

    advgetopt::getopt       f_opts;
    bool                    f_verbose = false;
    bool                    f_quiet = false;
    bool                    f_show_comments = false;
    bool                    f_show_descriptions = false;
    bool                    f_show_dependencies = false;
    bool                    f_output_empty_tables = false;
    int                     f_command = 0;
    advgetopt::variables::pointer_t
                            f_variables = advgetopt::variables::pointer_t();
    advgetopt::variables::pointer_t
                            f_verify = advgetopt::variables::pointer_t();
    advgetopt::conf_file::parameters_t
                            f_parameters = advgetopt::conf_file::parameters_t();
    table::map_t            f_tables = table::map_t();
    table::pointer_t        f_generate_for_table = table::pointer_t();
    std::string             f_log_introducer = "[iptables]";
    std::string             f_remove_user_chain = std::string();
    std::string             f_create_set = std::string();
    std::string             f_create_set_ipv4 = std::string();
    std::string             f_create_set_ipv6 = std::string();
    std::string             f_add_to_set = std::string();
    std::string             f_add_to_set_ipv4 = std::string();
    std::string             f_add_to_set_ipv6 = std::string();
    std::string             f_load_to_set = std::string();
    std::string             f_load_to_set_ipv4 = std::string();
    std::string             f_load_to_set_ipv6 = std::string();
    std::string             f_output = std::string();
};



// vim: ts=4 sw=4 et
