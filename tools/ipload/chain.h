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
#include    "section_reference.h"



enum class policy_t
{
    POLICY_ACCEPT,
    POLICY_DROP,
};

typedef std::map<std::string, policy_t>     policy_map_t;


enum class type_t
{
    TYPE_RETURN,
    TYPE_DROP,
    TYPE_REJECT,
    TYPE_USER_DEFINED,
};

typedef std::map<std::string, type_t>       type_map_t;



class chain
{
public:
    typedef std::shared_ptr<chain>              pointer_t;
    typedef std::vector<pointer_t>              vector_t;
    typedef std::map<std::string, pointer_t>    map_t;

                                        chain(
                                              advgetopt::conf_file::parameters_t::iterator & it
                                            , advgetopt::conf_file::parameters_t const & config_params
                                            , advgetopt::variables::pointer_t variables
                                            , bool verbose);

    bool                                is_valid() const;

    std::string const &                 get_name() const;
    std::string const &                 get_exact_name() const;
    bool                                get_condition() const;
    policy_t                            get_policy(std::string const & table_name) const;
    std::string                         get_policy_name(std::string const & table_name) const;
    type_t                              get_type(std::string const & table_name) const;
    advgetopt::string_list_t const &    get_tables() const;
    std::string const &                 get_log() const;
    bool                                is_system_chain() const;
    bool                                is_verbose() const;

private:
    std::string                         f_name = std::string();
    std::string                         f_exact_name = std::string();
    std::string                         f_description = std::string();
    policy_map_t                        f_policy = policy_map_t();
    type_map_t                          f_type = type_map_t();
    advgetopt::string_list_t            f_tables = advgetopt::string_list_t();
    std::string                         f_log = std::string();
    bool                                f_valid = true;
    bool                                f_is_system_chain = false;
    bool                                f_verbose = false;
    bool                                f_condition = true;
};



// vim: ts=4 sw=4 et
