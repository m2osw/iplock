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


enum class type_t
{
    TYPE_RETURN,
    TYPE_DROP,
    TYPE_USER_DEFINED,
};


class chain
{
public:
                                    chain(
                                          advgetopt::conf_file::parameters_t::iterator name
                                        , advgetopt::conf_file::parameters_t const & config_params
                                        , advgetopt::variables::pointer_t variables);

    bool                            is_valid() const;
    void                            add_section_reference(section_reference::pointer_t section_reference);
    section_reference::vector_t const &
                                    get_section_references() const;

private:
    std::string                     f_name = std::string();
    policy_t                        f_policy = policy_t::POLICY_DROP;
    type_t                          f_type = type_t::TYPE_DROP; // this should be RETURN for a user defined chain
    std::string                     f_log = std::string();
    section_reference::vector_t     f_section_references = section_reference::vector_t();
    bool                            f_valid = true;
};



// vim: ts=4 sw=4 et
