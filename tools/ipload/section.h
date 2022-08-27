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



class section
{
public:
    typedef std::shared_ptr<section>    pointer_t;
    typedef std::vector<pointer_t>      vector_t;
    typedef std::map<std::string, pointer_t>
                                        map_t;

                                        section(
                                              advgetopt::conf_file::parameters_t::iterator & it
                                            , advgetopt::conf_file::parameters_t const & config_params
                                            , advgetopt::variables::pointer_t variables);

    bool                                is_valid() const;
    void                                mark_invalid();

    std::string const &                 get_name() const;
    advgetopt::string_list_t const &    get_before() const;
    advgetopt::string_list_t const &    get_after() const;
    bool                                get_default() const;

private:
    std::string                         f_name = std::string();
    advgetopt::string_list_t            f_before = advgetopt::string_list_t();
    advgetopt::string_list_t            f_after = advgetopt::string_list_t();
    bool                                f_default = false;
    bool                                f_valid = true;
};



// vim: ts=4 sw=4 et
