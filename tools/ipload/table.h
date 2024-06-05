// Copyright (c) 2014-2024  Made to Order Software Corp.  All Rights Reserved
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
#include    "chain_reference.h"



class table
{
public:
    typedef std::shared_ptr<table>              pointer_t;
    typedef std::vector<pointer_t>              vector_t;
    typedef std::map<std::string, pointer_t>    map_t;

                                        table(
                                              advgetopt::conf_file::parameters_t::iterator & it
                                            , advgetopt::conf_file::parameters_t const & config_params
                                            , advgetopt::variables::pointer_t variables);

    bool                                is_valid() const;
    bool                                empty() const;
    std::string                         get_name() const;
    std::string                         get_description() const;

    void                                add_chain_reference(chain_reference::pointer_t c);
    chain_reference::pointer_t          get_chain_reference(std::string const & name) const;
    chain_reference::map_t const &      get_chain_references() const;

private:
    bool                                f_valid = false;
    std::string                         f_name = std::string();
    std::string                         f_description = std::string();
    chain_reference::map_t              f_chain_references = chain_reference::map_t();
};



// vim: ts=4 sw=4 et
