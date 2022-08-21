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
#include    "command.h"



namespace tool
{



typedef std::vector<uint16_t> port_list_t;



class scheme
    : public command
{
public:
                                    scheme(
                                          iplock * parent
                                        , char const * command_name
                                        , advgetopt::getopt::pointer_t opts
                                        , std::string const & scheme_name = std::string());

    std::string                     get_command(std::string const & name) const;
    std::string                     get_scheme_string(std::string const & name) const;

    port_list_t const &             get_ports() const;

    virtual void                    run() override;

protected:
    std::string                     f_scheme = "http";
    advgetopt::getopt::pointer_t    f_scheme_opts = advgetopt::getopt::pointer_t();
    port_list_t                     f_ports = port_list_t();
};



} // namespace tool
// vim: ts=4 sw=4 et
