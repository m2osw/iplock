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

// advgetopt
//
#include    <advgetopt/advgetopt.h>


// libaddr
//
#include    <libaddr/addr.h>



namespace tool
{



class controller;



class command
{
public:
    typedef std::shared_ptr<command> pointer_t;

                        command(
                              controller * parent
                            , char const * command_name);
                        command(command const & rhs) = delete;
    virtual             ~command();

    command &           operator = (command const & rhs) = delete;

    virtual void        run() = 0;

    virtual bool        needs_root() const;
    std::string const & get_command_name() const;
    int                 exit_code() const;

protected:
    std::string &       get_set_name();

    controller *                    f_controller = nullptr; // just in case, unused at this time...
    std::string                     f_command_name = std::string();
    advgetopt::getopt::pointer_t    f_iplock_config = advgetopt::getopt::pointer_t();
    advgetopt::string_list_t        f_allowed_set_names = advgetopt::string_list_t();
    std::string                     f_set_name = std::string();
    bool const                      f_quiet;
    bool const                      f_verbose;
    int                             f_exit_code = 0;
};



} // namespace tool
// vim: ts=4 sw=4 et
