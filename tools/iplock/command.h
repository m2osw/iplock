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
#include    <advgetopt/advgetopt.h>



namespace tool
{



class iplock;



class command
{
public:
    typedef std::shared_ptr<command> pointer_t;

                        command(
                              iplock * parent
                            , char const * command_name
                            , advgetopt::getopt::pointer_t opts);
                        command(command const & rhs) = delete;
    virtual             ~command();

    command &           operator = (command const & rhs) = delete;

    virtual void        run() = 0;

    int                 exit_code() const;

protected:
    void                verify_ip(std::string const & ip);

    iplock *                        f_iplock = nullptr; // just in case, unused at this time...
    advgetopt::getopt::pointer_t    f_opts = advgetopt::getopt::pointer_t();
    advgetopt::getopt::pointer_t    f_iplock_opts = advgetopt::getopt::pointer_t();
    std::string                     f_chain = std::string("unwanted");
    std::string                     f_interface = std::string("eth0");
    bool const                      f_quiet;  // since it is const, you must specify it in the constructor
    bool const                      f_verbose;  // since it is const, you must specify it in the constructor
    int                             f_exit_code = 0;
};



} // namespace tool
// vim: ts=4 sw=4 et
