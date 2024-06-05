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
 * \brief The iplock tool class.
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



extern char const * const   g_suffixes[];



class controller
{
public:
                            controller(int argc, char * argv[]);

    advgetopt::getopt &     opts();
    int                     run_command();

private:
    void                    set_command(command::pointer_t c);
    bool                    make_root();

    advgetopt::getopt       f_opts;
    bool                    f_verbose = false;
    bool                    f_quiet = false;
    command::pointer_t      f_command = command::pointer_t();
};



} // namespace tool
// vim: ts=4 sw=4 et
