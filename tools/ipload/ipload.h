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
#include    <advgetopt/conf_file.h>



class ipload
{
public:
    static constexpr int    COMMAND_LOAD   = 0x0001;
    static constexpr int    COMMAND_SHOW   = 0x0002;
    static constexpr int    COMMAND_VERIFY = 0x0004;

                            ipload(int argc, char * argv[]);

    int                     run();

private:
    void                    make_root();
    bool                    load_data();
    void                    load_basic();
    void                    load_to_iptables();
    void                    show();
    void                    load_config(std::string const & filename);
    void                    load_conf_file(
                                  std::string const & filename
                                , advgetopt::conf_file::parameters_t config_params);
    void                    add_params(advgetopt::conf_file::parameters_t config_params);
    void                    create_defaults();

    advgetopt::getopt       f_opts;
    bool                    f_verbose = false;
    bool                    f_quiet = false;
    int                     f_command = 0;
    advgetopt::variables::pointer_t
                            f_variables = advgetopt::variables::pointer_t();
    advgetopt::conf_file::sections_t
                            f_sections = advgetopt::conf_file::sections_t();
    advgetopt::conf_file::parameters_t
                            f_parameters = advgetopt::conf_file::parameters_t();
};



// vim: ts=4 sw=4 et
