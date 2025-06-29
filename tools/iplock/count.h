// Copyright (c) 2014-2025  Made to Order Software Corp.  All Rights Reserved
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



class count
    : public command
{
public:
                                    count(controller * parent);
    virtual                         ~count() override;

    virtual void                    run() override;

private:
    addr::addr                      parse_ip(std::string const & ip);

    bool const                      f_reset;  // since it is const, you must specify it in the constructor
    //advgetopt::getopt::pointer_t    f_count_opts = advgetopt::getopt::pointer_t();
    std::vector<std::string>        f_targets = std::vector<std::string>();
    std::string                     f_chain = std::string();
};



} // namespace tool
// vim: ts=4 sw=4 et
