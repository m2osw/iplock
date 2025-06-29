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


// libaddr
//
#include    <libaddr/addr_parser.h>



namespace tool
{



enum class mode_t
{
    MODE_BLOCK,
    MODE_UNBLOCK,
};


class block_or_unblock
    : public command
{
public:
                        block_or_unblock(
                              controller * parent
                            , char const * command_name);
    virtual             ~block_or_unblock() override;

    void                handle_ips(std::string const & cmd, mode_t mode);

private:
    void                get_allowlist();
    void                add_ips(std::string const & ips);

    std::string         f_command = std::string();
    mode_t              f_mode = mode_t::MODE_BLOCK;
    bool                f_found_ips = false;
    addr::addr_range::vector_t
                        f_allowlist_ips = addr::addr_range::vector_t();
    std::string         f_set_rules = std::string();
};



} // namespace tool
// vim: ts=4 sw=4 et
