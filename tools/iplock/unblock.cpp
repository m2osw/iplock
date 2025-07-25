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


/** \file
 * \brief iplock tool.
 *
 * This implementation offers a way to easily and safely add and remove
 * IP addresses one wants to block/unblock temporarily.
 *
 * The tool makes use of the iptables tool to add and remove rules
 * to one specific table which is expected to be included in your
 * INPUT rules (with a `-j \<table-name>`).
 */


// self
//
#include    "unblock.h"



// last include
//
#include    <snapdev/poison.h>



namespace tool
{



/** \class unblock
 * \brief Unblock the specified IP addresses.
 *
 * This class goes through the list of IP addresses specified on the
 * command line and remove them from the set as defined by the `--set`
 * command line option. By default this is the "unwanted" set.
 */

unblock::unblock(controller * parent)
    : block_or_unblock(parent, "unblock")
{
}


unblock::~unblock()
{
}


void unblock::run()
{
    handle_ips("del [set] [ip] -exist", mode_t::MODE_UNBLOCK);
}



} // namespace tool
// vim: ts=4 sw=4 et
