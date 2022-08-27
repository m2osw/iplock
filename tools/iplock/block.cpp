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
#include    "block.h"



// last include
//
#include    <snapdev/poison.h>



namespace tool
{



/** \class block
 * \brief Block the specified IP addresses.
 *
 * This class goes through the list of IP addresses specified on the
 * command line and add them to the chain as defined in ipconfig.conf.
 *
 * By default, the scheme is set to "http". It can be changed with
 * the --scheme command line option.
 */

block::block(iplock * parent, advgetopt::getopt::pointer_t opts)
    : block_or_unblock(parent, "iplock --block", opts)
{
}



block::~block()
{
}


void block::run()
{
    handle_ips("block",1);
}



} // namespace tool
// vim: ts=4 sw=4 et