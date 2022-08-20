// Copyright (c) 2011-2022  Made to Order Software Corp.  All Rights Reserved
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
 * \brief Declare the block_ip() function.
 *
 * This header declares the block_ip() function and related parameters.
 */

// eventdispatcher
//
#include    <eventdispatcher/connection_with_send_message.h>



namespace iplock
{



void block_ip(
      ed::connection_with_send_message::pointer_t messenger
    , std::string const & uri
    , std::string const & period = std::string()
    , std::string const & reason = std::string());



} // namespace iplock
// vim: ts=4 sw=4 et
