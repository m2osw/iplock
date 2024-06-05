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
 * \brief Exceptions.
 *
 * The following are all the exceptions used by the IP Lock library.
 */


// libexcept
//
#include    <libexcept/exception.h>



namespace iplock
{



DECLARE_LOGIC_ERROR(logic_error);

DECLARE_MAIN_EXCEPTION(iplock_exception);

DECLARE_EXCEPTION(iplock_exception, count_mismatch);
DECLARE_EXCEPTION(iplock_exception, invalid_parameter);



} // namespace ed
// vim: ts=4 sw=4 et
