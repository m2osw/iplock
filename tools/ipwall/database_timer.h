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


// eventdispatcher
//
#include <eventdispatcher/timer.h>



namespace ipwall
{



class server;



class database_timer
    : public ed::timer
{
public:
    typedef std::shared_ptr<database_timer>        pointer_t;

                                database_timer(server * s);
                                database_timer(database_timer const & rhs) = delete;
    virtual                     ~database_timer() override {}

    database_timer &            operator = (database_timer const & rhs) = delete;

    // ed::snap_timer implementation
    virtual void                process_timeout();

private:
    server *                    f_server = nullptr;
};



} // namespace iplock
// vim: ts=4 sw=4 et
