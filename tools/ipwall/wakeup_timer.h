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



class wakeup_timer
    : public ed::timer
{
public:
    typedef std::shared_ptr<wakeup_timer>        pointer_t;

                                wakeup_timer(server * s);
                                wakeup_timer(wakeup_timer const & rhs) = delete;
    virtual                     ~wakeup_timer() override {}

    wakeup_timer &              operator = (wakeup_timer const & rhs) = delete;

    // ed::snap_timer implementation
    virtual void                process_timeout();

private:
    server *                    f_server = nullptr;
};


} // namespace ipwall
// vim: ts=4 sw=4 et
