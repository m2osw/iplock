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


// self
//
#include    "database_timer.h"

#include    "server.h"


// last include
//
#include    <snapdev/poison.h>



namespace ipwall
{



/** \class database_timer
 * \brief The timer used when a connection to the database fails.
 *
 * When we receive the DATABASE_READY event, the connection is likely to
 * work. However, while reading the data in the following loop, we may
 * end up with an exception and that stops the connection right there.
 * In other words, on return the f_database pointer will be reset back
 * to a null pointer.
 *
 * To allow for a little bit of time before reconnecting, we use this
 * timer. Because in most cases this happens when the database is rather
 * overloaded so trying to reconnect immediately at this stage is not
 * a good plan.
 *
 * At this time, we setup the timer to 30 seconds. The firewall continues
 * to be fully functional, so a longer pause should not be much of a
 * problem.
 */




/** \brief Initializes the reconnect timer with a pointer to the snap firewall.
 *
 * The constructor saves the pointer of the snap_firewall object so
 * it can later be used when the reconnect timer events occurs.
 *
 * By default the timer is "off" meaning that it will not trigger
 * a process_reconnect() call until you turn it on.
 *
 * \param[in] s  A pointer to the ipwall server object.
 */
database_timer::database_timer(server * s)
    : timer(-1)
    , f_server(s)
{
    set_name("database_timer");
}


/** \brief The reconnect timer timed out.
 *
 * The reconnect timer is used to force a DATABASE_READY some time after
 * a failure in the setup_firewall() function happens.
 *
 * In most cases, this gets used when a timeout happens in the database
 * cluster. If the timeout happens while running the setup function, then
 * we do not want to try again immediately. Instead, we wait a little
 * while and send a DATABASE_READY message to the local database service
 * whenever this function gets called.
 */
void database_timer::process_timeout()
{
    f_server->process_reconnect();
}



} // namespace ipwall
// vim: ts=4 sw=4 et
