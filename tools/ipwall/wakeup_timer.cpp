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
#include    "wakeup_timer.h"

#include    "server.h"


// last include
//
#include    <snapdev/poison.h>



namespace ipwall
{



/** \brief Initializes the timer with a pointer to the server.
 *
 * The constructor saves the pointer of the server object so
 * it can later be used when the process timeouts.
 *
 * By default the timer is "off" meaning that it does not trigger
 * a process_timeout() call until you turn it on.
 *
 * \param[in] s  A pointer to the server object.
 */
wakeup_timer::wakeup_timer(server * s)
    : timer(-1)
    , f_server(s)
{
    set_name("wakeup_timer");
}


/** \brief The wake up timer activation.
 *
 * The wake up timer is used to know when we have to remove IP
 * addresses from the firewall. Adding happens at the start and
 * whenever another service tells us to add an IP. Removal,
 * however, we are on our own.
 *
 * Whenever an IP is added by a service, it is accompanied by a
 * time period it should be blocked for. This may be forever, however,
 * when the amount of time is not forever, the ipwall tool
 * needs to wake up at some point. Note that those times are saved in
 * the database so one can know when to remove IPs even across restarts
 * (actually, on a restart we usually do the opposite, we refill the
 * firewall with existing IP addresses that have not yet timed out;
 * however, if this was not a full server restart, then we do removals
 * only).
 *
 * Note that the messenger may receive an IPWALL_UNBLOCK command in
 * which case an IP gets removed immediately and the timer reset to
 * the next IP that needs to be removed as required.
 */
void wakeup_timer::process_timeout()
{
    f_server->process_timeout();
}



} // namespace ipwall
// vim: ts=4 sw=4 et
