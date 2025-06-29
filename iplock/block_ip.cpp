// Copyright (c) 2011-2025  Made to Order Software Corp.  All Rights Reserved
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
#include    "iplock/block_ip.h"


// iplock
//
#include    <iplock/names.h>


// communicatord
//
#include    <communicatord/names.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
#include    <snapdev/not_used.h>


// last include
//
#include    <snapdev/poison.h>





/** \file
 * \brief This file implements the block_ip() funciton.
 *
 * The iplock environment includes the ipwall service one can use to block
 * and unblock IP addresses on an entire cluster. This file implements a
 * very easy to use block_ip() C++ function which communicates with that
 * ipwall service.
 */




/** \brief The iplock namespace.
 *
 * The iplock namespace is used throughout all the iplock library.
 */
namespace iplock
{



/** \brief Block an IP address at the firewall level.
 *
 * This function sends a IPWALL_BLOCK message to the ipwall service in
 * order to have the IP from the specified \p uri blocked for the
 * specified \p period.
 *
 * The \p uri can include a scheme which represents the name of a protocol
 * that needs to be blocked. At this time, we accept "http" and "smtp".
 * Please use "http" for "https" since both ports will get blocked anyway.
 *
 * This function does not verify the name of the scheme. However, the
 * ipwall does so before using it.
 *
 * If the scheme is not defined, then the default, which is "http",
 * is used.
 *
 * Supported schemes are defined under /etc/iplock/schemes and
 * /etc/iplock/schemes/schemes.d for user defined schemes and
 * modifications of system defined schemes.
 *
 * The \p period parameter is not required. If not specified, the default
 * applies. At this time, the ipwall tool uses "day" as its default.
 * The supported periods are:
 *
 * \li "5min" -- this is mainly for test purposes, blocks the IP for 5 minutes.
 * \li "hour" -- block the IP address for one hour.
 * \li "day" -- block the IP address for 24h. (default)
 * \li "week" -- block the IP address for 7 days.
 * \li "month" -- block the IP address for 31 days.
 * \li "year" -- block the IP address for 366 days.
 * \li "forever" -- block the IP address for 5 years.
 *
 * \todo
 * We may add support for UDP at a later time (and "auto-discovery" of the
 * communicatord URL).
 *
 * \param[in] messenger  Your messenger used to send the message.
 * \param[in] uri  The IP address of to ban.
 * \param[in] period  The duration for which the ban applies.
 * \param[in] reason  A brief description for why the block is being requested.
 */
void block_ip(
      ed::connection_with_send_message::pointer_t messenger
    , std::string const & uri
    , std::string const & period
    , std::string const & reason)
{
    // send a IPWALL_BLOCK message
    //
    ed::message message;
    message.set_command(iplock::g_name_iplock_cmd_ipwall_block);
    message.set_service(communicatord::g_name_communicatord_service_public_broadcast);

    message.add_parameter(iplock::g_name_iplock_param_uri, uri);

    if(!period.empty())
    {
        message.add_parameter(iplock::g_name_iplock_param_period, period);
    }
    //else -- ipwall uses "day" by default

    if(!reason.empty())
    {
        message.add_parameter(iplock::g_name_iplock_param_reason, reason);
    }

    messenger->send_message(message, true);
}



} // namespace iplock
// vim: ts=4 sw=4 et
