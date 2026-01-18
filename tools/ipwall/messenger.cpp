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
#include    "messenger.h"

#include    "server.h"


// iplock
//
#include    <iplock/names.h>


// communicator
//
#include    <communicator/names.h>


// prinbee
//
#include    <prinbee/names.h>


// last include
//
#include    <snapdev/poison.h>



namespace ipwall
{



/** \class messenger
 * \brief Handle messages from the Communicator Daemon server.
 *
 * This class is an implementation of the TCP client message connection
 * so we can handle incoming messages.
 */




/** \brief The messenger initialization.
 *
 * The messenger is a connection to the communicatord server.
 *
 * In most cases we receive IPWALL_BLOCK, STOP, and LOG_ROTATE messages
 * from it. We implement a few other messages too (HELP, READY...)
 *
 * We use a permanent connection so if the communicatord restarts
 * for whatever reason, we reconnect automatically.
 *
 * \param[in] s  The firewall server we are listening for.
 * \param[in] opts  The command line options.
 */
messenger::messenger(server * s, advgetopt::getopt & opts)
    : fluid_settings_connection(opts, "ipwall")
    , f_server(s)
{
    set_name("messenger");

    get_dispatcher()->add_matches({
        DISPATCHER_MATCH(iplock::g_name_iplock_cmd_ipwall_get_status, &messenger::msg_ipwall_get_status),
        DISPATCHER_MATCH(iplock::g_name_iplock_cmd_ipwall_block,      &messenger::msg_ipwall_block_ip),
        DISPATCHER_MATCH(iplock::g_name_iplock_cmd_ipwall_unblock,    &messenger::msg_ipwall_unblock_ip),
    });
}


void messenger::finish_initialization()
{
    process_fluid_settings_options();
    automatic_watch_initialization();
}


void messenger::msg_ipwall_block_ip(ed::message & msg)
{
    f_server->block_ip(msg);
}


void messenger::msg_ipwall_unblock_ip(ed::message & msg)
{
    f_server->unblock_ip(msg);
}


// TODO: derive from prinbee_connection instead of fluid_settings_connection
//       and we get the following "for free" (automatic, that is)
//
//void messenger::msg_database_ready(ed::message & msg)
//{
//    snapdev::NOT_USED(msg);
//
//    f_server->process_database_ready();
//}
//
//
//void messenger::msg_no_database(ed::message & msg)
//{
//    snapdev::NOT_USED(msg);
//
//    f_server->process_no_database();
//}


void messenger::msg_ipwall_get_status(ed::message & msg)
{
    // someone is asking us whether we are ready, reply with
    // the corresponding answer and make sure not to cache
    // the answer because it could change later (i.e. ipwall
    // restarts, for example).
    //
    ed::message reply;
    reply.reply_to(msg);
    reply.set_command(iplock::g_name_iplock_cmd_ipwall_current_status);
    reply.add_parameter(
              ::communicator::g_name_communicator_param_cache
            , ::communicator::g_name_communicator_value_no);
    reply.add_parameter(
              ::communicator::g_name_communicator_param_status
            , f_server->is_firewall_up()
                    ? ::communicator::g_name_communicator_value_up
                    : ::communicator::g_name_communicator_value_down);
    send_message(reply);
}



} // namespace ipwall
// vim: ts=4 sw=4 et
