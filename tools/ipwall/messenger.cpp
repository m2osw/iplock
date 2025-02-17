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


// self
//
#include    "messenger.h"

#include    "server.h"


// iplock
//
#include    <iplock/names.h>


// communicatord
//
#include    <communicatord/names.h>


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
 * In most cases we receive BLOCK, STOP, and LOG_ROTATE messages from it.
 * We implement a few other messages too (HELP, READY...)
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
    , f_dispatcher(std::make_shared<ed::dispatcher>(this))
{
    set_name("messenger");

    set_dispatcher(f_dispatcher);

    f_dispatcher->add_matches({
        // the name of the ipwall status message is defined in the
        // communicator daemon so that way we can send that message
        // from there and prinbee
        //
        DISPATCHER_MATCH(communicatord::g_name_communicatord_cmd_ipwall_get_status, &messenger::msg_ipwall_get_status),

        DISPATCHER_MATCH(iplock::g_name_iplock_cmd_ipwall_block,                    &messenger::msg_ipwall_block_ip),
        DISPATCHER_MATCH(iplock::g_name_iplock_cmd_ipwall_unblock,                  &messenger::msg_ipwall_unblock_ip),
    });

    // further dispatcher initialization
    //
#ifdef _DEBUG
    f_dispatcher->set_trace();
    f_dispatcher->set_show_matches();
#endif
}


void messenger::finish_initialization()
{
    add_fluid_settings_commands();

    // add the communicator commands last (it includes the "always match")
    f_dispatcher->add_communicator_commands();

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
    reply.set_command(communicatord::g_name_communicatord_cmd_ipwall_current_status);
    reply.add_parameter(
              communicatord::g_name_communicatord_param_cache
            , communicatord::g_name_communicatord_value_no);
    reply.add_parameter(
              communicatord::g_name_communicatord_param_status
            , f_server->is_firewall_up()
                    ? communicatord::g_name_communicatord_value_up
                    : communicatord::g_name_communicatord_value_down);
    send_message(reply);
}



} // namespace ipwall
// vim: ts=4 sw=4 et
