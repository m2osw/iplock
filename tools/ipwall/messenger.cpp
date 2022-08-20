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


// self
//
#include    "messenger.h"

#include    "server.h"


//// snapwebsites lib
////
//#include <snapwebsites/log.h>
//#include <snapwebsites/process.h>
//#include <snapwebsites/snap_cassandra.h>
//#include <snapwebsites/snapwebsites.h>
//
//
//// snapdev lib
////
//#include <snapdev/not_used.h>
//
//
//// libaddr lib
////
//#include <libaddr/addr_exception.h>
//#include <libaddr/addr_parser.h>
//
//
//// advgetopt lib
////
//#include <advgetopt/exception.h>
//
//
//// Qt lib
////
//#include <QDir>
//
//
//// C++ lib
////
//#include <fstream>
//#include <sstream>
//
//
//// C lib
////
//#include <sys/stat.h>


// last include
//
#include <snapdev/poison.h>



namespace ipwall
{



/** \class messenger
 * \brief Handle messages from the Snap Communicator server.
 *
 * This class is an implementation of the TCP client message connection
 * so we can handle incoming messages.
 */




/** \brief The messenger initialization.
 *
 * The messenger is a connection to the snapcommunicator server.
 *
 * In most cases we receive BLOCK, STOP, and LOG messages from it. We
 * implement a few other messages too (HELP, READY...)
 *
 * We use a permanent connection so if the snapcommunicator restarts
 * for whatever reason, we reconnect automatically.
 *
 * \note
 * The messenger connection used by the snapfirewall tool makes use
 * of a thread. You will want to change this initialization function
 * if you intend to fork() direct children of ours (i.e. not fork()
 * + execv() as we do to run iptables.)
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
        DISPATCHER_MATCH("BLOCK",          &messenger::msg_block_ip),
        DISPATCHER_MATCH("DATABASEREADY",  &messenger::msg_database_ready),
        DISPATCHER_MATCH("FIREWALLSTATUS", &messenger::msg_firewall_ready),
        DISPATCHER_MATCH("NODATABASE",     &messenger::msg_no_database),
        DISPATCHER_MATCH("UNBLOCK",        &messenger::msg_unblock_ip),
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


void messenger::msg_block_ip(ed::message & msg)
{
    f_server->block_ip(msg);
}


void messenger::msg_unblock_ip(ed::message & msg)
{
    f_server->unblock_ip(msg);
}


void messenger::msg_database_ready(ed::message & msg)
{
    snapdev::NOT_USED(msg);

    f_server->process_database_ready();
}


void messenger::msg_no_database(ed::message & msg)
{
    snapdev::NOT_USED(msg);

    f_server->process_no_database();
}


void messenger::msg_firewall_ready(ed::message & msg)
{
    // someone is asking us whether we are ready, reply with
    // the corresponding answer and make sure not to cache
    // the answer because it could change later (i.e. snapfirewall
    // restarts, for example.)
    //
    ed::message reply;
    reply.reply_to(msg);
    reply.set_command(f_server->is_firewall_up() ? "FIREWALLUP" : "FIREWALLDOWN");
    reply.add_parameter("cache", "no");
    send_message(reply);
}




///** \brief The messenger could not connect to snapcommunicator.
// *
// * This function is called whenever the messengers fails to
// * connect to the snapcommunicator server. This could be
// * because snapcommunicator is not running or because the
// * configuration information for the snapfirewall is wrong...
// *
// * With systemd the snapcommunicator should already be running
// * although this is not 100% guaranteed. So getting this
// * error from time to time is considered normal.
// *
// * \param[in] error_message  An error message.
// */
//void messenger::process_connection_failed(std::string const & error_message)
//{
//    SNAP_LOG_ERROR("connection to snapcommunicator failed (")(error_message)(")");
//
//    // also call the default function, just in case
//    snap_tcp_client_permanent_message_connection::process_connection_failed(error_message);
//}
//
//
///** \brief The connection was established with Snap! Communicator.
// *
// * Whenever the connection is established with the Snap! Communicator,
// * this callback function is called.
// *
// * The messenger reacts by REGISTERing the snap_firewall with the Snap!
// * Communicator. The name of the backend is taken from the action
// * it was called with.
// */
//void messenger::process_connected()
//{
//    snap_tcp_client_permanent_message_connection::process_connected();
//
//    snap::snap_communicator_message register_firewall;
//    register_firewall.set_command("REGISTER");
//    register_firewall.add_parameter("service", "snapfirewall");
//    register_firewall.add_parameter("version", snap::snap_communicator::VERSION);
//    send_message(register_firewall);
//}



} // namespace ipwall
// vim: ts=4 sw=4 et
