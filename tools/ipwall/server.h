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
#pragma once


// self
//
#include    "block_info.h"
#include    "database_timer.h"
#include    "interrupt.h"
#include    "messenger.h"
#include    "wakeup_timer.h"



namespace ipwall
{



class server
{
public:
    typedef std::shared_ptr<server>      pointer_t;

                                server(int argc, char * argv[]);
                                server(server const &) = delete;
                                ~server();

    server &                    operator = (server const &) = delete;

    static pointer_t            instance( int argc, char * argv[] );

    void                        run();

    void                        process_timeout();
    void                        process_reconnect();
    void                        process_database_ready();
    void                        process_no_database();
    void                        stop(bool quitting);
    void                        next_wakeup();
    void                        block_ip(ed::message const & message);
    void                        unblock_ip(ed::message const & message);
    void                        is_db_ready();

    bool                        is_firewall_up() const;

private:
    void                        setup_firewall();

    advgetopt::getopt                   f_opts;
    ed::communicator::pointer_t         f_communicator = ed::communicator::pointer_t();
    std::string                         f_server_name = std::string();
    interrupt::pointer_t                f_interrupt = interrupt::pointer_t();
    messenger::pointer_t                f_messenger = messenger::pointer_t();
    database_timer::pointer_t           f_database_timer = database_timer::pointer_t();
    wakeup_timer::pointer_t             f_wakeup_timer = wakeup_timer::pointer_t();
    //snap::database                      f_database = snap::database();
    //libdbproxy::table::pointer_t        f_firewall_table = libdbproxy::table::pointer_t();
    bool                                f_stop_received = false;
    bool                                f_firewall_up = false;
    block_info::block_info_vector_t     f_blocks = block_info::block_info_vector_t();       // save here until connected to Cassandra
};



} // namespace ipwall
// vim: ts=4 sw=4 et
