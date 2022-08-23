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

// fluid-settings
//
#include    <fluid-settings/fluid_settings_connection.h>



namespace ipwall
{



class server;



class messenger
    : public fluid_settings::fluid_settings_connection
{
public:
    typedef std::shared_ptr<messenger>    pointer_t;

                        messenger(server * s, advgetopt::getopt & opts);
                        messenger(messenger const & rhs) = delete;
    virtual             ~messenger() override {}

    messenger &         operator = (messenger const & rhs) = delete;

    void                finish_initialization();

private:
    void                msg_block_ip(ed::message & msg);
    void                msg_database_ready(ed::message & msg);
    void                msg_firewall_ready(ed::message & msg);
    void                msg_no_database(ed::message & msg);
    void                msg_unblock_ip(ed::message & msg);

    // this is owned by the main server function so no need for a smart pointer
    server *            f_server = nullptr;
    ed::dispatcher::pointer_t
                        f_dispatcher = ed::dispatcher::pointer_t();
};



} // namespace ipwall
// vim: ts=4 sw=4 et
