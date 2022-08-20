// Copyright (c) 2011-2022  Made to Order Software Corp.  All Rights Reserved
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

/** \file
 * \brief Declare the wait_on_firewall class.
 *
 * When you start a service which accepts TCP or UDP connections, you
 * should first make sure that the firewall is up. One way is to setup
 * the service so it starts only after the ipload service ran. This is
 * certainly the easiest. However, a service which may run on a system
 * without ipload cannot have such in its systemd `.service` file. For
 * this reason, we instead have a function which makes your service
 * aware of the firewall status.
 *
 * Note that the status goes from "down" to "up" and it is never expected
 * to go back down. So once you receive the FIREWALLUP message, you can
 * be sure that it is up and it will stay up (even if the ipwall service
 * crashes, it won't remove the firewall currently in effect).
 */

// fluid-settings
//
#include    <fluid-settings/fluid_settings_connection.h>


// cppprocess
//
#include    <cppprocess/process.h>



namespace iplock
{



class wait_on_firewall
{
public:
    virtual         ~wait_on_firewall();

    void            add_wait_on_firewall_commands(std::string const & ipwall_service_name = "ipwall");
    bool            is_firewall_up() const;
    bool            is_firewall_available() const;

    // new callbacks
    //
    virtual void    firewall_is_up() = 0;

private:
    void            check_if_active(std::string const & ipwall_service_name);
    void            firewall_is_active(
                              ed::child_status status
                            , cppprocess::process::pointer_t iplock_process);
    bool            service_status(
                              std::string const & service
                            , std::string const & status);

    void            msg_firewall_up(ed::message & msg);
    void            msg_firewall_down(ed::message & msg);

    bool            f_firewall_is_active = false;       // whether the systemd service is present and available
    bool            f_firewall_is_available = false;    // whether the ipwall service is currently running or not
    bool            f_firewall_is_up = false;           // whether the firewall is considered up and running
    snapdev::callback_manager<fluid_settings::status_callback_t>::callback_id_t
                    f_status_callback_id = snapdev::callback_manager<fluid_settings::status_callback_t>::NULL_CALLBACK_ID;
};



} // namespace iplock
// vim: ts=4 sw=4 et
