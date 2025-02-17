// Copyright (c) 2011-2024  Made to Order Software Corp.  All Rights Reserved
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
 * When you start a service which accepts public TCP or UDP connections,
 * you should first make sure the firewall is up. One way is to setup
 * the service so it starts only after the `ipload` and/or `ipwall` services
 * started successfully. This is certainly the easiest. However, a service
 * which may run on a system without `ipload` cannot have such in its
 * systemd `.service` file. For this reason, we instead have this
 * wait_on_firewall class which makes your service aware of the current
 * firewall status.
 *
 * Note that once the `ipload` service is active, the status goes to "up"
 * and never goes back "down". So once you receive the IPWALL_CURRENT_STATUS
 * message with the status parameter set to "up", you can be sure that it is
 * up and it will stay up (even if the `ipwall` service crashes, it won't
 * remove the firewall currently in effect).
 */

// fluid-settings
//
#include    <fluid-settings/fluid_settings_connection.h>


// snapdev
//
#include    <snapdev/callback_manager.h>


// cppprocess
//
#include    <cppprocess/process.h>



namespace iplock
{



enum firewall_status_t
{
    FIREWALL_STATUS_NOT_READY,      // ipload has not yet run or failed
    FIREWALL_STATUS_OFF,            // ipload is disabled so the firewall is not going to be UP or ACTIVE
    FIREWALL_STATUS_DOWN,           // ipload is enabled, but we do not yet know whether it is UP or ACTIVE
    FIREWALL_STATUS_UP,             // ipload has run, firewall is up
    FIREWALL_STATUS_ACTIVE,         // ipwall is running so you can dynamically BLOCK IP addresses
};


enum class check_state_t
{
    CHECK_STATE_IDLE,
    CHECK_STATE_IS_ENABLED,
    CHECK_STATE_IS_ACTIVE,
};


class wait_on_firewall
{
public:
    typedef std::function<bool(firewall_status_t)>
                            status_callback_t;
    typedef snapdev::callback_manager<status_callback_t>::callback_id_t
                            callback_id_t;

    virtual                 ~wait_on_firewall();

    void                    add_wait_on_firewall_commands();
    firewall_status_t       get_firewall_status() const;
    callback_id_t           add_status_callback(status_callback_t func);
    bool                    remove_status_callback(callback_id_t callback_id);

    // new callbacks
    //
    virtual void            status_changed(firewall_status_t status);

private:
    typedef snapdev::callback_manager<status_callback_t>
                            callback_manager_t;

    bool                    check_status(ed::timer::pointer_t t);
    void                    start_check();
    bool                    systemctl_exited(
                                      ed::child_status status
                                    , cppprocess::process::pointer_t p);
    int                     get_systemctl_result(
                                      ed::child_status status
                                    , cppprocess::process::pointer_t p);
    void                    set_status(firewall_status_t status);

    void                    msg_ipwall_current_status(ed::message & msg);
    void                    msg_status(ed::message & msg);
    void                    msg_ready(ed::message & msg);

    ed::timer::pointer_t    f_status_timer = ed::timer::pointer_t();
    callback_manager_t      f_status_callbacks = callback_manager_t();
    check_state_t           f_check_state = check_state_t::CHECK_STATE_IDLE;
    firewall_status_t       f_firewall_status = firewall_status_t::FIREWALL_STATUS_NOT_READY;
    bool                    f_ipwall_is_up = false;
};



} // namespace iplock
// vim: ts=4 sw=4 et
