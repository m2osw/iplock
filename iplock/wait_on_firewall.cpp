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

/** \file
 * \brief Implementation of the wait_on_firewall class.
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
 * to go back down. So once you receive the FIREWALL_UP message, you can
 * be sure that it is up and it will stay up (even if the ipwall service
 * crashes, it won't remove the firewall currently in effect).
 */

// self
//
#include    <iplock/wait_on_firewall.h>

#include    <iplock/exception.h>
#include    <iplock/names.h>


// eventdispatcher
//
#include    <eventdispatcher/connection_with_send_message.h>
#include    <eventdispatcher/dispatcher_support.h>


// communicatord
//
#include    <communicatord/names.h>


// snaplogger
//
#include    <snaplogger/message.h>


// cppprocess
//
#include    <cppprocess/io_capture_pipe.h>


// last include
//
#include    <snapdev/poison.h>



namespace iplock
{


/** \class wait_on_firewall
 * \brief Allow your process to wait for the firewall to be up.
 *
 * Many services open TCP and UDP connections which need to be protected
 * by the firewall. Those services should have their messenger derive
 * from this class and wait until the is_firewall_up() function gets
 * called before they open any public connection.
 */


wait_on_firewall::~wait_on_firewall()
{
    fluid_settings::fluid_settings_connection * fs(dynamic_cast<fluid_settings::fluid_settings_connection *>(this));
    if(fs != nullptr)
    {
        fs->remove_status_callback(f_status_callback_id);
    }
}


/** \brief Initialize wait_on_firewall.
 *
 * This function makes the wait_on_firewall listen for a FIREWALL_UP message
 * from the ipwall service.
 *
 * The function first makes sure that the ipwall service is:
 *
 * \li installed
 * \li active
 * \li running
 *
 * If any of these is false, then we either get an error (i.e. the service
 * is marked as active but it is not running) or we skip of the test and
 * assume that the firewall is not required on that computer and thus
 * \em pretend that it is up for the service to continue as normal.
 *
 * \note
 * Most of our services are local and thus do not require the wait_on_firewall
 * signals. This is really only required for services that listen on public
 * TCP ports such as an HTTP or an SMTP service. It is also useful for
 * services that listen on 0.0.0.0 (ANY) even if those are considered private
 * (such as a database). Because those services would be accessible through
 * the public Internet as well if their port is not properly blocked.
 */
void wait_on_firewall::add_wait_on_firewall_commands(std::string const & ipwall_service_name)
{
    check_if_active(ipwall_service_name);

    fluid_settings::fluid_settings_connection * fs(dynamic_cast<fluid_settings::fluid_settings_connection *>(this));
    if(fs != nullptr)
    {
        // TODO: we should look into using a shared pointer instead of `this`
        //       (although we have a shared_from_this() function in `fs`
        //       I don't think it would be compatible with wait_on_firewall?)
        //
        f_status_callback_id = fs->add_status_callback(std::bind(
                                      &wait_on_firewall::service_status
                                    , this
                                    , std::placeholders::_1
                                    , std::placeholders::_2));
    }

    ed::dispatcher_support * ds(dynamic_cast<ed::dispatcher_support *>(this));
    if(ds == nullptr)
    {
        throw logic_error("the wait_on_firewall class must be used with a dispatcher_support class.");
    }
    ed::dispatcher::pointer_t dispatcher(ds->get_dispatcher());
    if(dispatcher == nullptr)
    {
        throw logic_error("the wait_on_firewall::add_wait_on_firewall_commands() must be called after you setup your dispatcher (set_dispatcher() was not yet called).");
    }
    dispatcher->add_matches({
            DISPATCHER_MATCH(g_name_iplock_cmd_firewall_up,   &wait_on_firewall::msg_firewall_up),
            DISPATCHER_MATCH(g_name_iplock_cmd_firewall_down, &wait_on_firewall::msg_firewall_down),
        });

    ed::connection_with_send_message * cwm(dynamic_cast<ed::connection_with_send_message *>(this));
    if(cwm == nullptr)
    {
        throw logic_error("the wait_on_firewall class must also represent a connection_with_message.");
    }

    // send a FIREWALL_READY message to get the current firewall status
    //
    // Note: no need to cache the message; if the firewall starts after
    //       we sent this message, we will receive a FIREWALL_UP once it
    //       is up, so no worries; if the firewall is not install on
    //       this machine, then we just get a "not available" error
    //       message which we ignore here
    //
    ed::message msg;
    msg.reply_to(msg);
    msg.set_command(g_name_iplock_cmd_firewall_ready);
    msg.add_parameter(
              communicatord::g_name_communicatord_param_cache
            , communicatord::g_name_communicatord_value_no);
    cwm->send_message(msg);
}


void wait_on_firewall::check_if_active(std::string const & ipwall_service_name)
{
    // TODO: note that this test is flaky in the sense that it happens only
    //       once on startup; we would also need a way to detect whether
    //       the firewall gets activated later; the status callback may
    //       partially be used for that purpose
    //
    //f_firewall_is_active = system("systemctl is-active -q ipwall") == 0;

    cppprocess::process::pointer_t firewall_is_active_process(
            std::make_shared<cppprocess::process>("check firewall service status"));
    firewall_is_active_process->set_command("systemctl");
    firewall_is_active_process->add_argument("is-active");
    firewall_is_active_process->add_argument("-q");
    firewall_is_active_process->add_argument(ipwall_service_name);

    cppprocess::io_capture_pipe::pointer_t output_pipe(std::make_shared<cppprocess::io_capture_pipe>());
    firewall_is_active_process->set_output_io(output_pipe);

    cppprocess::io_capture_pipe::pointer_t error_pipe(std::make_shared<cppprocess::io_capture_pipe>());
    firewall_is_active_process->set_error_io(error_pipe);

    int const r(firewall_is_active_process->start());
    if(r != 0)
    {
        SNAP_LOG_ERROR
            << "could not start process to check whether the \""
            << ipwall_service_name
            << "\" service is active."
            << SNAP_LOG_SEND;

        // assume it is active... otherwise other parts of the system may not
        // ever start (this is actually a security issue)
        //
        f_firewall_is_active = true;
        return;
    }

    // TODO: `this` should be a smart pointer instead...
    //       as it stands, the wait_on_firewall object could be deleted
    //       before the process is finished
    //
    ed::signal_child::pointer_t child_signal(ed::signal_child::get_instance());
    child_signal->add_listener(
              firewall_is_active_process->process_pid()
            , std::bind(
                    &wait_on_firewall::firewall_is_active
                  , this
                  , std::placeholders::_1
                  , firewall_is_active_process));
}


void wait_on_firewall::firewall_is_active(
      ed::child_status status
    , cppprocess::process::pointer_t p)
{
    f_firewall_is_active = status.is_exited()
                        && status.exit_code() == 0;

    cppprocess::io_capture_pipe::pointer_t output_pipe(std::dynamic_pointer_cast<cppprocess::io_capture_pipe>(p->get_output_io()));
    cppprocess::io_capture_pipe::pointer_t error_pipe(std::dynamic_pointer_cast<cppprocess::io_capture_pipe>(p->get_error_io()));
    if(status.is_signaled())
    {
        SNAP_LOG_ERROR
            << "systemctl received a signal and died: "
            << status.terminate_signal()
            << " -- Console Output:\n"
            << output_pipe->get_output()
            << " -- Console Errors:\n"
            << error_pipe->get_output()
            << SNAP_LOG_SEND;
    }
    else if(status.is_exited())
    {
        if(status.exit_code() != 0)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "an error occurred running systemctl: "
                << status.exit_code()
                << " -- Console Output:\n"
                << output_pipe->get_output()
                << " -- Console Errors:\n"
                << error_pipe->get_output()
                << SNAP_LOG_SEND;
        }
    }
}


bool wait_on_firewall::is_firewall_available() const
{
    return f_firewall_is_available;
}


bool wait_on_firewall::is_firewall_up() const
{
    return f_firewall_is_up;
}


void wait_on_firewall::msg_firewall_up(ed::message & msg)
{
    snapdev::NOT_USED(msg);

    f_firewall_is_up = true;

    firewall_is_up();
}


void wait_on_firewall::msg_firewall_down(ed::message & msg)
{
    snapdev::NOT_USED(msg);

    // once UP the firewall should never go back down
    //
    // however, if the ipwall service is restarted, we may get a FIREWALLDOWN
    // message even though the "old" firewall is still up and running so
    // in effect we just completely ignore this message; it's not quite
    // accurate
    //
    //if(f_firewall_is_up)
    //{
    //    throw ();
    //}
}


bool wait_on_firewall::service_status(std::string const & service, std::string const & status)
{
    if(service == "ipwall")
    {
        f_firewall_is_available = status == "up";
    }

    // always continue; someone else may be interested by the same message
    //
    return true;
}



} // namespace iplock
// vim: ts=4 sw=4 et

