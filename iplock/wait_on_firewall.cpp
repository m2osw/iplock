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
#include    <eventdispatcher/names.h>


// communicatord
//
#include    <communicatord/names.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
#include    <snapdev/safe_assert.h>
#include    <snapdev/safe_object.h>


// cppprocess
//
#include    <cppprocess/io_capture_pipe.h>


// last include
//
#include    <snapdev/poison.h>



namespace iplock
{



namespace
{



constexpr std::int64_t const        IPWALL_STATUS_CHECK_DELAY = 1'000'000LL * 60LL;


void reset_state(check_state_t * state)
{
    *state = check_state_t::CHECK_STATE_IDLE;
}



} // no name namespace



/** \class wait_on_firewall
 * \brief Allow your process to track the firewall status.
 *
 * \note
 * If there is nothing your service can do until the `ipwall` service is up
 * and running, then you can instead use the `After=ipwall`. Similarly, if
 * it just needs the firewall, you can use the `After=ipload` option. The
 * `ipwall` service actually only starts after `ipload` was successfully
 * started. So receiving any message from `ipwall` mean that the firewall
 * is up and active.
 *
 * The firewall is an important part of the system since it prevents
 * hackers from accessing services you start locally. Although in most
 * cases our processes only connect to the communicator daemon, a few
 * open their own public connection. These need to be protected and
 * to do so we want to track the current firewall status.
 *
 * This class tracks the status of two services in link with the
 * firewall:
 *
 * 1. It makes sure that the ipload service started successfully
 * 2. It checks whether the ipwall service is currently running
 *
 * Once ipload ran successfully, the firewall is up and it is safe
 * for your application to open its own potentially public port(s).
 *
 * For applications that want to be able to actively IPWALL_BLOCK (and
 * IPWALL_UNBLOCK) IP addresses, they also need to wait on the ipwall
 * service. This allows the application to proactively prevent hackers
 * from accessing any of the Snap! C++ systems by quickly blocking their
 * IP addresses. (i.e. The block automatically propagates to all the
 * computers in your cluster.)
 *
 * As a result, you have three possible states:
 *
 * 1. firewall is not ready (ipload has not yet run) [FIREWALL_STATUS_NOT_READY]
 * 2. firewall is ready, but ipwall is not available [FIREWALL_STATUS_UP]
 * 3. firewall is up and ipwall is available [FIREWALL_STATUS_ACTIVE]
 *
 * Once the status is UP it can bounce between UP and ACTIVE. It cannot go
 * back to NOT_READY (i.e. in the Snap! C++ execution environment, we do not
 * offer a way to flush the firewall; it is, of course, always doable...
 * either by hand or even with one of our tools, but the functionality should
 * never happen on its own; the sitter can be used to verify that the firewall
 * does not get flushed--see the sitter/plugins/sitter_firewall plugin, which
 * needs to be moved to this project).
 */


wait_on_firewall::~wait_on_firewall()
{
}


/** \brief Initialize wait_on_firewall.
 *
 * This function initializes the wait_on_firewall object.
 *
 * First the initialization function checks whether the ipload service ran
 * successfully. If not, then a timer is used to check again once in a
 * while. Until it was activated, the firewall status is set to
 * FIREWALL_STATUS_NOT_READY.
 *
 * Once we detect that the ipload service is marked as active, we take
 * the ipwall service status in account. This function sets up the
 * dispatcher to listen for messages from the ipwall service for that
 * purpose. If the ipwall is up and running, then the status becomes
 * FIREWALL_STATUS_ACTIVE. Otherwise, it gets set to FIREWALL_STATUS_UP.
 * (i.e. when the firewall is just up, it is static in the sense that
 * IPWALL_BLOCK messages are ignored.)
 *
 * The message we listen to is IPWALL_CURRENT_STATUS. We also listen to
 * the STATUS message, which tells us when ipwall goes down (i.e. the
 * ipwall service would not know to send a "down" status if it crashes).
 *
 * In case the ipwall service is already running, we need to pro-actively
 * send the IPWALL_GET_STATUS message. To do so at the right time, we
 * also listen for the READY message. When we get that message, we send
 * the status request. This means this function needs to be called before
 * that message gets sent.
 *
 * If the ipload service is disabled, then the state is set to
 * FIREWALL_STATUS_DOWN. This means your application can continue without
 * the firewall (i.e. the service is not disabled by default, this means
 * the administrator decided to turn it off).
 *
 * \note
 * The status of the ipload is not known at the time this function returns.
 * It starts a process to determine whether the service is disabled and
 * if not try another to determine whether the service is considered
 * active.
 *
 * \note
 * Most of our services are local and thus do not require the
 * wait_on_firewall signals. This is really only required for the very few
 * services that listen on public TCP or UDP ports such as an HTTP or an
 * SMTP service. It is also useful for services that listen on
 * 0.0.0.0 (ANY) even if those are considered private (such as a database).
 * Because those services would be accessible through the public Internet
 * as well if their port is not properly blocked.
 *
 * \exception logic_error
 * The logic_error exception is raised if the wait_on_firewall was not
 * properly derived from a ed::dispatcher_support or if the dispatcher
 * pointer was not yet set. It also has to be an ed::connection object.
 */
void wait_on_firewall::add_wait_on_firewall_commands()
{
    ed::connection * c(dynamic_cast<ed::connection *>(this));
    if(c == nullptr)
    {
        throw logic_error("the wait_on_firewall class must be used with a connection class.");
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
            DISPATCHER_MATCH(communicatord::g_name_communicatord_cmd_ipwall_current_status, &wait_on_firewall::msg_ipwall_current_status),
            ed::define_match(
                  ed::Expression(communicatord::g_name_communicatord_cmd_status)
                , ed::Callback(std::bind(&wait_on_firewall::msg_status, this, std::placeholders::_1))
                , ed::MatchFunc(&ed::one_to_one_callback_match)
                , ed::Priority(ed::dispatcher_match::DISPATCHER_MATCH_CALLBACK_PRIORITY)
            ),
            ::ed::define_match(
                  ::ed::Expression(ed::g_name_ed_cmd_ready)
                , ::ed::Callback(std::bind(&wait_on_firewall::msg_ready, this, std::placeholders::_1))
                , ed::MatchFunc(&ed::one_to_one_callback_match)
                , ed::Priority(ed::dispatcher_match::DISPATCHER_MATCH_CALLBACK_PRIORITY)
            ),
        });

    // the status may change over time, have a timer to run the check
    // over time but also call the function once now
    //
    f_status_timer = std::make_shared<ed::timer>(IPWALL_STATUS_CHECK_DELAY);
    f_status_timer->get_callback_manager().add_callback(std::bind(
                  &wait_on_firewall::check_status
                , std::dynamic_pointer_cast<wait_on_firewall>(c->shared_from_this())
                , std::placeholders::_1));

    // immediately start the process of checking for the status for the first time
    //
    // (this makes use of a background process and we get the response
    // through the communicator through a child signal, so it is not
    // immediate)
    //
    check_status(f_status_timer);
}


/** \brief Check the status of the ipload service.
 *
 * To check the status of the ipload service, we run the systemctl command
 * and expect to receive a child signal. The signal gives us the result
 * of the call (a.k.a. the exit code or the number of a signal that killed
 * the child process).
 *
 * That means it looks like spaghetti code. Here is the list of function
 * called in the process and how it repeats if a call fails in some way.
 *
 * \msc
 * a [label="add_wait_on_firewall_commands"],
 * b [label="check_status"],
 * c [label="start_check"],
 * d [label="systemctl_exited"],
 * e [label="communicator"];
 *
 * #
 * # Phase 1: check is-enabled
 * #
 * a=>b [label="start check process"];
 * --- [label="if already running, return"];
 * b=>c [label="run systemctl is-enabled"];
 * ... [label="wait for process to complete"];
 * e=>d [label="check result of systemctl"];
 * --- [label="if check failed (signaled), return without changing the state"];
 * --- [label="if check failed (exit 1), change state to OFF"];
 * --- [label="if check succeeded (exit 0), change state to DOWN and continue status check process"];
 *
 * #
 * # Phase 2: check is-active
 * #
 * d=>b [label="continue check process"];
 * b=>c [label="run systemctl is-active"];
 * ... [label="wait for process to complete"];
 * e=>d [label="check result of systemctl"];
 * --- [label="if check failed (signaled), return without changing the state"];
 * --- [label="if check failed (exit 1), return without changing the state"];
 * --- [label="if check succeeded (exit 0), change state to UP or ACTIVE"];
 * \endmsc
 *
 * If starting the systemctl command fails, the state does not change and
 * the process stops.
 */
bool wait_on_firewall::check_status(ed::timer::pointer_t t)
{
    snapdev::NOT_USED(t); // t == f_status_timer

    if(f_check_state != check_state_t::CHECK_STATE_IDLE)
    {
        return true;
    }
    f_check_state = check_state_t::CHECK_STATE_IS_ENABLED;
    start_check();
    return true;
}


void wait_on_firewall::start_check()
{
    // make sure that on any error the state gets reset to IDLE
    //
    snapdev::safe_object<check_state_t *, reset_state> safe_state;
    safe_state.make_safe(&f_check_state);

    cppprocess::process::pointer_t systemctl_process(
            std::make_shared<cppprocess::process>("check ipload service status"));
    systemctl_process->set_command("systemctl");
    systemctl_process->add_argument(
                f_check_state == check_state_t::CHECK_STATE_IS_ENABLED
                    ? "is-enabled"
                    : "is-active");
    systemctl_process->add_argument("-q");
    systemctl_process->add_argument(iplock::g_name_iplock_service_ipload);

    cppprocess::io_capture_pipe::pointer_t output_pipe(std::make_shared<cppprocess::io_capture_pipe>());
    systemctl_process->set_output_io(output_pipe);

    cppprocess::io_capture_pipe::pointer_t error_pipe(std::make_shared<cppprocess::io_capture_pipe>());
    systemctl_process->set_error_io(error_pipe);

    int const r(systemctl_process->start());
    if(r != 0)
    {
        SNAP_LOG_ERROR
            << "process \""
            << systemctl_process->get_command_line()
            << "\" failed starting."
            << SNAP_LOG_SEND;
        return;
    }

    ed::connection * c(dynamic_cast<ed::connection *>(this));
    if(c == nullptr)
    {
        throw logic_error("the wait_on_firewall class must be used with a connection class.");
    }

    ed::signal_child::pointer_t child_signal(ed::signal_child::get_instance());
    child_signal->add_listener(
              systemctl_process->process_pid()
            , std::bind(
                      &wait_on_firewall::systemctl_exited
                    , std::dynamic_pointer_cast<wait_on_firewall>(c->shared_from_this())
                    , std::placeholders::_1
                    , systemctl_process));

    // it worked, keep the state as it was on entry
    //
    safe_state.release();
}


bool wait_on_firewall::systemctl_exited(
      ed::child_status status
    , cppprocess::process::pointer_t p)
{
    // make sure that on any error the state gets reset to IDLE
    //
    snapdev::safe_object<check_state_t *, reset_state> safe_state;
    safe_state.make_safe(&f_check_state);

    int const result(get_systemctl_result(status, p));
    if(f_check_state == check_state_t::CHECK_STATE_IS_ENABLED)
    {
        switch(result)
        {
        case 0:
            set_status(firewall_status_t::FIREWALL_STATUS_DOWN);

            // start the next stage
            //
            safe_state.release();
            f_check_state = check_state_t::CHECK_STATE_IS_ACTIVE;
            start_check();
            break;

        case 1:
            set_status(firewall_status_t::FIREWALL_STATUS_OFF);
            break;

        //case -1 and -2 are ignored
        }
    }
    else
    {
        snapdev::SAFE_ASSERT(f_check_state == check_state_t::CHECK_STATE_IS_ACTIVE, "f_check_state was expected to be set to check_state_t::CHECK_STATE_IS_ACTIVE");

        switch(result)
        {
        case 0:
            set_status(f_ipwall_is_up
                                ? firewall_status_t::FIREWALL_STATUS_UP
                                : firewall_status_t::FIREWALL_STATUS_ACTIVE);
            break;

        case 1:
            set_status(firewall_status_t::FIREWALL_STATUS_DOWN);
            break;

        }
    }

    return true;
}


int wait_on_firewall::get_systemctl_result(
      ed::child_status status
    , cppprocess::process::pointer_t p)
{
    cppprocess::io_capture_pipe::pointer_t output_pipe(std::dynamic_pointer_cast<cppprocess::io_capture_pipe>(p->get_output_io()));
    cppprocess::io_capture_pipe::pointer_t error_pipe(std::dynamic_pointer_cast<cppprocess::io_capture_pipe>(p->get_error_io()));
    if(status.is_signaled())
    {
        SNAP_LOG_ERROR
            << "\""
            << p->get_command_line()
            << "\" received a signal and died: "
            << status.terminate_signal()
            << "\n -- Console Output:\n"
            << output_pipe->get_output()
            << " -- Console Errors:\n"
            << error_pipe->get_output()
            << SNAP_LOG_SEND;

        return -1;
    }
    else if(status.is_exited())
    {
        if(status.exit_code() == 0)
        {
            return 0;
        }

        SNAP_LOG_RECOVERABLE_ERROR
            << "an error occurred running \""
            << p->get_command_line()
            << "\": "
            << status.exit_code()
            << "\n -- Console Output:\n"
            << output_pipe->get_output()
            << " -- Console Errors:\n"
            << error_pipe->get_output()
            << SNAP_LOG_SEND;

        return 1;
    }

    SNAP_LOG_SEVERE
        << "unknown status returned running \""
        << p->get_command_line()
        << "\":\n"
        << " -- Console Output:\n"
        << output_pipe->get_output()
        << " -- Console Errors:\n"
        << error_pipe->get_output()
        << SNAP_LOG_SEND;

    return -2;
}


void wait_on_firewall::set_status(firewall_status_t status)
{
    if(f_firewall_status != status)
    {
        f_firewall_status = status;
        status_changed(f_firewall_status);
    }
}


wait_on_firewall::callback_id_t wait_on_firewall::add_status_callback(status_callback_t func)
{
    return f_status_callbacks.add_callback(func);
}


bool wait_on_firewall::remove_status_callback(callback_id_t callback_id)
{
    return f_status_callbacks.remove_callback(callback_id);
}


void wait_on_firewall::status_changed(firewall_status_t firewall_status)
{
    snapdev::NOT_USED(firewall_status);

    f_status_callbacks.call(f_firewall_status);
}


firewall_status_t wait_on_firewall::get_firewall_status() const
{
    return f_firewall_status;
}


void wait_on_firewall::msg_ipwall_current_status(ed::message & msg)
{
    // once up, the firewall should never go back down (i.e. the ipwall will
    // not flush an existing firewall)
    //
    // however, if the ipwall service is restarted, we may get an "ipwall
    // is down" message (state=down) and that changes the state of the
    // firewall from "ACTIVE" to "UP"
    //
    f_ipwall_is_up = msg.get_parameter(communicatord::g_name_communicatord_param_status) == communicatord::g_name_communicatord_value_up;

    switch(f_firewall_status)
    {
    case firewall_status_t::FIREWALL_STATUS_UP:
    case firewall_status_t::FIREWALL_STATUS_ACTIVE:
        set_status(f_ipwall_is_up
                        ? firewall_status_t::FIREWALL_STATUS_UP
                        : firewall_status_t::FIREWALL_STATUS_ACTIVE);
        break;

    default:
        // the ipload state is not yet determine or it is not active
        break;

    }
}


void wait_on_firewall::msg_status(ed::message & msg)
{
    if(!msg.has_parameter(communicatord::g_name_communicatord_param_status)
    || !msg.has_parameter(communicatord::g_name_communicatord_param_service))
    {
        return;
    }

    std::string const service(msg.get_parameter(communicatord::g_name_communicatord_param_service));
    if(service == g_name_iplock_service_ipwall)
    {
        // in this case, if the service goes UP, we ignore the message because
        // we will soon receive the IPWALL_CURRENT_STATUS message; in all other
        // cases we make sure that the status gets checked
        //
        std::string const status(msg.get_parameter(communicatord::g_name_communicatord_param_status));
        if(status != communicatord::g_name_communicatord_value_up)
        {
            msg_ipwall_current_status(msg);
        }
    }
}


void wait_on_firewall::msg_ready(ed::message & msg)
{
    ed::connection_with_send_message * c(dynamic_cast<ed::connection_with_send_message *>(this));
    if(c == nullptr)
    {
        throw logic_error("the wait_on_firewall class must also represent a connection_with_send_message.");
    }

    // send a IPWALL_GET_STATUS query message to get the current ipwall
    // status
    //
    // Note: no need to cache the message; if the ipwall starts after
    //       we sent this message, we automatically receive an
    //       IPWALL_CURRENT_STATUS once it is up (it gets broadcast), so no
    //       worries; if the ipwall is not installed on this machine, then
    //       we just get a "not available" error message which we ignore here
    //       (i.e. meaning we never consider the firewall as being active)
    //
    ed::message ipwall_get_status;
    ipwall_get_status.reply_to(msg);
    ipwall_get_status.set_command(communicatord::g_name_communicatord_cmd_ipwall_get_status);
    ipwall_get_status.add_parameter(
              communicatord::g_name_communicatord_param_cache
            , communicatord::g_name_communicatord_value_no);
    c->send_message(ipwall_get_status);
}



} // namespace iplock
// vim: ts=4 sw=4 et

