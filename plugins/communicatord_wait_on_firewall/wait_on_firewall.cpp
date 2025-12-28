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

/** \file
 * \brief Implementation of the wait_on_firewall plugin.
 *
 * When you start a service which accepts TCP or UDP connections from the
 * Internet (i.e. public IP address), you should first make sure that the
 * firewall is up. One way is to setup the systemctl service so it starts
 * only after the ipload service ran:
 *
 * \code
 * [Unit]
 * ...
 * After=ipload.service
 * ...
 * \endcode
 *
 * This is certainly the easiest. However, a service which may run on a
 * system without ipload cannot have such in its systemd `.service` file.
 * For this reason, we instead have a function to make your service
 * aware of the firewall status and starts or does not start depending
 * on settings.
 *
 * Here are the currently possible states:
 *
 * \li FIREWALL_STATUS_NOT_READY -- the firewaill status is not yet known;
 *     this is the default status until this plugin has had time to run the
 *     systemctl commands necessary to make sure the ipload service ran
 * \li FIREWALL_STATUS_OFF -- the ipload service is disabled; we consider that
 *     there is no firewall up at all
 * \li FIREWALL_STATUS_DOWN -- the ipload service is enabled but did not yet
 *     run to install the firewall
 * \li FIREWALL_STATUS_UP -- the ipload service is enabled and ran successfully
 *     so the firewall is up
 * \li FIREWALL_STATUS_ACTIVE -- the ipload service is enabled and ran and
 *     also we detected that the ipwall service is ready to receive
 *     IPWALL_BLOCK messages
 *
 * \note
 * The status goes from "not ready" to either "off" or "down". Then from time
 * to time, the status may change. The object has a timer which wakes up the
 * test once every minute and as a consequence the states may change. When
 * that happens, the plugin broadcasts the new state to services listening
 * for the message.
 */

// self
//
#include    "wait_on_firewall.h"



// iplock
//
#include    <iplock/exception.h>
#include    <iplock/names.h>


// eventdispatcher
//
#include    <eventdispatcher/connection_with_send_message.h>
#include    <eventdispatcher/dispatcher_support.h>
#include    <eventdispatcher/names.h>


// communicator
//
#include    <communicator/names.h>
#include    <communicator/plugins/base_connection.h>
#include    <communicator/plugins/communicatord.h>


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
namespace wait_on_firewall
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
 * As a result, you have the following possible states:
 *
 * \li firewall status is unknown [FIREWALL_STATUS_UNKNOWN]: something's wrong; it should never enter this state
 * \li firewall is not ready [FIREWALL_STATUS_NOT_READY]: ipload was not checked yet
 * \li firewall is off [FIREWALL_STATUS_OFF]: the ipload command is disabled
 * \li firewall is down [FIREWALL_STATUS_DOWN]: the ipload command is enabled but has not run yet
 * \li firewall is up [FIREWALL_STATUS_UP]: ipload ran, but ipwall is not yet available
 * \li firewall is active [FIREWALL_STATUS_ACTIVE]: ipload ran and ipwall is running
 *
 * \note
 * The unknown status may happen between incompatible versions (i.e. two
 * versions of the iplock library with different versions).
 *
 * Once the status is UP it can bounce between UP and ACTIVE. It should not go
 * back to NOT_READY. However, if you disable the ipload service, then that is
 * detected and the status goes back to OFF. In that case, the firewall is
 * still up until the next reboot. Such changes should not happen on their
 * own, however.
 *
 * The sitter is used to verify that the iptables do not get flushed entirely.
 * The firewall plugin in the sitter should be moved to this project, though.
 */


SERVERPLUGINS_START(wait_on_firewall)
    , ::serverplugins::description(
            "Periodically check the status of the firewall environment.")
    , ::serverplugins::dependency("communicatord")
    , ::serverplugins::help_uri("https://snapwebsites.org/help")
    , ::serverplugins::categorization_tag("firewall")
    , ::serverplugins::categorization_tag("security")
SERVERPLUGINS_END(wait_on_firewall)



/** \brief Initialize wait_on_firewall signals.
 *
 * This function terminates the initialization of the wait_on_firewall plugin
 * by registering for different events.
 */
void wait_on_firewall::bootstrap()
{
    SERVERPLUGINS_LISTEN(wait_on_firewall, communicator_daemon::communicatord, initialize, std::placeholders::_1);
    SERVERPLUGINS_LISTEN0(wait_on_firewall, communicator_daemon::communicatord, terminate);
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
 *
 * \param[in] opts  A set of command line options.
 */
void wait_on_firewall::on_initialize(advgetopt::getopt & opts)
{
    snapdev::NOT_USED(opts);

    ed::connection * c(dynamic_cast<ed::connection *>(this));
    if(c == nullptr)
    {
        throw logic_error("the wait_on_firewall class must be used with a connection class.");
    }

    communicator_daemon::communicatord::pointer_t s(plugins()->get_server<communicator_daemon::communicatord>());
    if(s == nullptr)
    {
        throw logic_error("the wait_on_firewall is a plugin and it must have a communicatord as its server.");
    }
    ed::dispatcher::pointer_t dispatcher(s->get_dispatcher());
    if(dispatcher == nullptr)
    {
        throw logic_error("the wait_on_firewall plugin must have a server with a dispatcher ready.");
    }
    dispatcher->add_matches({
            DISPATCHER_MATCH(communicator::g_name_communicator_cmd_iplock_get_status, &wait_on_firewall::msg_iplock_get_status),
            DISPATCHER_MATCH(g_name_iplock_cmd_ipwall_current_status, &wait_on_firewall::msg_ipwall_current_status),
            ed::define_match(
                  ed::Expression(communicator::g_name_communicator_cmd_status)
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
    // again and again but we also call the function once now
    //
    f_status_timer = std::make_shared<ed::timer>(IPWALL_STATUS_CHECK_DELAY);
    f_status_timer->get_callback_manager().add_callback([this](ed::timer::pointer_t t)
        {
            snapdev::NOT_USED(t);
            this->check_status();
            return true;
        });

    // immediately start the process of checking for the status for the first time
    //
    // (this makes use of a background process and we get the response
    // through the ed::communicator from a child signal, so it is not
    // instant)
    //
    check_status();
}


void wait_on_firewall::on_terminate()
{
    f_status_timer.reset();
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
 *
 * \return The function always returns true.
 */
bool wait_on_firewall::check_status()
{
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

    // systemctl is-enabled -q ipload
    //   or
    // systemctl is-active -q ipload
    //
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

    //ed::connection * c(dynamic_cast<ed::connection *>(this));
    //if(c == nullptr)
    //{
    //    throw logic_error("the wait_on_firewall class must be used with a connection class.");
    //}

    ed::signal_child::pointer_t child_signal(ed::signal_child::get_instance());
    //ed::connection::weak_pointer_t w(c->shared_from_this());
    child_signal->add_listener(
              systemctl_process->process_pid()
            , [this, systemctl_process](ed::child_status status)
            {
                return this->systemctl_exited(status, systemctl_process);
            });

    // it worked, keep the state as it was on entry
    //
    safe_state.release();
}


bool wait_on_firewall::systemctl_exited(
      ed::child_status const & status
    , cppprocess::process::pointer_t p)
{
    // make sure that on any error the state gets reset to IDLE
    //
    snapdev::safe_object<check_state_t *, reset_state> safe_state;
    safe_state.make_safe(&f_check_state);

    int const result(p->get_result(status));
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
    else // if(f_check_state == check_state_t::CHECK_STATE_IS_ACTIVE)
    {
        snapdev::SAFE_ASSERT(f_check_state == check_state_t::CHECK_STATE_IS_ACTIVE, "f_check_state was expected to be set to check_state_t::CHECK_STATE_IS_ACTIVE");

        switch(result)
        {
        case 0:
            set_status(f_ipwall_is_up
                        ? firewall_status_t::FIREWALL_STATUS_ACTIVE
                        : firewall_status_t::FIREWALL_STATUS_UP);
            break;

        case 1:
            set_status(firewall_status_t::FIREWALL_STATUS_DOWN);
            break;

        }
    }

    return true;
}


void wait_on_firewall::set_status(firewall_status_t status)
{
    if(f_firewall_status != status)
    {
        f_firewall_status = status;

        // get the server which has a messenger to send messages
        //
        communicator_daemon::communicatord::pointer_t s(plugins()->get_server<communicator_daemon::communicatord>());
        if(s == nullptr)
        {
            throw logic_error("the wait_on_firewall is a plugin and it must have a communicatord as its server.");
        }

        ed::message iplock_status_msg;
        iplock_status_msg.set_service(communicator::g_name_communicator_service_local_broadcast);
        iplock_status_msg.set_command(communicator::g_name_communicator_cmd_iplock_current_status);
        iplock_status_msg.add_parameter(
                  communicator::g_name_communicator_param_firewall_status
                , to_string(f_firewall_status));
        iplock_status_msg.add_parameter(
                  communicator::g_name_communicator_param_cache
                , communicator::g_name_communicator_value_no);
        s->broadcast_message(iplock_status_msg);
    }
}


void wait_on_firewall::msg_iplock_get_status(ed::message & msg)
{
    communicator_daemon::base_connection::pointer_t conn(msg.user_data<communicator_daemon::base_connection>());
    if(conn == nullptr)
    {
        return;
    }

    ed::message iplock_status_msg;
    iplock_status_msg.reply_to(msg);
    iplock_status_msg.set_command(communicator::g_name_communicator_cmd_iplock_current_status);
    iplock_status_msg.add_parameter(
              communicator::g_name_communicator_param_firewall_status
            , to_string(f_firewall_status));
    iplock_status_msg.add_parameter(
              communicator::g_name_communicator_param_cache
            , communicator::g_name_communicator_value_no);
    conn->send_message_to_connection(iplock_status_msg);
}


//wait_on_firewall::callback_id_t wait_on_firewall::add_status_callback(status_callback_t func)
//{
//    return f_status_callbacks.add_callback(func);
//}


//bool wait_on_firewall::remove_status_callback(callback_id_t callback_id)
//{
//    return f_status_callbacks.remove_callback(callback_id);
//}


//void wait_on_firewall::status_changed(firewall_status_t firewall_status)
//{
//    snapdev::NOT_USED(firewall_status);
//
//    f_status_callbacks.call(f_firewall_status);
//}


//firewall_status_t wait_on_firewall::get_firewall_status() const
//{
//    return f_firewall_status;
//}


//bool wait_on_firewall::is_firewall_up() const
//{
//    switch(f_firewall_status)
//    {
//    case firewall_status_t::FIREWALL_STATUS_UP:
//    case firewall_status_t::FIREWALL_STATUS_ACTIVE:
//        return true;
//
//    default:
//        return false;
//
//    }
//    snapdev::NOT_REACHED();
//}


void wait_on_firewall::msg_ipwall_current_status(ed::message & msg)
{
    if(!msg.has_parameter(communicator::g_name_communicator_param_status))
    {
        return;
    }

    // once up, the firewall should never go back down (i.e. by default
    // ipload does not flush an existing firewall)
    //
    // however, if the ipwall service is restarted, we may get an "ipwall
    // is down" message (state=down) and that changes the state of the
    // firewall from "ACTIVE" to "UP"
    //
    f_ipwall_is_up = msg.get_parameter(communicator::g_name_communicator_param_status) == communicator::g_name_communicator_value_up;

    switch(f_firewall_status)
    {
    case firewall_status_t::FIREWALL_STATUS_UP:
    case firewall_status_t::FIREWALL_STATUS_ACTIVE:
        set_status(f_ipwall_is_up
                        ? firewall_status_t::FIREWALL_STATUS_ACTIVE
                        : firewall_status_t::FIREWALL_STATUS_UP);
        break;

    default:
        // the ipload state is not yet determined or it is down
        break;

    }
}


void wait_on_firewall::msg_status(ed::message & msg)
{
    if(!msg.has_parameter(communicator::g_name_communicator_param_status)
    || !msg.has_parameter(communicator::g_name_communicator_param_service))
    {
        return;
    }

    std::string const service(msg.get_parameter(communicator::g_name_communicator_param_service));
    if(service == g_name_iplock_service_ipwall)
    {
        // in this case, if the service goes UP, we ignore the message because
        // we will soon receive the IPWALL_CURRENT_STATUS message; in all other
        // cases we make sure that the status gets checked
        //
        std::string const status(msg.get_parameter(communicator::g_name_communicator_param_status));
        if(status != communicator::g_name_communicator_value_up)
        {
            msg_ipwall_current_status(msg);
        }
    }
}


void wait_on_firewall::msg_ready(ed::message & msg)
{
    snapdev::NOT_USED(msg);

    // get the server which has a messenger to send messages
    //
    communicator_daemon::communicatord::pointer_t s(plugins()->get_server<communicator_daemon::communicatord>());
    if(s == nullptr)
    {
        throw logic_error("the wait_on_firewall is a plugin and it must have a communicatord as its server.");
    }

    //ed::connection_with_send_message * c(dynamic_cast<ed::connection_with_send_message *>(this));
    //if(c == nullptr)
    //{
    //    throw logic_error("the wait_on_firewall class must also represent a connection_with_send_message.");
    //}

    // send an IPWALL_GET_STATUS query message to get the current ipwall
    // status
    //
    // Note: no need to cache the message; if the ipwall starts after
    //       we sent this message, we automatically receive an
    //       IPWALL_CURRENT_STATUS once it is up (it gets broadcast), so no
    //       worries; if the ipwall is not installed on this machine, then
    //       we just get a "not available" error message which we ignore here
    //       (i.e. meaning we never consider the firewall as being active)
    //
    ed::message ipwall_get_status_msg;
    ipwall_get_status_msg.set_service(g_name_iplock_service_ipwall);
    ipwall_get_status_msg.set_command(g_name_iplock_cmd_ipwall_get_status);
    ipwall_get_status_msg.add_parameter(
              communicator::g_name_communicator_param_cache
            , communicator::g_name_communicator_value_no);
    s->forward_message(ipwall_get_status_msg);
}


char const * to_string(firewall_status_t status)
{
    switch(status)
    {
    case firewall_status_t::FIREWALL_STATUS_UNKNOWN:
        return "unknown";

    case firewall_status_t::FIREWALL_STATUS_NOT_READY:
        return "not_ready";

    case firewall_status_t::FIREWALL_STATUS_OFF:
        return "off";

    case firewall_status_t::FIREWALL_STATUS_DOWN:
        return "down";

    case firewall_status_t::FIREWALL_STATUS_UP:
        return "up";

    case firewall_status_t::FIREWALL_STATUS_ACTIVE:
        return "active";

    }
    snapdev::NOT_REACHED();
}


firewall_status_t from_string(char const * status)
{
    if(status != nullptr
    && *status != '\0')
    {
        switch(*status)
        {
        case 'a':
            if(strcmp(status, "active") == 0)
            {
                return firewall_status_t::FIREWALL_STATUS_ACTIVE;
            }
            break;

        case 'd':
            if(strcmp(status, "down") == 0)
            {
                return firewall_status_t::FIREWALL_STATUS_DOWN;
            }
            break;

        case 'n':
            if(strcmp(status, "not_ready") == 0)
            {
                return firewall_status_t::FIREWALL_STATUS_NOT_READY;
            }
            break;

        case 'o':
            if(strcmp(status, "off") == 0)
            {
                return firewall_status_t::FIREWALL_STATUS_OFF;
            }
            break;

        case 'u':
            if(strcmp(status, "up") == 0)
            {
                return firewall_status_t::FIREWALL_STATUS_UP;
            }
            break;

        }
    }

    return firewall_status_t::FIREWALL_STATUS_UNKNOWN;
}



} // namespace wait_on_firewall
} // namespace iplock
// vim: ts=4 sw=4 et
