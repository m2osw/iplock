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
#include    "interrupt.h"

#include    "server.h"


// snaplogger
//
#include <snaplogger/message.h>


// C
//
#include <signal.h>


// last include
//
#include <snapdev/poison.h>



namespace ipwall
{



/** \brief The interrupt initialization.
 *
 * The interrupt uses the signalfd() function to obtain a file descriptor
 * to listen on incoming Unix signals.
 *
 * Specifically, it listens on the SIGINT signal, which is the equivalent
 * to the Ctrl-C.
 *
 * \param[in] s  The firewall server we are listening for.
 */
interrupt::interrupt(server * s)
    : signal(SIGINT)
    , f_server(s)
{
    unblock_signal_on_destruction();
    set_name("interrupt");
}


/** \brief Call the stop function of the snaplock object.
 *
 * When this function is called, the signal was received and thus we are
 * asked to quit as soon as possible.
 */
void interrupt::process_signal()
{
    // we simulate the STOP, so pass 'false' (i.e. not quitting)
    //
    f_server->stop(false);
}



} // namespace ipwall
// vim: ts=4 sw=4 et
