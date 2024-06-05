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
#include    "server.h"


// snaplogger
//
#include    <snaplogger/message.h>


// eventdispatcher
//
#include    <eventdispatcher/signal_handler.h>


// libexcept
//
#include    <libexcept/file_inheritance.h>


// advgetopt
//
#include    <advgetopt/exception.h>


// last include
//
#include    <snapdev/poison.h>



int main(int argc, char * argv[])
{
    ed::signal_handler::create_instance();
    libexcept::verify_inherited_files();
    libexcept::collect_stack_trace();

    try
    {
        // create an instance of the snap_firewall object
        //
        ipwall::server wall(argc, argv);

        // Now run!
        //
        wall.run();

        // exit normally (i.e. we received a STOP message on our
        // connection with the Snap! Communicator service.)
        //
        return 0;
    }
    catch(advgetopt::getopt_exit const & e)
    {
        return e.code();
    }
    catch(libexcept::exception_t const & e )
    {
        SNAP_LOG_FATAL
            << "ipwall: libexcept::exception_t caught! "
            << e.what()
            << SNAP_LOG_SEND;
    }
    catch(std::exception const & e)
    {
        SNAP_LOG_FATAL
            << "ipwall: std::exception caught! "
            << e.what()
            << SNAP_LOG_SEND;
    }
    catch(...)
    {
        SNAP_LOG_FATAL
            << "ipwall: unknown exception caught!"
            << SNAP_LOG_SEND;
    }

    return 1;
}


// vim: ts=4 sw=4 et
