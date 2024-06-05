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


// iplock
//
#include    <iplock/version.h>


// snaplogger
//
#include    <snaplogger/message.h>
#include    <snaplogger/options.h>


// snapdev
//
#include    <snapdev/gethostname.h>
#include    <snapdev/stringize.h>


// advgetopt
//
#include    <advgetopt/exception.h>


// last include
//
#include    <snapdev/poison.h>



namespace ipwall
{



/** \class server
 * \brief Firewall process class.
 *
 * This class handles firewall requests.
 *
 * There are two requests that this process handles:
 *
 * 1) request to setup a firewall in the first place. This means setting
 *    up the necessary files under /etc so the server boots with a strong
 *    firewall as one would expect on any sane server;
 *
 * 2) request to, generally temporarilly, block IP addresses on the
 *    firewall; when a spam or hacker hit is detected, then a message
 *    is expected to be sent to this firewall process to block the
 *    IP address of that spammer or hacker.
 *
 * \msc
 * hscale = 2;
 * a [label="ipwall"],
 * b [label="communicatord"],
 * c [label="other-process"],
 * d [label="iplock"];
 *
 * #
 * # Register ipwall
 * #
 * a=>a [label="connect socket to snapcommunicator"];
 * a->b [label="REGISTER service=ipwall;version=<VERSION>"];
 * b->a [label="READY"];
 * b->a [label="HELP"];
 * a->b [label="COMMANDS list=HELP,LOG_ROTATE,..."];
 *
 * #
 * # Reconfigure logger
 * #
 * b->a [label="LOG"];
 * a=>a [label="logging::recongigure()"];
 *
 * #
 * # Stop ipwall
 * #
 * b->a [label="STOP"];
 * a=>a [label="exit(0);"];
 *
 * c->a [label="kill -INT a"];
 * a->a [label="STOP"];
 * a=>a [label="exit(0);"];
 *
 * #
 * # Block an IP address
 * #
 * c->b [label="ip/BLOCK uri=...;period=...;reason=..."];
 * b->a [label="BLOCK uri=...;period=...;reason=..."];
 * a->d [label="block IP address with iplock"];
 *
 * #
 * # Unblock an IP address
 * #
 * c->b [label="ip/UNBLOCK uri=..."];
 * b->a [label="UNBLOCK uri=..."];
 * a->d [label="unblock IP address with iplock"];
 *
 * #
 * # Wakeup timer
 * #
 * a->a [label="wakeup timer timed out"];
 * a=>a [label="unblocked an IP address"];
 * \endmsc
 */



/** \brief Command line options.
 *
 * This table includes the server specific options.
 */
advgetopt::option const g_options[] =
{
    advgetopt::end_options()
};


advgetopt::group_description const g_group_descriptions[] =
{
    advgetopt::define_group(
          advgetopt::GroupNumber(advgetopt::GETOPT_FLAG_GROUP_COMMANDS)
        , advgetopt::GroupName("command")
        , advgetopt::GroupDescription("Commands:")
    ),
    advgetopt::define_group(
          advgetopt::GroupNumber(advgetopt::GETOPT_FLAG_GROUP_OPTIONS)
        , advgetopt::GroupName("option")
        , advgetopt::GroupDescription("Options:")
    ),
    advgetopt::end_groups()
};


// until we have C++20 remove warnings this way
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
advgetopt::options_environment const g_options_environment =
{
    .f_project_name = "ipwall",
    .f_group_name = "iplock",
    .f_options = g_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = "IPWALL_OPTIONS",
    .f_environment_variable_intro = "IPWALL_",
    .f_section_variables_name = nullptr,
    .f_configuration_files = nullptr,
    .f_configuration_filename = "ipwall.conf",
    .f_configuration_directories = nullptr,
    .f_environment_flags = advgetopt::GETOPT_ENVIRONMENT_FLAG_SYSTEM_PARAMETERS
                         | advgetopt::GETOPT_ENVIRONMENT_FLAG_PROCESS_SYSTEM_PARAMETERS,
    .f_help_header = "Usage: %p [-<opt>]\n"
                     "where -<opt> is one or more of:",
    .f_help_footer = "%c",
    .f_version = IPLOCK_VERSION_STRING,
    .f_license = "GNU GPL 3",
    .f_copyright = "Copyright (c) 2014-"
                   SNAPDEV_STRINGIZE(UTC_BUILD_YEAR)
                   " by Made to Order Software Corporation -- All Rights Reserved",
    .f_build_date = UTC_BUILD_DATE,
    .f_build_time = UTC_BUILD_TIME,
    .f_groups = g_group_descriptions,
};
#pragma GCC diagnostic pop






/** \brief This function initialize an ipwall server object.
 *
 * The constructor puts in place the command line options by
 * parsing them.
 *
 * As we are at it, we also load the configuration file and
 * setup the logger.
 *
 * \param[in] argc  The command line argc parameter.
 * \param[in] argv  The command line argv parameter.
 */
server::server(int argc, char * argv[])
    : f_opts(g_options_environment)
{
    snaplogger::add_logger_options(f_opts);
    f_opts.finish_parsing(argc, argv);
    if(!snaplogger::process_logger_options(f_opts, "/etc/iplock/logger"))
    {
        // exit on any error
        //
        throw advgetopt::getopt_exit("logger options generated an error.", 0);
    }
}


/** \brief Clean up the firewall.
 *
 * This function is used to do some clean up of the firewall environment.
 */
server::~server()
{
    f_communicator.reset();
}






/** \brief Execute the ipwall run() loop.
 *
 * This function initializes the various connections used by the
 * ipwall process and then runs the event loop.
 *
 * In effect, this function finishes the initialization of the
 * server then listen for events.
 */
void server::run()
{
    // get the server name
    //
    f_server_name = snapdev::gethostname();

    // initialize the communicator and its connections
    //
    f_communicator = ed::communicator::instance();

    f_interrupt = std::make_shared<interrupt>(this);
    f_communicator->add_connection(f_interrupt);

    f_database_timer = std::make_shared<database_timer>(this);
    f_communicator->add_connection(f_database_timer);

    f_wakeup_timer = std::make_shared<wakeup_timer>(this);
    f_communicator->add_connection(f_wakeup_timer);

    f_messenger = std::make_shared<messenger>(this, f_opts);
    f_messenger->finish_initialization();
    f_communicator->add_connection(f_messenger);

    f_communicator->run();
}


/** \brief Setup the firewall on startup.
 *
 * On startup we have to assume that the firewall is not yet properly setup
 * so we run the follow process once.
 *
 * The process gets all the IPs defined in the database and:
 *
 * \li unblock the addresses which timed out
 * \li unblock and (re-)block addresses that are not out of date
 *
 * The unblock and re-block process is necessary in case you are restarting
 * the process. The problem is that the IP address may already be in your
 * firewall. If that's the case, just blocking would duplicate it, which
 * would slow down the firewall for nothing and also would not properly
 * unblock the IP when we receive the timeout because that process would
 * only unblock one instance.
 */
void server::setup_firewall()
{
#if 0
    // make sure we are also connected with the Cassandra database
    //
    if(!f_firewall_table)
    {
        return;
    }

    int64_t const now(snap::snap_communicator::get_current_date());
    int64_t const limit(now + 60LL * 1000000LL); // "lose" 1 min. precision

    libdbproxy::row::pointer_t row(f_firewall_table->getRow(f_server_name));
    row->clearCache();

    // the first row we keep has a date we use to know when to wake up
    // next and drop that IP from our firewall
    //
    bool first(true);

    block_info_t::block_info_vector_t to_block_list;

    // run through the entire table
    //
    auto column_predicate(std::make_shared<libdbproxy::cell_range_predicate>());
    column_predicate->setCount(100);
    column_predicate->setIndex(); // behave like an index
    for(;;)
    {
        row->readCells(column_predicate);
        libdbproxy::cells const cells(row->getCells());
        if(cells.isEmpty())
        {
            // it looks like we are done
            break;
        }

        for(libdbproxy::cells::const_iterator it(cells.begin());
                                                         it != cells.end();
                                                         ++it)
        {
            libdbproxy::cell::pointer_t cell(*it);

            // first we want to unblock that IP address
            //
            QString const uri(cell->getValue().stringValue());

            try
            {
                // this one should always work since we saved it in the
                // database, only between versions the format could change
                //
                block_info_t info(uri);

                QByteArray const key(it.key());
                int64_t const drop_date(libdbproxy::safeInt64Value(key, 0, -1));
                if(drop_date < limit)
                {
                    // unblock the IP, just in case
                    //
                    //info.iplock_unblock();
                    SNAP_LOG_TRACE( "No longer blocking ip address '")(info.get_ip())("'");

                    // save with the new status of UNBANNED
                    //
                    info.save(f_firewall_table, f_server_name);

                    // now drop that row
                    //
                    // Note: the save() does that for new keys, old keys may
                    //       not get deleted properly so I kept this code
                    //       for now... generally speaking, it is safer
                    //       to have it here anyway
                    //
                    row->dropCell(key);
                }
                else
                {
                    // this IP is still expected to be blocked, so
                    // re-block it
                    //
                    if(first)
                    {
                        // on the first one, we want to mark that as the
                        // time when the block has to be dropped
                        //
                        // Note: only the first one is necessary since these
                        //       are sorted by date in the database
                        //
                        first = false;
                        f_wakeup_timer->set_timeout_date(drop_date);
                    }

                    // block the IP
                    //
                    //info.iplock_block();
                    to_block_list.push_back( info );

                    // show all the IPs (not useful at all time to reprint
                    // all the IPs, it should go a lot faster by not doing
                    // so.)
                    //
                    //SNAP_LOG_TRACE( "Add to block list address='")(info.get_ip())("', scheme='")(info.get_scheme())("'.");

                    // no save necessary, it is already as it needs to be
                }
            }
            catch(std::exception const & e)
            {
                SNAP_LOG_ERROR("an exception occurred while initializing the firewall: ")(e.what());
            }
        }
    }

    std::for_each(
              f_blocks.begin()
            , f_blocks.end()
            , [&, limit](block_info_t & info)
            {
                if(limit >= info.get_block_limit())
                {
                    // passed the limit already so we can unblock now
                    //
                    //info.iplock_unblock();
                }
                else
                {
                    to_block_list.push_back( info );

                    // show all the pending IPs
                    //
                    //SNAP_LOG_TRACE( "Add pending IP address to block list: '")(info.get_ip())("'");
                }

                // always save the IP so we know that such and such was
                // banned before (i.e. recidivists can be counted now)
                //
                info.save(f_firewall_table, f_server_name);
            }
        );

    SNAP_LOG_INFO("Block ")(to_block_list.size())(" IPs (including ")(f_blocks.size())(" from the pending IP address list).");

    f_blocks.clear();

    std::string const private_folder("/var/cache/snapwebsites/private");
    QDir pf( private_folder.c_str() );
    if( !pf.exists() )
    {
        pf.mkdir( private_folder.c_str() );
        if( ::chmod( private_folder.c_str(), 0700 ) != 0 )
        {
            // this should not happen, but at least let admins know
            //
            int const e(errno);
            SNAP_LOG_WARNING("chmod(\"")(private_folder)(", 0700\") failed. (errno: ")(e)(", ")(strerror(e));
        }
    }

    std::stringstream ss;
    ss << private_folder << "/iplock." << getpid();
    std::string const outfile(ss.str());
    {
        std::ofstream ip_list( outfile );

        for( auto const & info : to_block_list )
        {
            ip_list << info.get_ip().toUtf8().data()
                    << " "
                    << info.get_scheme().toUtf8().data()
                    << std::endl;
        }
    }

    // Run the iplock process, but in batch mode.
    //
    {
        snap::process iplock_process("block bulk IP address");
        iplock_process.set_command("iplock");

        // whether we block or unblock the specified IP address
        iplock_process.add_argument("--batch");
        iplock_process.add_argument(outfile.c_str());

        // keep the stderr output
        iplock_process.add_argument("2>&1");

        int const r(iplock_process.run());
        if(r != 0)
        {
            // Note: if the IP was not already defined, this command
            //       generates an error
            //
            int const e(errno);
            QString const output(iplock_process.get_output(true));
            SNAP_LOG_ERROR("an error occurred (")
                    (r)
                    (") trying to run \"")
                    (iplock_process.get_name())
                    ("\", errno: ")
                    (e)
                    (" -- ")
                    (strerror(e))
                    ("\nConsole output:\n")
                    (output);
        }
    }

    f_firewall_up = true;

#ifndef _DEBUG
    // Only remove if we are not in debug mode
    //
    unlink( outfile.c_str() );
#endif

    // send a "FIREWALLUP" message to let others know that the firewall
    // is up
    //
    // TODO
    // some daemons, like snapserver does, should wait on that
    // signal before starting... (but ipwall is optional,
    // so be careful on how you handle that one! in snapserver
    // we first check whether ipwall is active on the
    // computer and if so request the message.)
    //
    snap::snap_communicator_message firewall_up_message;
    firewall_up_message.set_command("FIREWALL_UP");
    firewall_up_message.set_service(".");
    f_messenger->send_message(firewall_up_message);
#endif
}


/** \brief Timeout is called whenever an IP address needs to be unblocked.
 *
 * This function is called when the wakeup timer times out. We set the
 * date when the wakeup timer has to time out to the next IP that
 * times out. That information comes from the Cassandra database.
 *
 * Certain IP addresses are permanently added to the firewall,
 * completely preventing the offender from accessing us for the
 * rest of time.
 */
void server::process_timeout()
{
    // STOP received?
    // the timer may still tick once after we received a STOP event
    // so we want to check here to make sure we are good.
    //
    if(f_stop_received)
    {
        // TBD: note that this means we are not going to unblock any
        //      old IP block if we already received a STOP...
        return;
    }

    snapdev::timespec_ex const now(snapdev::timespec_ex::gettime());

    f_blocks.erase(
            std::remove_if(
                  f_blocks.begin()
                , f_blocks.end()
                , [&, now](block_info & info)
                {
                    if(now > info.get_block_limit())
                    {
                        // this one timed out, remove from the
                        // firewall and the f_blocks vector
                        // (so in effect we "lose" that IP information
                        // but we do not want to use too much RAM either;
                        // in a properly setup system it should be really
                        // rare)
                        //
                        info.iplock_unblock();

                        return true;
                    }

                    return false;
                }
            )
            , f_blocks.end()
        );

#if 0
    // make sure we are connected to cassandra
    //
    if(f_firewall_table)
    {
        // we are interested only by the columns that concern us, which
        // means columns that have a name starting with the server name
        // as defined in the snapserver.conf file
        //
        //      <server-name> '/' <date with leading zeroes in minutes (10 digits)>
        //

        libdbproxy::row::pointer_t row(f_firewall_table->getRow(f_server_name));
        row->clearCache();

        // unblock IP addresses which have a timeout in the past
        //
        auto column_predicate = std::make_shared<libdbproxy::cell_range_predicate>();
        QByteArray limit;
        libdbproxy::setInt64Value(limit, 0);  // whatever the first column is
        column_predicate->setStartCellKey(limit);
        libdbproxy::setInt64Value(limit, now + 60LL * 1000000LL);  // until now within 1 minute
        column_predicate->setEndCellKey(limit);
        column_predicate->setCount(100);
        column_predicate->setIndex(); // behave like an index
        for(;;)
        {
            row->readCells(column_predicate);
            libdbproxy::cells const cells(row->getCells());
            if(cells.isEmpty())
            {
                // it looks like we are done
                break;
            }

            // any entries we grab here, we drop right now
            //
            for(libdbproxy::cells::const_iterator it(cells.begin());
                                                             it != cells.end();
                                                             ++it)
            {
                libdbproxy::cell::pointer_t cell(*it);

                // first we want to unblock that IP address
                //
                QString const uri(cell->getValue().stringValue());

                try
                {
                    // remove the block, it timed out
                    //
                    block_info_t info(uri);
                    info.iplock_unblock();

                    // save the entry with the new status
                    //
                    info.save(f_firewall_table, f_server_name);

                    // now drop that row
                    //
                    // Note: the save() does that for new keys, old keys may
                    //       not get deleted properly so I kept this code
                    //       for now...
                    //
                    QByteArray const key(cell->columnKey());
                    row->dropCell(key);
                }
                catch(std::exception const & e)
                {
                    SNAP_LOG_ERROR("an exception occurred while checking IPs in the process_timeout() function: ")(e.what());
                }
            }
        }
    }
#endif

    next_wakeup();
}


/** \brief Restart process to reconnect.
 *
 * The setup_firewall() function failed and set the reconnect_timer to
 * get this function called a little later.
 *
 * Here we simply send a DATABASE_STATUS message to get things restarted.
 */
void server::process_reconnect()
{
    is_db_ready();
}


/** \brief Send the DATABASE_STATUS to snapdbproxy.
 *
 * This function builds a message and sends it to snapdbproxy. It is
 * used whenever we need to know whether the database is accessible.
 *
 * Note that the function itself does not return true or false. If
 * you need to know whether we are currently connected to the
 * snapdbproxy daemon, check the f_database pointer; if not nullptr
 * then we are connected and you can send a CQL order.
 */
void server::is_db_ready()
{
    ed::message isdbready_message;
    isdbready_message.set_command("DATABASE_STATUS");
    isdbready_message.set_service("prinbee");
    f_messenger->send_message(isdbready_message);
}


/** \brief Called whenever the firewall table changes.
 *
 * Whenever the firewall table changes, the next wake up date may change.
 * This function makes sure to determine what the smallest date is and
 * saves that in the wakeup timer if such a smaller date exists.
 *
 * \note
 * At this time, the setup() function does this on its own since it has
 * the information without the need for yet another access to the
 * database.
 */
void server::next_wakeup()
{
    // by default there is nothing to wake up for
    //
    snapdev::timespec_ex limit;
#if 0
    if(f_firewall_table)
    {
        libdbproxy::row::pointer_t row(f_firewall_table->getRow(f_server_name));

        // determine whether there is another IP in the table and if so at
        // what time we need to wake up to remove it from the firewall
        //
        auto column_predicate(std::make_shared<libdbproxy::cell_range_predicate>());
        column_predicate->setCount(1);
        column_predicate->setIndex(); // behave like an index
        row->clearCache();
        row->readCells(column_predicate);
        libdbproxy::cells const cells(row->getCells());
        if(!cells.isEmpty())
        {
            QByteArray const key(cells.begin().key());
            limit = libdbproxy::safeInt64Value(key, 0, -1);
        }
        else
        {
            // no entries means no need to wakeup
            //
            limit = 0;
        }
    }
    else
#endif
         if(!f_blocks.empty())
    {
        // each time we add an entry to f_blocks, we re-sort the vector
        // so the first entry is always the smallest
        //
        limit = f_blocks.front().get_block_limit();
    }

    snapdev::timespec_ex zero(0, 0);
    if(limit > zero)
    {
        // we have a valid date to wait on,
        // save it in our wakeup timer
        //
        f_wakeup_timer->set_timeout_date(limit);
    }
    //else -- there is nothing to wake up for...
}


bool server::is_firewall_up() const
{
    return f_firewall_up;
}


void server::process_database_ready()
{
#if 0
    try
    {
        // connect to Cassandra and get a pointer to our firewall table
        //
        f_database.connect();
        f_firewall_table = f_database.get_table("firewall");

        // now that we are fully registered, setup the firewall
        //
        setup_firewall();
    }
    catch(std::runtime_error const & e)
    {
        SNAP_LOG_WARNING
            << "failed to connect to snapdbproxy: "
            << e.what()
            << SNAP_LOG_SEND;

        // make sure the table is not defined
        //
        f_database.disconnect();
        f_firewall_table.reset();

        // in this particular case, we do not automatically get
        // another DATABASEREADY message so we have to send another
        // DATABASESTATUS at some point, but we want to give Cassandra
        // a break for a little while and thus ask to be awaken in
        // 30 seconds before we try again
        //
        std::int64_t const now(snap::snap_communicator::get_current_date());
        std::int64_t const reconnect_date(now + 30LL * 1000000LL);
        f_reconnect_timer->set_timeout_date(reconnect_date);
    }
#endif
}


void server::process_no_database()
{
#if 0
    f_cassandra.disconnect();
    f_firewall_table.reset();
#endif
}


/** \brief Called whenever we receive the STOP command or equivalent.
 *
 * This function makes sure the snapfirewall exits as quickly as
 * possible.
 *
 * \li Marks the messenger as done.
 * \li Disabled wakeup timer.
 * \li UNREGISTER from snapcommunicator.
 * \li Remove wakeup timer from snapcommunicator.
 *
 * \note
 * If the f_messenger is still in place, then just sending the
 * UNREGISTER is enough to quit normally. The socket of the
 * f_messenger will be closed by the snapcommunicator server
 * and we will get a HUP signal. However, we get the HUP only
 * because we first mark the messenger as done.
 *
 * \param[in] quitting  Set to true if we received a QUITTING message.
 */
void server::stop(bool quitting)
{
    f_stop_received = true;

    // stop the timers immediately, although that will not prevent
    // one more call to their callbacks which thus still have to
    // check the f_stop_received flag
    //
    if(f_database_timer != nullptr)
    {
        f_database_timer->set_enable(false);
        f_database_timer->set_timeout_date(-1);
    }
    if(f_wakeup_timer != nullptr)
    {
        f_wakeup_timer->set_enable(false);
        f_wakeup_timer->set_timeout_date(-1);
    }

    if(f_messenger != nullptr)
    {
        f_messenger->unregister_communicator(quitting);

        // we can remove our messenger immediately, the communicator lower
        // layer is responsible for sending messages, etc.
        //
        if(f_communicator != nullptr)
        {
            f_communicator->remove_connection(f_messenger);
        }
    }

    if(f_communicator != nullptr)
    {
        f_communicator->remove_connection(f_database_timer);
        f_communicator->remove_connection(f_wakeup_timer);
        f_communicator->remove_connection(f_interrupt);
    }
}



void server::block_ip(ed::message const & msg)
{
    // message data could be tainted, we need to protect ourselves against
    // unwanted exceptions
    //
    try
    {
        // check the "uri" and "period" parameters
        //
        // the URI may include a protocol and an IP separated by "://"
        // if no "://" appears, then only an IP is expected
        //
        block_info info(msg);
        info.set_ban_count(1); // newly created ban count is always 0, so just set to 1

#if 0
        // save in our list of blocked IP addresses
        //
        if(f_firewall_table != nullptr)
        {
            // actually add to the firewall
            //
            info.iplock_block();

            info.save(f_firewall_table, f_server_name);
        }
        else
#endif
        {
            // cache in memory for later, once we connect to our database,
            // we will save those there
            //
            // TODO: I do not, right now, think that we could have such an
            //       attack that memory would be a problem because some of
            //       the largest DDoS only make use of 10 to 20,000 IPs
            //       Even a 50,000 IPs attack is just not quite likely
            //       before you connect to the databse unless somehow
            //       snapfirewall never gets a connection...
            //
            auto const & it(std::find(
                      f_blocks.begin()
                    , f_blocks.end()
                    , info));
            if(it == f_blocks.end())
            {
                // block the IP now
                //
                info.iplock_block();

                // this is a new block, keep it as is
                //
                f_blocks.push_back(info);
            }
            else
            {
                // there is a matching old block, keep the new info in
                // the old block but update as required
                //
                it->keep_longest(info);

                // no need to block the IP, it already is
                //
                // (Note: it may have changed from some scheme to "all"
                //        inside the keep_longest() function...)
            }

            // keep them sorted, as in the Cassandra database
            //
            // even if we do not push a new entry, the keep_longest()
            // may end up changing the order of the existing items...
            //
            std::sort(f_blocks.begin(), f_blocks.end());
        }

        next_wakeup();
    }
    catch(std::exception const & e)
    {
        SNAP_LOG_ERROR
            << "an exception occurred while checking the BLOCK message in the block_ip() function: "
            << e.what()
            << SNAP_LOG_SEND;

        // we probably should not catch all exceptions here (i.e. on a
        // bad_alloc, we probably want to quit...)
        //
        // in any event, this probably means we just lost our connections
        // and need to try to reconnect
        //
#if 0
        f_cassandra.disconnect();
        f_firewall_table.reset();
#endif

        // check with snapdbproxy whether it is still connected or not
        //
        is_db_ready();
    }
}


void server::unblock_ip(ed::message const & msg)
{
    // message data could be tainted, we need to protect ourselves against
    // unwanted exceptions
    //
    try
    {
        // check the "uri" and "period" parameters
        //
        // the URI may include a protocol and an IP separated by "://"
        // if no "://" appears, then only an IP is expected
        //
        block_info info(msg);

        // remove from the firewall
        //
        info.iplock_unblock();

#if 0
        // save in our list of blocked IP addresses
        //
        if(f_firewall_table != nullptr)
        {
            info.save(f_firewall_table, f_server_name);
        }
        else
        {
            // find the block in the cache, it should be there unless we
            // lost the connection with the Cassandra cluster
            //
            auto const & it(std::find(
                      f_blocks.begin()
                    , f_blocks.end()
                    , info));
            if(it != f_blocks.end())
            {
                // by erasing the info we lose that data, but that only
                // happens when we are not connected to the database;
                // the connection to the database should happen very
                // quickly so most blocks will not be removed before
                // they get saved
                //
                f_blocks.erase(it);
            }
        }
#endif

        next_wakeup();
    }
    catch(std::exception const & e)
    {
        SNAP_LOG_ERROR
            << "an exception occurred while checking the UNBLOCK message in the unblock_ip() function: "
            << e.what()
            << SNAP_LOG_SEND;

        // we probably should not catch all exceptions here (i.e. on a
        // bad_alloc, we probably want to quit...)
        //
        // in any event, this probably means we just lost our connections
        // and need to try to reconnect
        //
#if 0
        f_database.disconnect();
        f_firewall_table.reset();
#endif

        // check with snapdbproxy whether it is still connected or not
        //
        is_db_ready();
    }
}



} // namespace ipwall
// vim: ts=4 sw=4 et
