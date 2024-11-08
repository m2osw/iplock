// Copyright (c) 2022-2024  Made to Order Software Corp.  All Rights Reserved
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


// iplock
//
#include    <iplock/version.h>
#include    <iplock/knock_ports.h>


// advgetopt
//
#include    <advgetopt/exception.h>
#include    <advgetopt/advgetopt.h>
#include    <advgetopt/utils.h>
#include    <advgetopt/validator_duration.h>


// libaddr
//
#include    <libaddr/addr_parser.h>


// libexcept
//
#include    <libexcept/file_inheritance.h>


// eventdispatcher
//
#include    <eventdispatcher/signal_handler.h>


// snapdev
//
#include    <snapdev/raii_generic_deleter.h>
#include    <snapdev/stringize.h>


// snaplogger
//
#include    <snaplogger/message.h>
#include    <snaplogger/options.h>


// last include
//
#include    <snapdev/poison.h>



/** \mainpage
 *
 * \image html iplock-logo.jpg
 *
 * The knock-knock command allows you to open a door by knocking on
 * pre-specified ports as defined in your firewall with the
 * `"knock = ..."` parameter.
 *
 * This command line tool accepts the same set of ports with a protocol
 * set to `tcp:` or `udp:` as that ipload parameter.
 */


/** \brief Command line options.
 *
 * This table includes all the options supported by knock-knock
 * command line.
 */
advgetopt::option const g_options[] =
{
    // COMMANDS
    //

    // OPTIONS
    //
    advgetopt::define_option(
          advgetopt::Name("delay")
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS
            , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("0.1s")
        , advgetopt::Validator("duration")
        , advgetopt::Help("Delay between each knock.")
    ),
    advgetopt::define_option(
          advgetopt::Name("protocol")
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS
            , advgetopt::GETOPT_FLAG_COMMAND_LINE
            , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("tcp")
        , advgetopt::Help("Default to TCP if protocol is not defined.")
    ),
    advgetopt::define_option(
          advgetopt::Name("verbose")
        , advgetopt::ShortName('v')
        , advgetopt::Flags(advgetopt::option_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS
            , advgetopt::GETOPT_FLAG_COMMAND_LINE>())
        , advgetopt::Help("Make the knocking verbose.")
    ),
    advgetopt::define_option(
          advgetopt::Name("--")
        , advgetopt::Flags(advgetopt::command_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS
            , advgetopt::GETOPT_FLAG_REQUIRED
            , advgetopt::GETOPT_FLAG_MULTIPLE
            , advgetopt::GETOPT_FLAG_DEFAULT_OPTION
            , advgetopt::GETOPT_FLAG_SHOW_USAGE_ON_ERROR>())
        , advgetopt::Help(" The hostname to knock followed by the list of protocol and ports to activate (i.e. <hostname> <protocol>:<port> ...).")
    ),
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




// TODO: once we have stdc++20, remove all defaults
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
advgetopt::options_environment const g_options_environment =
{
    .f_project_name = "knock_knock",
    .f_group_name = "iplock",
    .f_options = g_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = "KNOCK_KNOCK_OPTIONS",
    .f_environment_variable_intro = nullptr,
    .f_section_variables_name = nullptr,
    .f_configuration_files = nullptr,
    .f_configuration_filename = "knock-knock",
    .f_configuration_directories = nullptr,
    .f_environment_flags = advgetopt::GETOPT_ENVIRONMENT_FLAG_SYSTEM_PARAMETERS
                         | advgetopt::GETOPT_ENVIRONMENT_FLAG_PROCESS_SYSTEM_PARAMETERS,
    .f_help_header = "Usage: %p [-<opt>] <hostname> [<protocol>:]<port> ...\n"
                     "the <protocol> is optional, it defaults to tcp: unless you used the --protocol option.\n"
                     "at least one <port> is required.\n"
                     "where -<opt> is one or more of:",
    .f_help_footer = nullptr,
    .f_version = IPLOCK_VERSION_STRING,
    .f_license = "GNU GPL 3",
    .f_copyright = "Copyright (c) 2022-"
                    SNAPDEV_STRINGIZE(UTC_BUILD_YEAR)
                    " by Made to Order Software Corporation",
    .f_build_date = UTC_BUILD_DATE,
    .f_build_time = UTC_BUILD_TIME,
    .f_groups = g_group_descriptions,
};
#pragma GCC diagnostic pop




class knock_knock
{
public:
                                knock_knock(int argc, char * argv[]);

    int                         run();

private:
    advgetopt::getopt           f_opts;
    double                      f_delay = 1.0;
    bool                        f_tcp = true;
    bool                        f_verbose = true;
};



knock_knock::knock_knock(int argc, char * argv[])
    : f_opts(g_options_environment)
{
    snaplogger::add_logger_options(f_opts);
    f_opts.finish_parsing(argc, argv);
    if(!snaplogger::process_logger_options(
                  f_opts
                , "/etc/iplock/logger"
                , std::cout
                , !isatty(fileno(stdin))))
    {
        // exit on any error
        //
        throw advgetopt::getopt_exit("logger options generated an error.", 1);
    }

    f_tcp = f_opts.get_string("protocol") == "tcp";

    advgetopt::validator_duration::convert_string(
                  f_opts.get_string("delay")
                , advgetopt::validator_duration::VALIDATOR_DURATION_DEFAULT_FLAGS
                , f_delay);
}


int knock_knock::run()
{
    std::size_t const max(f_opts.size("--"));
    if(max < 2)
    {
        SNAP_LOG_ERROR
            << "at least one port must be specified after the hostname."
            << SNAP_LOG_SEND;
        return 1;
    }

    iplock::protocol_port::vector_t ports;
    for(std::size_t idx(1); idx < max; ++idx)
    {
        std::string const user_port(f_opts.get_string("--", idx));

        std::string const error(iplock::parse_ports(user_port, ports));
        if(!error.empty())
        {
            SNAP_LOG_ERROR
                << "could not parse port \""
                << user_port
                << "\": "
                << error
                << SNAP_LOG_SEND;
            return 1;
        }
    }

    std::string const hostname(f_opts.get_string("--", 0));
    for(auto & p : ports)
    {
        if(p.f_protocol == IPPROTO_IP)
        {
            p.f_protocol = f_tcp ? IPPROTO_TCP : IPPROTO_UDP;
        }
        addr::addr const a(addr::string_to_addr(
                          hostname
                        , std::string()
                        , p.f_port
                        , p.protocol_name()));

        int const s(a.create_socket(addr::addr::SOCKET_FLAG_NONBLOCK));
        if(s < 0)
        {
            SNAP_LOG_ERROR
                << "error creating socket for: "
                << p.protocol_name()
                << ':'
                << p.f_port
                << SNAP_LOG_SEND;
            return 1;
        }
        snapdev::raii_fd_t safe_socket(s);

        if(p.f_protocol == IPPROTO_UDP)
        {
            // for UDP we need to send a message
            //
            char data[1] = {};
			int const r(a.sendto(s, data, sizeof(data)));
            if(r == -1)
            {
                int const e(errno);
                SNAP_LOG_ERROR
                    << "could not send UDP message for: \""
                    << p.protocol_name()
                    << ':'
                    << p.f_port
                    << "\": "
                    << e
                    << ", "
                    << strerror(e)
                    << "."
                    << SNAP_LOG_SEND;
                return 1;
            }
        }
        else
        {
            int const r(a.connect(s));
            if(r != 0
            && errno != EINPROGRESS)
            {
                int const e(errno);
                SNAP_LOG_ERROR
                    << "could not connect to \""
                    << p.protocol_name()
                    << "://"
                    << hostname
                    << ':'
                    << p.f_port
                    << "\": "
                    << e
                    << ", "
                    << strerror(e)
                    << "."
                    << SNAP_LOG_SEND;
                return 1;
            }
        }

        safe_socket.reset();

        if(f_verbose)
        {
            SNAP_LOG_INFO
                << "knocked on \""
                << p.protocol_name()
                << "://"
                << hostname
                << ':'
                << p.f_port
                << "\"."
                << SNAP_LOG_SEND;
        }

        usleep(f_delay * 1'000'000.0);
    }

    return 0;
}



int main(int argc, char * argv[])
{
    ed::signal_handler::create_instance();
    libexcept::verify_inherited_files();
    libexcept::collect_stack_trace();

    try
    {
        knock_knock kk(argc, argv);
        return kk.run();
    }
    catch(advgetopt::getopt_exit const & e)
    {
        return e.code();
    }
    catch(std::exception const & e)
    {
        std::cerr << "error:ipload: an exception occurred: " << e.what() << '\n';
    }
    catch(...)
    {
        std::cerr << "error:ipload: received an unknown exception.\n";
    }

    return 1;
}



// vim: ts=4 sw=4 et
