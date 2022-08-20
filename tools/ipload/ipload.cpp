// Copyright (c) 2022  Made to Order Software Corp.  All Rights Reserved
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
 * \brief ipload tool
 *
 * This tool loads configuration files in order to build the firewall
 * scripts and upload those script using iptables.
 */


// self
//
#include    "ipload.h"


// iplock
//
#include    <iplock/version.h>


// libaddr
//
#include    <libaddr/addr_parser.h>


// advgetopt
//
#include    <advgetopt/exception.h>


// snaplogger
//
#include    <snaplogger/options.h>


// boost lib
//
#include    <boost/preprocessor/stringize.hpp>
//#include    <boost/algorithm/string/replace.hpp>
//#include    <boost/filesystem.hpp>
//#include    <boost/lexical_cast.hpp>


// C++ lib
//
//#include    <iostream>
//#include    <fstream>
//#include    <sstream>


// C
//
//#include    <net/if.h>
#include    <unistd.h>


// snapdev lib
//
#include    <snapdev/poison.h>






/** \brief Command line options.
 *
 * This table includes all the options supported by ipload on the
 * command line.
 */
advgetopt::option const g_options[] =
{
    // COMMANDS
    //
    advgetopt::define_option(
          advgetopt::Name("batch")
        , advgetopt::ShortName('a')
        , advgetopt::Flags(advgetopt::command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Text file containing rules to add to the firewall.")
    ),
    advgetopt::define_option(
          advgetopt::Name("block")
        , advgetopt::ShortName('b')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("Block the speficied IP address. If already blocked, do nothing.")
    ),
    advgetopt::define_option(
          advgetopt::Name("count")
        , advgetopt::ShortName('n')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("Return the number of times each IP address was"
                " blocked since the last counter reset. You may use the"
                " --reset along this command to atomically reset the"
                " counters as you retrieve them.")
    ),
    advgetopt::define_option(
          advgetopt::Name("flush")
        , advgetopt::ShortName('f')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
                    , advgetopt::GETOPT_FLAG_SHOW_USAGE_ON_ERROR>())
        , advgetopt::Help("Flush all rules specified in chain.")
    ),
    advgetopt::define_option(
          advgetopt::Name("unblock")
        , advgetopt::ShortName('u')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE>())
        , advgetopt::Help("Unblock the specified IP address. If not already blocked, do nothing.")
    ),

    // OPTIONS
    //
    advgetopt::define_option(
          advgetopt::Name("quiet")
        , advgetopt::ShortName('q')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::Help("Prevent iptables from printing messages in stdout or stderr.")
    ),
    advgetopt::define_option(
          advgetopt::Name("reset")
        , advgetopt::ShortName('r')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::Help("Use with the --count command to retrieve the counters and reset them atomically.")
    ),
    advgetopt::define_option(
          advgetopt::Name("scheme")
        , advgetopt::ShortName('s')
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Configuration file to define iptables commands. This is one name (no '/' or '.'). The default is \"http\".")
    ),
    advgetopt::define_option(
          advgetopt::Name("total")
        , advgetopt::ShortName('t')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::Help("Write the grand total only when --count is specified.")
    ),
    advgetopt::define_option(
          advgetopt::Name("verbose")
        , advgetopt::ShortName('v')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::Help("Show comands being executed.")
    ),
    advgetopt::define_option(
          advgetopt::Name("--")
        , advgetopt::Flags(advgetopt::command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_DEFAULT_OPTION
                    , advgetopt::GETOPT_FLAG_MULTIPLE>())
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
    .f_project_name = "ipload",
    .f_group_name = nullptr,
    .f_options = g_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = "IPLOAD_OPTIONS",
    .f_environment_variable_intro = nullptr,
    .f_section_variables_name = nullptr,
    .f_configuration_files = nullptr,
    .f_configuration_filename = nullptr,
    .f_configuration_directories = nullptr,
    .f_environment_flags = advgetopt::GETOPT_ENVIRONMENT_FLAG_SYSTEM_PARAMETERS
                         | advgetopt::GETOPT_ENVIRONMENT_FLAG_PROCESS_SYSTEM_PARAMETERS,
    .f_help_header = "Usage: %p [-<opt>] [ip]\n"
                     "where -<opt> is one or more of:",
    .f_help_footer = nullptr,
    .f_version = IPLOCK_VERSION_STRING,
    .f_license = "This software is licenced under the MIT",
    .f_copyright = "Copyright (c) 2007-"
                    BOOST_PP_STRINGIZE(UTC_BUILD_YEAR)
                    " by Made to Order Software Corporation",
    .f_build_date = UTC_BUILD_DATE,
    .f_build_time = UTC_BUILD_TIME,
    .f_groups = g_group_descriptions,
};
#pragma GCC diagnostic pop






/** \brief Initialize the iplock object.
 *
 * This function parses the command line and  determines the command
 * that the end user selected (i.e. --block, --unblock, or --count.)
 *
 * If the user specified --help or --version, then this function
 * prints the help screen or version of iplock and exits the process
 * immediately.
 *
 * If no command was specified on the command line, then an error
 * is written to stderr and the process exits immediately.
 *
 * \param[in] argc  The number of arguments in argv.
 * \param[in] argv  The argument strings.
 */
ipload::ipload(int argc, char * argv[])
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


///** \brief Save the command pointer in f_command.
// *
// * This function saves the specified \p c command pointer to the f_command
// * parameter.
// *
// * It is done that way so we can very easily detect whether more than one
// * command was specified on the command line.
// *
// * \param[in] c  The pointer to the command line to save in iplock.
// */
//void iplock::set_command(command::pointer_t c)
//{
//    if(f_command != nullptr)
//    {
//        std::cerr << "iplock:error: you can only specify one command at a time, one of: --block, --unblock, or --count." << std::endl;
//        exit(1);
//    }
//    f_command = c;
//}


/** \brief Before running a command, make sure we are root.
 *
 * This function gets called by the run_command() function.
 *
 * The function exits the process with an error if becoming root is not
 * possible. This can happen if (1) the process is run by systemd and
 * systemd prevents such, (2) the binary is not marked with the 's'
 * bit.
 */
void ipload::make_root()
{
    if(setuid(0) != 0)
    {
        perror("iplock:error: setuid(0)");
        exit(1);
    }
    if(setgid(0) != 0)
    {
        perror("iplock:error: setgid(0)");
        exit(1);
    }
}


/** \brief Run the selected command.
 *
 * The constructor parses the command line options and from that
 * deterimes which command the user selected. This function runs
 * that command by calling its run() function.
 *
 * This function first makes sure the user is running as root.
 * This may change in the future if some of the commands may
 * otherwise be run as a regular user.
 */
void ipload::run()
{
    // all iptables commands require the user to be root.
    //
    make_root();

    //f_command->run();
}



// vim: ts=4 sw=4 et
