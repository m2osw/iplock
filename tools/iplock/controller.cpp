// Copyright (c) 2014-2022  Made to Order Software Corp.  All Rights Reserved
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
 * \brief iplock tool.
 *
 * This tool offers a way to easily and safely add and remove
 * IP addresses one wants to block/unblock \em temporarily.
 *
 * The tool makes use of the ipset command line to add and remove IPs
 * to a list or another. The lists are managed by the ipload tool, which
 * means they are created at boot time.
 */


// self
//
#include    "controller.h"

#include    "block.h"
#include    "count.h"
#include    "list.h"
#include    "list_allowed_sets.h"
#include    "flush.h"
#include    "unblock.h"


// advgetopt
//
#include    <advgetopt/exception.h>


// iplock
//
#include    <iplock/version.h>


// snaplogger
//
#include    <snaplogger/message.h>
#include    <snaplogger/options.h>


// snapdev
//
#include    <snapdev/stringize.h>


// C++
//
#include    <iostream>


// C
//
#include    <unistd.h>


// last include
//
#include    <snapdev/poison.h>



namespace tool
{



char const * const g_suffixes[]
{
    "",
    "_ipv4",
    "_ipv6",

    // end list
    nullptr
};



/** \brief Command line options.
 *
 * This table includes the options supported by iplock on the
 * command line.
 *
 * The configuration file is loaded separately from the normal
 * advgetopt scheme to increase security (avoid users who would
 * load their own version of the configuration file).
 */
advgetopt::option const g_iplock_options[] =
{
    // COMMANDS
    //
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
        , advgetopt::Help("Remove all the IP addresses from the specified set.")
    ),
    advgetopt::define_option(
          advgetopt::Name("list")
        , advgetopt::ShortName('l')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
                    , advgetopt::GETOPT_FLAG_SHOW_USAGE_ON_ERROR>())
        , advgetopt::Help("List the IP addresses currently defined in the named set.")
    ),
    advgetopt::define_option(
          advgetopt::Name("list-allowed-sets")
        , advgetopt::ShortName('L')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
                    , advgetopt::GETOPT_FLAG_SHOW_USAGE_ON_ERROR>())
        , advgetopt::Help("Display a list of sets that iplock has access to.")
    ),
    advgetopt::define_option(
          advgetopt::Name("unblock")
        , advgetopt::ShortName('u')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE>())
        , advgetopt::Help("Unblock the specified IP address. If not blocked, do nothing.")
    ),

    // OPTIONS
    //
    advgetopt::define_option(
          advgetopt::Name("ips")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Define the name of a file with a list of IPs to --block or --unblock.")
    ),
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
          advgetopt::Name("set")
        , advgetopt::ShortName('s')
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("unwanted")
        , advgetopt::Help("Define the name of the set where the IP is added or removed. Defaults to \"unwanted\".")
    ),
    advgetopt::define_option(
          advgetopt::Name("total")
        , advgetopt::ShortName('t')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::Help("Write the grand total when --count is specified.")
    ),
    advgetopt::define_option(
          advgetopt::Name("verbose")
        , advgetopt::ShortName('v')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::Help("Show commands being executed.")
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
#pragma GCC diagnostic ignored "-Wpedantic"
advgetopt::options_environment const g_iplock_options_environment =
{
    .f_project_name = "iplock",
    .f_group_name = "iplock",
    .f_options = g_iplock_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = "IPLOCK_OPTIONS",
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
    .f_license = "GNU GPL 3",
    .f_copyright = "Copyright (c) 2007-"
                        SNAPDEV_STRINGIZE(UTC_BUILD_YEAR)
                        " by Made to Order Software Corporation",
    .f_build_date = UTC_BUILD_DATE,
    .f_build_time = UTC_BUILD_TIME,
    .f_groups = g_group_descriptions,
};






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
controller::controller(int argc, char * argv[])
    : f_opts(g_iplock_options_environment)
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
        throw advgetopt::getopt_exit("iplock:error: logger options generated an error.", 1);
    }
}


/** \brief Save the command pointer in f_command.
 *
 * This function saves the specified \p c command pointer to the f_command
 * parameter.
 *
 * It is done that way so we can easily detect whether more than one
 * command was specified on the command line.
 *
 * \param[in] c  The pointer to the command to save in iplock.
 */
void controller::set_command(command::pointer_t c)
{
    if(f_command != nullptr)
    {
        SNAP_LOG_FATAL
            << "you can only specify one command; found \""
            << f_command->get_command_name()
            << "\" and \""
            << c->get_command_name()
            << "\"."
            << SNAP_LOG_SEND;
        exit(1);
    }
    f_command = c;
}


/** \brief Before running a command, make sure we are root.
 *
 * This function gets called by the run_command() function.
 *
 * The function exits the process with an error if becoming root is not
 * possible. This can happen if:
 *
 * \li the process is run by systemd and systemd prevents such; or
 * \li the binary is not marked with the 's' bit.
 *
 * \return true if the function succeeds.
 */
bool controller::make_root()
{
    if(setuid(0) != 0)
    {
        perror("iplock:error: setuid(0)");
        return false;
    }
    if(setgid(0) != 0)
    {
        perror("iplock:error: setgid(0)");
        return false;
    }

    return true;
}


advgetopt::getopt & controller::opts()
{
    return f_opts;
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
int controller::run_command()
{
    // define the command
    //
    // since the user may specify any number of commands, we use
    // the set_command() function to make sure that only one
    // gets set... if theuser has more on the command line, then
    // we print an error and exit with 1.
    //
    if(f_opts.is_defined("block"))
    {
        set_command(std::make_shared<block>(this));
    }
    if(f_opts.is_defined("count"))
    {
        set_command(std::make_shared<count>(this));
    }
    if(f_opts.is_defined("flush"))
    {
        set_command(std::make_shared<flush>(this));
    }
    if(f_opts.is_defined("list"))
    {
        set_command(std::make_shared<list>(this));
    }
    if(f_opts.is_defined("list-allowed-sets"))
    {
        set_command(std::make_shared<list_allowed_sets>(this));
    }
    if(f_opts.is_defined("unblock"))
    {
        set_command(std::make_shared<unblock>(this));
    }

    // no command specified?
    //
    if(f_command == nullptr)
    {
        SNAP_LOG_ERROR
            << "you must specify a command such as: --block, --unblock, --count, or --flush."
            << SNAP_LOG_SEND;
        return 1;
    }

    // all iptables/ipset commands require the user to be root.
    //
    if(f_command->needs_root())
    {
        if(!make_root())
        {
            return 1;
        }
    }

    f_command->run();

    return f_command->exit_code();
}



} // namespace tool
// vim: ts=4 sw=4 et
