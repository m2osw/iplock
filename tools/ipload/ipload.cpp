// Copyright (c) 2022-2025  Made to Order Software Corp.  All Rights Reserved
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

#include    "basic.h"
#include    "clear_firewall.h"
#include    "default_firewall.h"
#include    "utils.h"


// iplock
//
#include    <iplock/exception.h>
#include    <iplock/version.h>


// communicatord
//
#include    <communicatord/flags.h>


// libaddr
//
#include    <libaddr/addr_parser.h>
#include    <libaddr/iface.h>


// advgetopt
//
#include    <advgetopt/exception.h>
#include    <advgetopt/utils.h>


// snaplogger
//
#include    <snaplogger/message.h>
#include    <snaplogger/options.h>


// snapdev
//
#include    <snapdev/file_contents.h>
#include    <snapdev/glob_to_list.h>
#include    <snapdev/join_strings.h>
#include    <snapdev/pathinfo.h>
#include    <snapdev/stringize.h>
#include    <snapdev/string_replace_many.h>


// C
//
#include    <net/if.h>
#include    <readline/readline.h>
#include    <stdlib.h>
#include    <unistd.h>


// last include
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
          advgetopt::Name("dry-run")
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Alias("verify")
        , advgetopt::Help("parse the rules for errors; do not install them.")
    ),
    advgetopt::define_option(
          advgetopt::Name("flush")
        , advgetopt::ShortName('F')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("flush the firewall back to its defaults.")
    ),
    advgetopt::define_option(
          advgetopt::Name("load")
        , advgetopt::ShortName('L')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("load or reload all the rules.")
    ),
    advgetopt::define_option(
          advgetopt::Name("load-basic")
        , advgetopt::ShortName('B')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("only load the basic firewall (mainly for test purposes).")
    ),
    advgetopt::define_option(
          advgetopt::Name("load-default")
        , advgetopt::ShortName('D')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("only load the default firewall (mainly for test purposes).")
    ),
    advgetopt::define_option(
          advgetopt::Name("show")
        , advgetopt::ShortName('s')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("show the rules; like --load but instead of loading the rules to iptables, show them in your console.")
    ),
    advgetopt::define_option(
          advgetopt::Name("show-dependencies")
        , advgetopt::ShortName('d')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("show the rules dependency tree in a Makefile like format.")
    ),
    advgetopt::define_option(
          advgetopt::Name("verify")
        , advgetopt::ShortName('V')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("verify the rules; like --load but without the final step actually loading the rules in iptables.")
    ),

    // OPTIONS
    //
    advgetopt::define_option(
          advgetopt::Name("check-network-status")
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
                    , advgetopt::GETOPT_FLAG_CONFIGURATION_FILE>())
        , advgetopt::Help("Check and report network status. This is always done once on boot.")
    ),
    advgetopt::define_option(
          advgetopt::Name("comment")
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
                    , advgetopt::GETOPT_FLAG_CONFIGURATION_FILE>())
        , advgetopt::Help("Add comments to the output of the --show command.")
    ),
    advgetopt::define_option(
          advgetopt::Name("ip-lists")
        , advgetopt::ShortName('l')
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
                    , advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("/usr/share/iplock/ip-list:/var/lib/iplock/ip-list:/etc/iplock/ip-list")
        , advgetopt::Help("Colon separated paths to the IP lists to load in ipsets.")
    ),
    advgetopt::define_option(
          advgetopt::Name("no-defaults")
        , advgetopt::ShortName('N')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
                    , advgetopt::GETOPT_FLAG_CONFIGURATION_FILE>())
        , advgetopt::Help("Prevent ipload from loading the default firewall rules.")
    ),
    advgetopt::define_option(
          advgetopt::Name("quiet")
        , advgetopt::ShortName('q')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::Help("Prevent iptables from printing messages in stdout or stderr.")
    ),
    advgetopt::define_option(
          advgetopt::Name("rules")
        , advgetopt::ShortName('r')
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
                    , advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("/usr/share/iplock/ipload:/etc/iplock/ipload")
        , advgetopt::Help("Colon separated paths to the rules to load in iptables.")
    ),
    advgetopt::define_option(
          advgetopt::Name("show-variables")
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::Help("Show the complete list of variables after all were loaded from configuration files.")
    ),
    advgetopt::define_option(
          advgetopt::Name("verbose")
        , advgetopt::ShortName('v')
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::Help("Show comands being executed.")
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
    .f_group_name = "iplock",
    .f_options = g_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = "IPLOAD_OPTIONS",
    .f_environment_variable_intro = nullptr,
    .f_section_variables_name = nullptr,
    .f_configuration_files = nullptr,
    .f_configuration_filename = "ipload.conf",
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
#pragma GCC diagnostic pop



constexpr std::string_view      YES_I_AM_SURE = "YES I AM SURE!";
constexpr std::string_view      g_prompt_start = "Are you sure you want to reset your firewall?\nType \"";
constexpr std::string_view      g_prompt_end = "\" without the quotes to go ahead:\n";
constexpr std::string_view      g_prompt = snapdev::join_string_views<g_prompt_start, YES_I_AM_SURE, g_prompt_end>;

constexpr std::string_view      g_network_status = "/run/iplock/network.status";

constexpr std::string_view      g_basic_flag = "/run/iplock/basic.installed";
constexpr std::string_view      g_firewall_flag = "/run/iplock/firewall.installed";
constexpr std::string_view      g_default_flag = "/run/iplock/default.installed";





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

    f_verbose = f_opts.is_defined("verbose");
    f_quiet = f_opts.is_defined("quiet");

    if(f_opts.is_defined("flush"))
    {
        f_command |= COMMAND_FLUSH;
    }
    if(f_opts.is_defined("load"))
    {
        f_command |= COMMAND_LOAD;
    }
    if(f_opts.is_defined("load-basic"))
    {
        if(f_opts.is_defined("no-defaults"))
        {
            SNAP_LOG_ERROR
                << "the --no-defaults command line option cannot be used along the --load-basic command."
                << SNAP_LOG_SEND;
            throw advgetopt::getopt_exit("mutually exclusive command line options.", 1);
        }
        f_command |= COMMAND_LOAD_BASIC;
    }
    if(f_opts.is_defined("load-default"))
    {
        f_command |= COMMAND_LOAD_DEFAULT;
    }
    if(f_opts.is_defined("show"))
    {
        f_command |= COMMAND_SHOW;
    }
    if(f_opts.is_defined("show-dependencies"))
    {
        f_command |= COMMAND_SHOW_DEPENDENCIES;
    }
    if(f_opts.is_defined("verify"))
    {
        f_command |= COMMAND_VERIFY;
    }

    switch(f_command)
    {
    case COMMAND_FLUSH:
    case COMMAND_LOAD:
    case COMMAND_LOAD_BASIC:
    case COMMAND_LOAD_DEFAULT:
    case COMMAND_SHOW:
    case COMMAND_SHOW_DEPENDENCIES:
    case COMMAND_VERIFY:
        break;

    case COMMAND_SHOW | COMMAND_SHOW_DEPENDENCIES:
        // we will show both in this case
        //
        f_command = COMMAND_SHOW;
        f_show_dependencies = true;
        break;

    case 0:
        SNAP_LOG_ERROR
            << "you need to enter one of the supported commands: --load, --show, --show-dependencies, or --verify."
            << SNAP_LOG_SEND;
        throw advgetopt::getopt_exit("command missing.", 1);

    default:
        SNAP_LOG_ERROR
            << "you cannot use more than one command simultaneously (one of --load, --show, or --verify)."
            << SNAP_LOG_SEND;
        throw advgetopt::getopt_exit("multiple commands.", 1);

    }
}


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
 *
 * \return 1 if an error occurs, 0 otherwise.
 */
int ipload::run()
{
    switch(f_command)
    {
    case COMMAND_FLUSH:
        make_root();
        if(!load_data())
        {
            if(f_opts.is_defined("no-defaults"))
            {
                return 1;
            }
            SNAP_LOG_TODO
                << "could not load user defined ipload data; TODO: implement flush of default firewall."
                << SNAP_LOG_SEND;
        }
        if(!convert())
        {
            return 1;
        }
        if(!remove_from_iptables())
        {
            return 1;
        }

        SNAP_LOG_INFO
            << "flushed successfully."
            << SNAP_LOG_SEND;
        break;

    case COMMAND_LOAD:
        {
            check_network_status();

            // all iptables commands require the user to be root.
            //
            make_root();
            load_basic(false);
            std::string flag_name(g_firewall_flag);
            if(!load_data())
            {
                if(f_opts.is_defined("no-defaults"))
                {
                    return 1;
                }

                // for our own protection we want a default firewall that blocks
                // everything (including SSH...)
                //
                create_defaults();

                flag_name = g_default_flag;
            }
            if(!convert())
            {
                return 1;
            }
            if(!create_sets())
            {
                return 1;
            }
            if(!load_to_iptables(flag_name))
            {
                return 1;
            }

            SNAP_LOG_INFO
                << "loaded rules successfully."
                << SNAP_LOG_SEND;
        }
        break;

    case COMMAND_LOAD_BASIC:
        make_root();
        check_network_status();
        load_basic(true);

        SNAP_LOG_INFO
            << "load basic done."
            << SNAP_LOG_SEND;
        break;

    case COMMAND_LOAD_DEFAULT:
        make_root();
        check_network_status();
        create_defaults();
        if(!convert())
        {
            return 1;
        }
        if(!create_sets())
        {
            return 1;
        }
        if(!load_to_iptables(std::string(g_default_flag)))
        {
            return 1;
        }

        SNAP_LOG_INFO
            << "loaded default successfully."
            << SNAP_LOG_SEND;
        break;

    case COMMAND_SHOW:
        if(!load_data())
        {
            return 1;
        }
        f_show_comments = f_opts.is_defined("comment");
        if(!convert())
        {
            return 1;
        }
        if(f_show_dependencies)
        {
            show_dependencies();
        }
        show();
        break;

    case COMMAND_SHOW_DEPENDENCIES:
        if(!load_data())
        {
            return 1;
        }
        {
            bool const r(convert());
            show_dependencies();
            if(!r)
            {
                return 1;
            }
        }
        break;

    case COMMAND_VERIFY:
        if(!load_data())
        {
            return 1;
        }
        if(!convert())
        {
            return 1;
        }
        break;

    }

    return 0;
}


void ipload::check_network_status()
{
    bool raise_flag(true);
    if(access(g_network_status.data(), F_OK) == 0)
    {
        if(!f_opts.is_defined("check-network-status"))
        {
            return;
        }

        // this may have been a systemctl restart so don't raise a flag
        //
        raise_flag = false;
    }

    std::string interfaces_up;
    addr::iface::pointer_vector_t const interfaces(addr::iface::get_local_addresses());
    for(auto const & i : *interfaces)
    {
        if((i->get_flags() & IFF_UP) != 0
        && i->get_name() != "lo")        // "lo" will already be up
        {
            if(!interfaces_up.empty())
            {
                interfaces_up += ", ";
            }
            interfaces_up += i->get_name();

        }
    }

    if(!interfaces_up.empty())
    {
        SNAP_LOG_WARNING
            << "network interface(s) \""
            << interfaces_up
            << "\" were already up."
            << SNAP_LOG_SEND;

        if(raise_flag)
        {
            std::string message;
            message += "ipload detected that network interfaces \"";
            message += interfaces_up;
            message += "\" were already up while first installing the "
                       "firewall (i.e. at boot time)";
            communicatord::flag::pointer_t f(COMMUNICATORD_FLAG_UP(
                  "iplock"
                , "ipload"
                , "network-up"
                , message));
            f->set_state(communicatord::flag::state_t::STATE_UP)
                .set_priority(90) // this is considered a security issue
                .add_tag("security")
                .add_tag("firewall")
                .set_manual_down(true) // this test is not 100% reliable, so make it manual
                .save();
        }
    }

    std::ofstream out(g_network_status.data());
    if(out.is_open())
    {
        out << (!interfaces_up.empty() ? "up" : "down")
            << '\n';
    }
}


bool ipload::load_data()
{
    if(f_variables == nullptr)
    {
        f_variables = std::make_shared<advgetopt::variables>();
    }
    if(f_verify == nullptr)
    {
        f_verify = std::make_shared<advgetopt::variables>();
    }

    std::string const paths(f_opts.get_string("rules"));

    advgetopt::string_list_t path_list;
    advgetopt::split_string(paths, path_list, {":"});

    // for each file we find anywhere we want to remember about it otherwise
    // we will miss the "??-<name>.conf" in directories where upper folders
    // do not include a file.
    //
    // For example, we have this variables file:
    //
    //     /usr/share/iplock/ipload/general/variables.conf
    //
    // and without this, we would never find:
    //
    //     /etc/iplock/ipload/general/ipload.d/50-variables.conf
    //
    // the conf_files registers the filenames without the "path" part
    // and that gets re-added to the glob variable on the following iteration
    //
    std::set<std::string> conf_files;

    // first determine all the filenames; we put "general" files in a separate
    // list so that way we can load them first and give all the other files
    // the ability to override data found in the general files
    //
    // further we want to load the files under "/usr/share/iplock/ipload" first
    // then the files under "/etc/iplock/ipload"; finally we reapeat that loop
    // to load the corresponding "ipload.d"
    //
    advgetopt::string_list_t all_generals[3];
    advgetopt::string_list_t all_filenames[3];
    for(auto const & p : path_list)
    {
        std::string path(p);
        if(p.back() != '/')
        {
            path += '/';
        }
        snapdev::glob_to_list<std::set<std::string>> glob;
        if(!glob.read_path<
                 snapdev::glob_to_list_flag_t::GLOB_FLAG_IGNORE_ERRORS,
                 snapdev::glob_to_list_flag_t::GLOB_FLAG_RECURSIVE>(path + "*.conf"))
        {
            if(glob.get_last_error_errno() == ENOENT)
            {
                // the directory does not exist, just ignore that entry
                //
                continue;
            }
            SNAP_LOG_ERROR
                << "failed reading rules directory: \""
                << path
                << "/*.conf\"."
                << SNAP_LOG_SEND;
            return false;
        }

        // files found in previous folders are cumulative
        // if they do not exist in the new folders, it's simply ignored
        //
        for(auto const & n : conf_files)
        {
            glob.insert(path + n);
        }

        if(glob.empty())
        {
            SNAP_LOG_VERBOSE
                << "no rules found under \""
                << path
                << "\"."
                << SNAP_LOG_SEND;
            continue;
        }

        // convert all the files in sets of config parameter loaded by advgetopt
        //
        advgetopt::string_list_t generals[3];
        advgetopt::string_list_t filenames[3];
        for(auto const & n : glob)
        {
            // avoid repeated ipload.d sub-directories
            // and ignore invalid iplock.d (this could be a mistake since
            // we are inthe iplock project...)
            //
            if(n.find("/iplock.d/") != std::string::npos)
            {
                SNAP_LOG_MINOR
                    << "an \".../iplock.d/...\" sub-folder is not supported in \""
                    << n
                    << "\"; did you mean to use \".../ipload.d/...\"?"
                    << SNAP_LOG_SEND;
            }
            else if(n.find("/ipload.d/") == std::string::npos)
            {
                conf_files.insert(n.substr(path.length()));

                std::string const basename(snapdev::pathinfo::basename(n));
                if(n.find("/general/") != std::string::npos)
                {
                    generals[0].push_back(n);

                    advgetopt::string_list_t extra_files(advgetopt::insert_group_name(path + basename, "ipload", "iplock", false));
                    for(auto const & f : extra_files)
                    {
                        if(std::find(generals[1].begin(), generals[1].end(), f) == generals[1].end()
                        && std::find(generals[2].begin(), generals[2].end(), f) == generals[2].end())
                        {
                            generals[1].push_back(f);
                        }
                    }

                    advgetopt::string_list_t specialized_files(advgetopt::insert_group_name(n, "ipload", "iplock", false));
                    for(auto const & f : specialized_files)
                    {
                        if(std::find(generals[1].begin(), generals[1].end(), f) == generals[1].end()
                        && std::find(generals[2].begin(), generals[2].end(), f) == generals[2].end())
                        {
                            generals[2].push_back(f);
                        }
                    }
                }
                else
                {
                    filenames[0].push_back(n);

                    advgetopt::string_list_t extra_files(advgetopt::insert_group_name(path + basename, "ipload", "iplock", false));
                    for(auto const & f : extra_files)
                    {
                        if(std::find(filenames[1].begin(), filenames[1].end(), f) == filenames[1].end()
                        && std::find(filenames[2].begin(), filenames[2].end(), f) == filenames[2].end())
                        {
                            filenames[1].push_back(f);
                        }
                    }

                    advgetopt::string_list_t specialized_files(advgetopt::insert_group_name(n, "ipload", "iplock", false));
                    for(auto const & f : extra_files)
                    {
                        if(std::find(filenames[1].begin(), filenames[1].end(), f) == filenames[1].end()
                        && std::find(filenames[2].begin(), filenames[2].end(), f) == filenames[2].end())
                        {
                            filenames[2].push_back(f);
                        }
                    }
                }
            }
        }
        for(int idx(0); idx < 3; ++idx)
        {
            all_generals[idx].insert(all_generals[idx].end(), generals[idx].begin(), generals[idx].end());
            all_filenames[idx].insert(all_filenames[idx].end(), filenames[idx].begin(), filenames[idx].end());
        }
    }

    // make it a single variable
    //
    all_generals[0].insert(all_generals[0].end(), all_filenames[0].begin(), all_filenames[0].end());
    all_generals[0].insert(all_generals[0].end(), all_generals[1].begin(), all_generals[1].end());
    all_generals[0].insert(all_generals[0].end(), all_filenames[1].begin(), all_filenames[1].end());
    all_generals[0].insert(all_generals[0].end(), all_generals[2].begin(), all_generals[2].end());
    all_generals[0].insert(all_generals[0].end(), all_filenames[2].begin(), all_filenames[2].end());

    all_filenames[0].swap(all_generals[0]);

    for(auto const & f : all_filenames[0])
    {
        load_conf_file(f, f_parameters);
    }

    if(f_parameters.empty())
    {
        SNAP_LOG_FATAL
            << "no tables/chains/sections/rules found within path(s) \""
            << paths
            << "\"."
            << SNAP_LOG_SEND;
        return false;
    }

    if(f_opts.is_defined("show-variables"))
    {
        auto const & vars(f_variables->get_variables());
        SNAP_LOG_VERBOSE
            << "found a total of "
            << vars.size()
            << " variables."
            << SNAP_LOG_SEND;
        for(auto const & v : vars)
        {
            SNAP_LOG_VERBOSE
                << "variable \""
                << v.first
                << "\" = \""
                << v.second
                << "\"."
                << SNAP_LOG_SEND;
        }
    }

    advgetopt::variables::variable_t const & verify(f_verify->get_variables());
    for(auto const & v : verify)
    {
        bool const required(v.second == "required");
        bool const defined(v.second == "defined");

        if(required || defined)
        {
            if(!f_variables->has_variable(v.first))
            {
                SNAP_LOG_ERROR
                    << "required variable \""
                    << v.first
                    << "\" not found in the [variables] block."
                    << SNAP_LOG_SEND;
                return false;
            }
        }

        if(required)
        {
            if(f_variables->get_variable(v.first).empty())
            {
                SNAP_LOG_ERROR
                    << "required variable \""
                    << v.first
                    << "\" is defined, but is still empty."
                    << SNAP_LOG_SEND;
                return false;
            }
        }

        if(!required && !defined)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "required variable \""
                << v.first
                << "\" must be set to \"true\", \"1\", or \"on\"."
                << SNAP_LOG_SEND;
        }
    }

    return true;
}


void ipload::create_defaults()
{
    // the load_data() fails (no files, in most cases) then we want a
    // fallback to block the firewall (because by default the Linux
    // firewall is wide open)
    //
    snapdev::file_contents defaults("/run/users/0/default_firewall.conf", true);
    defaults.contents(std::string(tools_ipload::default_firewall, tools_ipload::default_firewall_size));
    if(!defaults.write_all())
    {
        SNAP_LOG_FATAL
            << "could not create \""
            << defaults.filename()
            << "\" to install a default firewall."
            << SNAP_LOG_SEND;
        // TODO: we can still default back to a set of rules
        //       we run manually...
        return;
    }

    load_conf_file(defaults.filename(), f_parameters);
}


void ipload::load_conf_file(
      std::string const & filename
    , advgetopt::conf_file::parameters_t & config_params)
{
    advgetopt::conf_file_setup conf_setup(
              filename
            , advgetopt::line_continuation_t::line_continuation_unix
            , advgetopt::ASSIGNMENT_OPERATOR_EQUAL | advgetopt::ASSIGNMENT_OPERATOR_EXTENDED);
    if(!conf_setup.is_valid())
    {
        SNAP_LOG_RECOVERABLE_ERROR
            << "info: configuration file \""
            << filename
            << "\" is not considered valid."
            << SNAP_LOG_SEND;
        return;
    }

    if(f_verbose)
    {
        SNAP_LOG_VERBOSE
            << "info: loading configuration file \""
            << filename
            << "\"."
            << SNAP_LOG_SEND;
    }

    advgetopt::conf_file::pointer_t conf(advgetopt::conf_file::get_conf_file(conf_setup));

    // any file can include some variables
    //
    snapdev::NOT_USED(conf->section_to_variables("variables", f_variables));

    // define whether a variable is required
    // (i.e. <var_name>=true)
    //
    snapdev::NOT_USED(conf->section_to_variables("verify", f_verify));

    // retrieve all the parameters in our own variable
    // by default parameters are overwritten between files
    // but user can use the +=, ?=, and := operators as well
    //
    advgetopt::conf_file::parameters_t const params(conf->get_parameters());
    for(auto const & p : params)
    {
        switch(p.second.get_assignment_operator())
        {
        case advgetopt::assignment_t::ASSIGNMENT_SET:
        case advgetopt::assignment_t::ASSIGNMENT_NONE:
            config_params[p.first] = p.second;
            break;

        case advgetopt::assignment_t::ASSIGNMENT_OPTIONAL:
            if(config_params.find(p.first) == config_params.end())
            {
                config_params[p.first] = p.second;
            }
            break;

        case advgetopt::assignment_t::ASSIGNMENT_APPEND:
            config_params[p.first] = config_params[p.first].get_value() + p.second.get_value();
            break;

        case advgetopt::assignment_t::ASSIGNMENT_NEW:
            if(config_params.find(p.first) != config_params.end())
            {
                SNAP_LOG_RECOVERABLE_ERROR
                    << "parameter \""
                    << p.first
                    << "\" cannot be overwritten (existing value \""
                    << config_params[p.first].get_value()
                    << "\" and new value \""
                    << p.second.get_value()
                    << "\")."
                    << SNAP_LOG_SEND;
            }
            else
            {
                config_params[p.first] = p.second;
            }
            break;

        }
    }
}


void ipload::load_basic(bool force)
{
    // user doesn't want defaults?
    //
    if(f_opts.is_defined("no-defaults"))
    {
        return;
    }

    // avoid running this code more than once
    //
    snapdev::file_contents installed(g_basic_flag.data(), true);
    if(!force
    && installed.exists())
    {
        return;
    }

    bool success(true);

    // install a default, very basic IPv4 firewall
    //
    {
        FILE * p(popen("iptables-restore", "w"));
        fwrite(tools_ipload::basic, sizeof(char), tools_ipload::basic_size, p);
        int const r(pclose(p));
        if(r != 0)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "the basic IPv4 firewall could not be loaded."
                << SNAP_LOG_SEND;
            success = false;
        }
    }

    // install a default, very basic IPv6 firewall
    //
    {
        FILE * p(popen("ip6tables-restore", "w"));
        fwrite(tools_ipload::basic, sizeof(char), tools_ipload::basic_size, p);
        int const r(pclose(p));
        if(r != 0)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "the basic IPv6 firewall could not be loaded."
                << SNAP_LOG_SEND;
            success = false;
        }
    }

    // write the flag file to disk
    //
    if(success)
    {
        installed.contents("yes\n");
        if(!installed.write_all())
        {
            SNAP_LOG_WARNING
                << "could not create flag \""
                << g_basic_flag
                << "\"."
                << SNAP_LOG_SEND;
        }
    }
}


/** \brief Convert the rules in an iptables script.
 *
 * This function goes through the list of parameters and generates a set of
 * tables, chains, sections, and rules to build the iptables script which
 * we can then load with the iptables-restore command (and equivalent for
 * IPv6).
 *
 * The command is broken up in several parts:
 *
 * 1. transform the parameters in objects
 * 2. generate a list of all the chains (they need to be defined)
 * 3. generate a list of rules for each chain, the order does not matter so
 *    we use the map (i.e. alphabetic order)
 * 4. generate the COMMIT command
 *
 * \return true if the conversion succeeded, false otherwise.
 */
bool ipload::convert()
{
    std::stringstream out;

    if(!process_parameters())
    {
        return false;
    }

    if(!generate_tables(out))
    {
        return false;
    }

    f_output = out.str();

    return true;
}


bool ipload::process_parameters()
{
    bool valid(true);
    chain::map_t chains;
    section::vector_t sections;
    rule::vector_t rules;

    auto p(f_parameters.begin());
    while(p != f_parameters.end())
    {
        if(p->first.empty())
        {
            ++p;
            continue;
        }
        switch(p->first[0])
        {
        case 'a':
            if(p->first == "add-to-set")
            {
                f_add_to_set = p->second;
                f_add_to_set += '\n';
                ++p;
                continue;
            }
            else if(p->first == "add-to-set-ipv4")
            {
                f_add_to_set_ipv4 = p->second;
                f_add_to_set_ipv4 += '\n';
                ++p;
                continue;
            }
            else if(p->first == "add-to-set-ipv6")
            {
                f_add_to_set_ipv6 = p->second;
                f_add_to_set_ipv6 += '\n';
                ++p;
                continue;
            }
            break;

        case 'c':
            if(p->first == "create-set")
            {
                f_create_set = p->second;
                ++p;
                continue;
            }
            if(p->first == "create-set-ipv4")
            {
                f_create_set_ipv4 = p->second;
                ++p;
                continue;
            }
            if(p->first == "create-set-ipv6")
            {
                f_create_set_ipv6 = p->second;
                ++p;
                continue;
            }
            break;

        case 'l':
            if(p->first == "log-introducer") // underscores are changed to '-' by advgetopt
            {
                f_log_introducer = p->second;
                while(f_log_introducer.back() == ' ')
                {
                    f_log_introducer.pop_back();
                }
                ++p;
                continue;
            }
            else if(p->first == "load-to-set")
            {
                f_load_to_set = p->second;
                ++p;
                continue;
            }
            else if(p->first == "load-to-set-ipv4")
            {
                f_load_to_set_ipv4 = p->second;
                ++p;
                continue;
            }
            else if(p->first == "load-to-set-ipv6")
            {
                f_load_to_set_ipv6 = p->second;
                ++p;
                continue;
            }
            break;

        case 'o':
            if(p->first == "output-empty-tables")
            {
                f_output_empty_tables = advgetopt::is_true(p->second);
                ++p;
                continue;
            }
            break;

        case 'r':
            if(p->first == "remove-user-chain") // underscores are changed to '-' by advgetopt
            {
                f_remove_user_chain = p->second;
                ++p;
                continue;
            }
            break;

        }

        advgetopt::string_list_t names;
        advgetopt::split_string(p->first, names, {"::"});
        if(names.empty())
        {
            throw iplock::logic_error("somehow the split_string returned an empty list?");
        }

        if(names[0] == "table")
        {
            if(names.size() != 3)
            {
                // expected table::<name>::<parameter>
                //
                SNAP_LOG_ERROR
                    << "the first table parameter is expected to be \"table::<name>::<parameter>\"."
                    << SNAP_LOG_SEND;
                valid = false;
                ++p;
                continue;
            }
            table::pointer_t tbl(std::make_shared<table>(p, f_parameters, f_variables));
            if(f_tables.find(tbl->get_name()) != f_tables.end())
            {
                SNAP_LOG_ERROR
                    << "table named \""
                    << tbl->get_name()
                    << "\" defined twice."
                    << SNAP_LOG_SEND;
                valid = false;
                ++p;
                continue;
            }
            f_tables[tbl->get_name()] = tbl;
        }
        else if(names[0] == "chain")
        {
            if(names.size() != 3)
            {
                // expected chain::<name>::<parameter>
                //
                SNAP_LOG_ERROR
                    << "the first chain parameter ("
                    << p->first
                    << ") is expected to be \"chain::<name>::<parameter>\"."
                    << SNAP_LOG_SEND;
                valid = false;
                ++p;
                continue;
            }
            chain::pointer_t c(std::make_shared<chain>(
                                      p
                                    , f_parameters
                                    , f_variables
                                    , f_verbose));
            if(chains.find(c->get_name()) != chains.end())
            {
                SNAP_LOG_ERROR
                    << "chain named \""
                    << c->get_exact_name()
                    << "\" defined twice."
                    << SNAP_LOG_SEND;
                valid = false;
                ++p;
                continue;
            }
            chains[c->get_name()] = c;
        }
        else if(names[0] == "section")
        {
            if(names.size() != 3)
            {
                // expected section::<name>::<parameter>
                //
                SNAP_LOG_ERROR
                    << "the first section parameter ("
                    << p->first
                    << ") is expected to be \"section::<name>\"."
                    << SNAP_LOG_SEND;
                valid = false;
                ++p;
                continue;
            }
            section::pointer_t sec(std::make_shared<section>(p, f_parameters, f_variables));
            if(std::find_if(
                      sections.begin()
                    , sections.end()
                    , [sec](auto const & a)
                        {
                            return a->get_name() == sec->get_name();
                        }) != sections.end())
            {
                SNAP_LOG_ERROR
                    << "section named \""
                    << sec->get_name()
                    << "\" defined twice."
                    << SNAP_LOG_SEND;
                valid = false;
                ++p;
                continue;
            }
            sections.push_back(sec);
        }
        else if(names[0] == "rule")
        {
            if(names.size() != 3)
            {
                // expected rule::<name>::<parameter>
                //
                SNAP_LOG_ERROR
                    << "the first rule parameter ("
                    << p->first
                    << ") is expected to be \"rule::<name>\"."
                    << SNAP_LOG_SEND;
                valid = false;
                ++p;
                continue;
            }
            rules.push_back(std::make_shared<rule>(
                      p
                    , f_parameters
                    , f_variables
                    , f_opts.get_string("ip-lists")));
        }
        else
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "unrecognized parameter \""
                << names[0]
                << "\"."
                << SNAP_LOG_SEND;
            ++p;
            continue;
        }
    }

    if(!sort_sections(sections))
    {
        valid = false;
    }

    if(!process_chains(chains))
    {
        valid = false;
    }

    if(!process_sections(sections))
    {
        valid = false;
    }

    if(!process_rules(rules))
    {
        valid = false;
    }

    if(!sort_rules())
    {
        valid = false;
    }

    return valid;
}


int ipload::count_levels(section::vector_t const & dependencies, section::pointer_t current_section)
{
    int cnt(1);
    for(auto const & d : dependencies)
    {
        if(d == current_section)
        {
            SNAP_LOG_ERROR
                << "detected a dependency loop for "
                << current_section->get_name()
                << SNAP_LOG_SEND;
            return cnt;
        }
        cnt = std::max(cnt, count_levels(d->get_dependencies(), current_section) + 1);
    }
    return cnt;
}


bool ipload::sort_sections(section::vector_t & sections)
{
    bool valid(true);

    // first add the "before" names to the "after" of the _other_ section
    //
    // (i.e. it becomes a "target: dependencies..." like in a Makefile)
    //
    for(auto & s : sections)
    {
        advgetopt::string_list_t before(s->get_before());
        for(auto const & name : before)
        {
            auto it(std::find_if(
                  sections.begin()
                , sections.end()
                , [name](auto const & other)
                    {
                        return other->get_name() == name;
                    }));
            if(it != sections.end())
            {
                (*it)->add_after(s->get_name());
            }
            else
            {
                SNAP_LOG_ERROR
                    << "could not find section named \""
                    << name
                    << "\"."
                    << SNAP_LOG_SEND;
                valid = false;
            }
        }
    }

    // next we want to build a tree, a node depending on another is lower
    // in the tree; here is an example:
    //
    //    1. first the "makefile" like content
    //
    //    a: b
    //    b:
    //    c: a
    //    d: b
    //    e: a b c d
    //
    //    2. the raw tree
    //
    //        _ b _<-------+
    //        /| |\        |
    //       /     \       |
    //      a       d      |
    //      ^       ^      |
    //      |\_____ |      |
    //      |      \|      |
    //      c<------e------+
    //
    //    3. the cleaned up tree
    //       (note that technically we do not need to do that, just could
    //       the number of levels is enough to solve the issue)
    //
    //        _ b _                level 1
    //        /| |\                .
    //       /     \               .
    //      a       d              level 2
    //      ^       ^              .
    //      |       |              .
    //      |       |              .
    //      c_      |              level 3
    //      |\      |              .
    //        \     |              .
    //         +----e              level 4
    //
    //    4. generate the output, one level at a time
    //
    //      b
    //      a
    //      d
    //      c
    //      e
    //
    for(auto & s : sections)
    {
        advgetopt::string_list_t after(s->get_after());
        for(auto const & name : after)
        {
            auto it(std::find_if(
                  sections.begin()
                , sections.end()
                , [name](auto const & other)
                    {
                        return other->get_name() == name;
                    }));
            if(it == sections.end())
            {
                // no such target, ignore
                //
                continue;
            }

            s->add_dependency(*it);
        }
    }

    int max_level(0);
    for(auto & s : sections)
    {
        int const level(count_levels(s->get_dependencies(), s));
        s->set_level(level);
        max_level = std::max(level, max_level);
    }

    section::vector_t ordered;
    for(int l(1); l <= max_level; ++l)
    {
        for(auto it(sections.begin()); it != sections.end(); ++it)
        {
            it = std::find_if(
                      it
                    , sections.end()
                    , [l](auto q)
                    {
                        return l == q->get_level();
                    });
            if(it == sections.end())
            {
                break;
            }
            ordered.push_back(*it);
        }
    }

    // save the ordered list back in the input vector
    //
    sections = std::move(ordered);

    return valid;
}


bool ipload::process_chains(chain::map_t const & chains)
{
    bool valid(true);

    for(auto const & c : chains)
    {
        advgetopt::string_list_t tables(c.second->get_tables());
        if(tables.empty())
        {
            tables.push_back("filter");
        }
        for(auto const & table_name : tables)
        {
            auto t(f_tables.find(table_name));
            if(t == f_tables.end())
            {
                SNAP_LOG_ERROR
                    << "could not find table \""
                    << table_name
                    << "\" for chain \""
                    << c.first
                    << "\"."
                    << SNAP_LOG_SEND;
                valid = false;
                continue;
            }
            t->second->add_chain_reference(std::make_shared<chain_reference>(c.second));
        }
    }

    return valid;
}


bool ipload::process_sections(section::vector_t const & sections)
{
    bool valid(true);

    for(auto const & t : f_tables)
    {
        chain_reference::map_t const & chains(t.second->get_chain_references());
        for(auto const & c : chains)
        {
            for(auto const & s : sections)
            {
                c.second->add_section_reference(std::make_shared<section_reference>(s));
                if(!c.second->is_valid())
                {
                    valid = false;
                }
            }
        }
    }

    return valid;
}


bool ipload::process_rules(rule::vector_t rules)
{
    bool valid(true);

    for(auto const & r : rules)
    {
        advgetopt::string_list_t table_names(r->get_tables());
        if(table_names.empty())
        {
            table_names.push_back("filter");
        }
        for(auto const & table_name : table_names)
        {
            auto t(f_tables.find(table_name));
            if(t == f_tables.end())
            {
                SNAP_LOG_ERROR
                    << "could not find table \""
                    << table_name
                    << "\" for rule \""
                    << r->get_name()
                    << "\"."
                    << SNAP_LOG_SEND;
                valid = false;
                continue;
            }

            advgetopt::string_list_t const & chain_names(r->get_chains());
            for(auto const & chain_name : chain_names)
            {
                chain_reference::pointer_t chain_reference(t->second->get_chain_reference(chain_name));
                if(chain_reference == nullptr)
                {
                    SNAP_LOG_ERROR
                        << "could not find chain \""
                        << chain_name
                        << "\" in table \""
                        << t->first
                        << "\" for rule \""
                        << r->get_name()
                        << "\"."
                        << SNAP_LOG_SEND;
                    valid = false;
                }
                else if(!chain_reference->add_rule(r))
                {
                    valid = false;
                }
            }
        }
    }

    return valid;
}




bool ipload::generate_tables(std::ostream & out)
{
    for(auto const & t : f_tables)
    {
        f_generate_for_table = t.second;

        // by default we do not want to generate tables when empty, even
        // if the rules imply at least a LOG action
        //
        if(f_generate_for_table->empty()
        && !f_output_empty_tables)
        {
            if(f_verbose)
            {
                out << "# Table " << t.first << " is empty.\n";
            }
            continue;
        }

        if(f_show_comments)
        {
            out << "# Table: " << t.first << "\n";
            if(f_verbose
            && !f_generate_for_table->get_description().empty())
            {
                out << "# " << f_generate_for_table->get_description() << "\n";
            }
        }
        out << "*" << t.first << "\n";

        chain_reference::map_t const & chains(f_generate_for_table->get_chain_references());

        // first we want a list of chains at the start of the filter
        // definition; we first print iptables internal names, mainly
        // for organization, then user defined chains
        //
        if(f_show_comments)
        {
            out << "\n# Chains\n";
        }
        for(auto const & c : chains)
        {
            if(!c.second->is_system_chain()
            || !c.second->get_condition())
            {
                continue;
            }
            if(!generate_chain_name(out, c.second))
            {
                return false;
            }
        }
        for(auto const & c : chains)
        {
            if(c.second->is_system_chain()
            || !c.second->get_condition())
            {
                continue;
            }
            if(!generate_chain_name(out, c.second))
            {
                return false;
            }
        }

        // now output the rules for each chain in this table
        // as above, we first output the system defined chains, then the
        // user defined chains
        //
        for(auto const & c : chains)
        {
            if(!c.second->is_system_chain()
            || !c.second->get_condition())
            {
                continue;
            }
            if(!generate_chain(out, c.second))
            {
                return false;
            }
        }
        for(auto const & c : chains)
        {
            if(c.second->is_system_chain()
            || !c.second->get_condition())
            {
                continue;
            }
            if(!generate_chain(out, c.second))
            {
                return false;
            }
        }

        if(f_show_comments)
        {
            out << "\n# Commit\n";
        }
        out << "COMMIT\n";

        if(f_show_comments)
        {
            // add an empty line after the COMMIT when comments are turned on
            //
            out << "\n";
        }
    }

    return true;
}


bool ipload::generate_chain_name(std::ostream & out, chain_reference::pointer_t c)
{
    out << ":"
        << c->get_exact_name()
        << ' '
        << (c->is_system_chain()
                    ? c->get_policy_name(f_generate_for_table->get_name())
                    : "-")
        << " [0:0]\n";

    return true;
}


bool ipload::generate_chain(std::ostream & out, chain_reference::pointer_t c)
{
    type_t const chain_type(c->get_type(f_generate_for_table->get_name()));
    if(c->empty(f_generate_for_table->get_name())
    && chain_type == type_t::TYPE_USER_DEFINED)
    {
        return true;
    }

    // the sections are there to group rules; in themselves they do not
    // generate anything in the output (except if we want to add comments
    // when the --show option is used)
    //
    if(f_show_comments)
    {
        out << "\n# Chain: " << c->get_exact_name() << "\n";
    }
    int count(0);
    section_reference::vector_t refs(c->get_section_references());
    for(auto const & s : refs)
    {
        if(!generate_rules(out, c, s, count))
        {
            return false;
        }
    }

    // close the chain with a LOG & a rule depending on its type
    //
    std::string const log(c->get_log());

    if(f_show_comments
    && chain_type != type_t::TYPE_USER_DEFINED)
    {
        out << "# Close with Chain Type:\n";
    }

    if(!log.empty()
    && chain_type != type_t::TYPE_USER_DEFINED)
    {
        std::string prefix(
                  f_log_introducer
                + ' '
                + log);
        prefix = snapdev::string_replace_many(
                  prefix
                , {{"\"", "'"}});
        if(prefix.length() > 28)
        {
            prefix = prefix.substr(0, 28);
        }
        prefix += ':';

        out << "-A "
            << c->get_exact_name()
            << " -j LOG --log-prefix \""
            << prefix
            << "\" --log-uid\n";
    }

    switch(chain_type)
    {
    case type_t::TYPE_RETURN:
        out << "-A "
            << c->get_exact_name()
            << " -j RETURN\n";
        break;

    case type_t::TYPE_DROP:
        out << "-A "
            << c->get_exact_name()
            << " -j DROP\n";
        break;

    case type_t::TYPE_REJECT:
        out << "-A "
            << c->get_exact_name()
            << " -j REJECT\n";
        break;

    case type_t::TYPE_USER_DEFINED:
        // the user wants to end the chain
        break;

    }

    return true;
}


bool ipload::generate_rules(
      std::ostream & out
    , chain_reference::pointer_t c
    , section_reference::pointer_t s
    , int & count)
{
    bool valid(true);

    rule::vector_t const & list(s->get_rules());
    for(auto const & r : list)
    {
#ifdef _DEBUG
        // we are expected to add the rules to chains using the list of chains
        // therefore here the find() should always find the chain in the list
        //
        advgetopt::string_list_t const & chains(r->get_chains());
        if(std::find(chains.begin(), chains.end(), c->get_name()) == chains.end())
        {
            throw iplock::logic_error(
                      "chain \""
                    + c->get_exact_name()
                    + "\" not found in rule \""
                    + r->get_name()
                    + "\" list of chains.");
        }
#endif

        // if empty() means:
        //
        //    rule is invalid
        //    if condition did not match
        //    enabled = false
        //
        if(r->empty())
        {
            continue;
        }

        if(f_show_comments && f_verbose)
        {
            ++count;
            out << "# Rule " << count << ": " << s->get_name() << '.' << r->get_name() << '\n';
            std::string const & description(r->get_description());
            if(!description.empty())
            {
                out << "#      " << description << '\n';
            }
        }
        r->set_log_introducer(f_log_introducer);
        out << r->to_iptables_rules(c->get_exact_name());

        if(!r->is_valid())
        {
            valid = false;
        }
    }

    return valid;
}


bool ipload::sort_rules()
{
    // to go through all the rules we go through the tables/chains/sections
    //
    bool valid(true);
    for(auto const & t : f_tables)
    {
        chain_reference::map_t const & chains(t.second->get_chain_references());
        for(auto const & c : chains)
        {
            section_reference::vector_t refs(c.second->get_section_references());
            for(auto const & s : refs)
            {
                if(!s->sort_rules())
                {
                    valid = false;
                }
            }
        }
    }

    return valid;
}


bool ipload::create_sets()
{
    // use a set to know whether we already added a set in case the same
    // set is referenced multiple times
    //
    std::set<std::string> found;
    bool valid(true);
    for(auto const & t : f_tables)
    {
        chain_reference::map_t const & chains(t.second->get_chain_references());
        for(auto const & c : chains)
        {
            section_reference::vector_t refs(c.second->get_section_references());
            for(auto const & s : refs)
            {
                rule::vector_t const & rules(s->get_rules());
                for(auto const & r : rules)
                {
                    std::string const & type(r->get_set_type());
                    advgetopt::string_list_t const & data(r->get_set_data());
                    bool const set_has_ip(r->set_has_ip());
                    advgetopt::string_list_t const & sets(r->get_set());
                    for(auto const & name : sets)
                    {
                        if(found.find(name) == found.end())
                        {
                            found.insert(name);

                            if(set_has_ip)
                            {
                                // IPv4
                                //
                                if(f_create_set_ipv4.empty())
                                {
                                    SNAP_LOG_ERROR
                                        << "the \"create_set_ipv4\" global variable is empty."
                                        << SNAP_LOG_SEND;
                                    return false;
                                }
                                std::string const cmd_ipv4(snapdev::string_replace_many(
                                          f_create_set_ipv4
                                        , {
                                            { "[name]", name + "_ipv4" },
                                            { "[type]", type },
                                          }));
                                int const exit_code_v4(system(cmd_ipv4.c_str()));
                                if(exit_code_v4 != 0)
                                {
                                    int const e(errno);
                                    SNAP_LOG_ERROR
                                        << "an error occurred trying to create ipset \""
                                        << name
                                        << "\" IPv4 with command: \""
                                        << cmd_ipv4
                                        << "\" (exit code: "
                                        << exit_code_v4
                                        << ", errno: "
                                        << e
                                        << ", "
                                        << strerror(e)
                                        << ")."
                                        << SNAP_LOG_SEND;
                                    valid = false;
                                }

                                // IPv6
                                //
                                if(f_create_set_ipv6.empty())
                                {
                                    SNAP_LOG_ERROR
                                        << "the \"create_set_ipv6\" global variable is empty."
                                        << SNAP_LOG_SEND;
                                    return false;
                                }
                                std::string const cmd_ipv6(snapdev::string_replace_many(
                                          f_create_set_ipv6
                                        , {
                                            { "[name]", name + "_ipv6" },
                                            { "[type]", type },
                                          }));
                                int const exit_code_v6(system(cmd_ipv6.c_str()));
                                if(exit_code_v6 != 0)
                                {
                                    int const e(errno);
                                    SNAP_LOG_ERROR
                                        << "an error occurred trying to create ipset \""
                                        << name
                                        << "\" IPv6 with command: \""
                                        << cmd_ipv6
                                        << "\" (exit code: "
                                        << exit_code_v6
                                        << ", errno: "
                                        << e
                                        << ", "
                                        << strerror(e)
                                        << ")."
                                        << SNAP_LOG_SEND;
                                    valid = false;
                                }
                            }
                            else
                            {
                                // without IPs, we can create one set and use
                                // it with IPv4 and IPv6
                                //
                                if(f_create_set.empty())
                                {
                                    SNAP_LOG_ERROR
                                        << "the \"create_set\" global variable is empty."
                                        << SNAP_LOG_SEND;
                                    return false;
                                }
                                std::string cmd(snapdev::string_replace_many(
                                          f_create_set
                                        , {
                                            { "[name]", name },
                                            { "[type]", type },
                                          }));
                                if(type == "bitmap:port")
                                {
                                    // in this case we must have a range,
                                    // check the data to determine the minimum
                                    // and maximum needed
                                    //
                                    std::int64_t min_port(65535);
                                    std::int64_t max_port(0);
                                    for(auto const & d : data)
                                    {
                                        // TODO: support ports from /etc/services
                                        //
                                        addr::addr a;
                                        if(a.set_port(d.c_str()))
                                        {
                                            int const port(a.get_port());
                                            if(port < min_port)
                                            {
                                                min_port = port;
                                            }
                                            if(port > max_port)
                                            {
                                                max_port = port;
                                            }
                                        }
                                    }
                                    cmd += " range "
                                              + std::to_string(min_port)
                                              + '-'
                                              + std::to_string(max_port);
                                }
                                int const exit_code(system(cmd.c_str()));
                                if(exit_code != 0)
                                {
                                    int const e(errno);
                                    SNAP_LOG_ERROR
                                        << "an error occurred trying to create ipset \""
                                        << name
                                        << "\" with command: \""
                                        << cmd
                                        << "\" (exit code: "
                                        << exit_code
                                        << ", errno: "
                                        << e
                                        << ", "
                                        << strerror(e)
                                        << ")."
                                        << SNAP_LOG_SEND;
                                    valid = false;
                                }
                            }
                        }

                        // there is data, add it to the set
                        //
                        FILE * ipv4_or_shared(nullptr);
                        FILE * ipv6(nullptr);
                        if(set_has_ip)
                        {
                            // in this case, we open two pipes to send
                            // data to the IPv4 and IPv6 sets
                            //
                            if(f_load_to_set_ipv4.empty())
                            {
                                SNAP_LOG_ERROR
                                    << "the \"load_to_set_ipv4\" global variable is empty."
                                    << SNAP_LOG_SEND;
                                return false;
                            }
                            if(f_load_to_set_ipv6.empty())
                            {
                                SNAP_LOG_ERROR
                                    << "the \"load_to_set_ipv6\" global variable is empty."
                                    << SNAP_LOG_SEND;
                                return false;
                            }

                            ipv4_or_shared = popen(f_load_to_set_ipv4.c_str(), "w");
                            if(ipv4_or_shared == nullptr)
                            {
                                int const e(errno);
                                SNAP_LOG_ERROR
                                    << "the \"load_to_set_ipv4\" command failed: "
                                    << e
                                    << ", "
                                    << strerror(e)
                                    << "; command \""
                                    << f_load_to_set_ipv4
                                    << "\"."
                                    << SNAP_LOG_SEND;
                                return false;
                            }

                            ipv6 = popen(f_load_to_set_ipv6.c_str(), "w");
                            if(ipv6 == nullptr)
                            {
                                int const e(errno);
                                SNAP_LOG_ERROR
                                    << "the \"load_to_set_ipv6\" command failed: "
                                    << e
                                    << ", "
                                    << strerror(e)
                                    << "; command \""
                                    << f_load_to_set_ipv6
                                    << "\"."
                                    << SNAP_LOG_SEND;
                                return false;
                            }
                        }
                        else
                        {
                            // in this case, we open one pipe to send
                            // data to the common set
                            //
                            if(f_load_to_set.empty())
                            {
                                SNAP_LOG_ERROR
                                    << "the \"load_to_set\" global variable is empty."
                                    << SNAP_LOG_SEND;
                                return false;
                            }

                            ipv4_or_shared = popen(f_load_to_set.c_str(), "w");
                            if(ipv4_or_shared == nullptr)
                            {
                                int const e(errno);
                                SNAP_LOG_ERROR
                                    << "the \"load_to_set\" command failed: "
                                    << e
                                    << ", "
                                    << strerror(e)
                                    << "; command \""
                                    << f_load_to_set
                                    << "\"."
                                    << SNAP_LOG_SEND;
                                return false;
                            }
                        }
                        for(auto const & d : data)
                        {
                            if(set_has_ip)
                            {
                                // a set with an IP will have that IP first
                                // (there may be more but all have to be of
                                // the same type: IPv4 or IPv6)
                                //
                                // the IP is parsed to determine which version
                                // of the set to use
                                //
                                std::string::size_type space(d.find(' '));
                                std::string ip;
                                if(space == std::string::npos)
                                {
                                    ip = d;
                                }
                                else
                                {
                                    ip = d.substr(0, space);
                                }
                                addr::addr_parser p;
                                p.set_protocol(IPPROTO_TCP);
                                p.set_allow(addr::allow_t::ALLOW_REQUIRED_ADDRESS, true);
                                p.set_allow(addr::allow_t::ALLOW_MASK, true);
                                p.set_allow(addr::allow_t::ALLOW_PORT, false);  // at this time, the port is expected to be separated by a space
                                addr::addr_range::vector_t addresses(p.parse(ip));
                                if(addresses.empty())
                                {
                                    SNAP_LOG_ERROR
                                        << "ipset data \""
                                        << d
                                        << "\" is not a valid IPv4 or IPv6 address. "
                                        << p.error_messages()
                                        << SNAP_LOG_SEND;
                                    valid = false;
                                    continue;
                                }
                                if(!addresses[0].has_from())
                                {
                                    SNAP_LOG_ERROR
                                        << "ipset data \""
                                        << d
                                        << "\" does not start with a valid IPv4 or IPv6 address (this should not happen)."
                                        << SNAP_LOG_SEND;
                                    valid = false;
                                    continue;
                                }
                                addr::addr const & a(addresses[0].get_from());
                                bool is_ipv4(a.is_ipv4());
                                if(is_ipv4)
                                {
                                    // we have one very special case of an IPv6
                                    // which looks like an IPv4 address
                                    //
                                    if(a.is_default()
                                    && a.get_mask_size() == 96)
                                    {
                                        is_ipv4 = false;
                                    }
                                }
                                if(is_ipv4)
                                {
                                    std::string const cmd_ipv4(snapdev::string_replace_many(
                                              f_add_to_set_ipv4
                                            , {
                                                { "[name]", name + "_ipv4" },
                                                { "[params]", d },
                                              }));
                                    if(fwrite(cmd_ipv4.c_str(), 1, cmd_ipv4.length(), ipv4_or_shared) != cmd_ipv4.length())
                                    {
                                        int const e(errno);
                                        SNAP_LOG_ERROR
                                            << "an error occurred trying to add data to ipset \""
                                            << name
                                            << "\" IPv4 with command: \""
                                            << cmd_ipv4
                                            << "\" (errno: "
                                            << e
                                            << ", "
                                            << strerror(e)
                                            << ")."
                                            << SNAP_LOG_SEND;
                                        valid = false;
                                    }
                                    //int const exit_code_v4(system(cmd_ipv4.c_str()));
                                    //if(exit_code_v4 != 0)
                                    //{
                                    //    int const e(errno);
                                    //    SNAP_LOG_ERROR
                                    //        << "an error occurred trying to add data to ipset \""
                                    //        << name
                                    //        << "\" IPv4 with command: \""
                                    //        << cmd_ipv4
                                    //        << "\" (exit code: "
                                    //        << exit_code_v4
                                    //        << ", errno: "
                                    //        << e
                                    //        << ", "
                                    //        << strerror(e)
                                    //        << ")."
                                    //        << SNAP_LOG_SEND;
                                    //    valid = false;
                                    //}
                                }
                                else
                                {
                                    if(f_add_to_set_ipv6.empty())
                                    {
                                        SNAP_LOG_ERROR
                                            << "the \"add_to_set_ipv6\" global variable is empty."
                                            << SNAP_LOG_SEND;
                                        return false;
                                    }
                                    std::string const cmd_ipv6(snapdev::string_replace_many(
                                              f_add_to_set_ipv6
                                            , {
                                                { "[name]", name + "_ipv6" },
                                                { "[params]", d },
                                              }));
                                    if(fwrite(cmd_ipv6.c_str(), 1, cmd_ipv6.length(), ipv6) != cmd_ipv6.length())
                                    {
                                        int const e(errno);
                                        SNAP_LOG_ERROR
                                            << "an error occurred trying to add data to ipset \""
                                            << name
                                            << "\" IPv6 with command: \""
                                            << cmd_ipv6
                                            << "\" (errno: "
                                            << e
                                            << ", "
                                            << strerror(e)
                                            << ")."
                                            << SNAP_LOG_SEND;
                                        valid = false;
                                    }
                                    //int const exit_code_v6(system(cmd_ipv6.c_str()));
                                    //if(exit_code_v6 != 0)
                                    //{
                                    //    int const e(errno);
                                    //    SNAP_LOG_ERROR
                                    //        << "an error occurred trying to add data to ipset \""
                                    //        << name
                                    //        << "\" IPv6 with command: \""
                                    //        << cmd_ipv6
                                    //        << "\" (exit code: "
                                    //        << exit_code_v6
                                    //        << ", errno: "
                                    //        << e
                                    //        << ", "
                                    //        << strerror(e)
                                    //        << ")."
                                    //        << SNAP_LOG_SEND;
                                    //    valid = false;
                                    //}
                                }
                            }
                            else
                            {
                                if(f_add_to_set.empty())
                                {
                                    SNAP_LOG_ERROR
                                        << "the \"add_to_set\" global variable is empty."
                                        << SNAP_LOG_SEND;
                                    return false;
                                }
                                std::string const cmd(snapdev::string_replace_many(
                                          f_add_to_set
                                        , {
                                            { "[name]", name },
                                            { "[params]", d },
                                          }));
                                if(fwrite(cmd.c_str(), 1, cmd.length(), ipv4_or_shared) != cmd.length())
                                {
                                    int const e(errno);
                                    SNAP_LOG_ERROR
                                        << "an error occurred trying to add data to ipset \""
                                        << name
                                        << "\" with command: \""
                                        << cmd
                                        << "\" (errno: "
                                        << e
                                        << ", "
                                        << strerror(e)
                                        << ")."
                                        << SNAP_LOG_SEND;
                                    valid = false;
                                }
                                //int const exit_code(system(cmd.c_str()));
                                //if(exit_code != 0)
                                //{
                                //    int const e(errno);
                                //    SNAP_LOG_ERROR
                                //        << "an error occurred trying to add data to ipset \""
                                //        << name
                                //        << "\" with command: \""
                                //        << cmd
                                //        << "\" (exit code: "
                                //        << exit_code
                                //        << ", errno: "
                                //        << e
                                //        << ", "
                                //        << strerror(e)
                                //        << ")."
                                //        << SNAP_LOG_SEND;
                                //    valid = false;
                                //}
                            }
                        }
                        if(ipv4_or_shared != nullptr)
                        {
                            int const exit_code(pclose(ipv4_or_shared));
                            if(exit_code != 0)
                            {
                                int const e(errno);
                                SNAP_LOG_ERROR
                                    << "an error occurred trying to add data to IPv4/common ipset \""
                                    << name
                                    << "\" with command: \""
                                    << "<todo>"
                                    << "\" (exit code: "
                                    << exit_code
                                    << ", errno: "
                                    << e
                                    << ", "
                                    << strerror(e)
                                    << ")."
                                    << SNAP_LOG_SEND;
                                valid = false;
                            }
                        }
                        if(ipv6 != nullptr)
                        {
                            int const exit_code(pclose(ipv6));
                            if(exit_code != 0)
                            {
                                int const e(errno);
                                SNAP_LOG_ERROR
                                    << "an error occurred trying to add data to IPv6 ipset \""
                                    << name
                                    << "\" with command: \""
                                    << "<todo>"
                                    << "\" (exit code: "
                                    << exit_code
                                    << ", errno: "
                                    << e
                                    << ", "
                                    << strerror(e)
                                    << ")."
                                    << SNAP_LOG_SEND;
                                valid = false;
                            }
                        }
                    }
                }
            }
        }
    }

    return valid;
}


bool ipload::remove_from_iptables()
{
    // first ask the user for confirmation if possible (i.e. isatty() is true)
    //
    if(isatty(fileno(stdin))
    && isatty(fileno(stdout)))
    {
        std::unique_ptr<char> answer(readline(g_prompt.data()));
        if(strcmp(answer.get(), YES_I_AM_SURE.data()) != 0)
        {
            SNAP_LOG_WARNING
                << "clearing of firewall canceled."
                << SNAP_LOG_SEND;
            return false;
        }
    }

    // first clear the rules & reset the policies by default
    //
    // TODO: add commands to clear all the tables to their default
    //
    if(f_verbose)
    {
        std::cerr << tools_ipload::clear_firewall;
    }

    // after these unlink() we do not really know the status of the firewall
    // but it is likely cleared... (if the clear fails, then, who knows!)
    //
    unlink(g_basic_flag.data());
    unlink(g_firewall_flag.data());
    unlink(g_default_flag.data());

    int exit_code(system(tools_ipload::clear_firewall));
    if(exit_code != 0)
    {
        SNAP_LOG_ERROR
            << "clear-firewall.sh failed with exit code "
            << exit_code
            << SNAP_LOG_SEND;
        return false;
    }

    // then go through the user defined chains and remove them
    //
    if(f_remove_user_chain.empty())
    {
        SNAP_LOG_ERROR
            << "the \"remove_user_chain\" global variable is empty."
            << SNAP_LOG_SEND;
        return false;
    }
    bool valid(true);
    for(auto const & t : f_tables)
    {
        chain_reference::map_t const & chains(t.second->get_chain_references());
        for(auto const & c : chains)
        {
            if(c.second->is_system_chain())
            {
                continue;
            }
            if(c.second->get_name().empty())
            {
                SNAP_LOG_EXCEPTION
                    << "found a chain without a name."
                    << SNAP_LOG_SEND;
                throw iplock::logic_error("chain has no name.");
            }
            std::string const cmd(snapdev::string_replace_many(
                      f_remove_user_chain
                    , {
                        {"[table]", t.first},
                        {"[name]", c.first},
                      }));
            if(f_verbose)
            {
                std::cerr << cmd << '\n';
            }
            exit_code = system(cmd.c_str());
            if(exit_code != 0)
            {
                int const e(errno);
                SNAP_LOG_ERROR
                    << "an error occurred trying to delete a user chain \""
                    << c.first
                    << "\" (exit code: "
                    << exit_code
                    << ", errno: "
                    << e
                    << ", "
                    << strerror(e)
                    << ")."
                    << SNAP_LOG_SEND;
                valid = false;
            }
        }
    }

    return valid;
}


bool ipload::load_to_iptables(std::string const & flag_name)
{
    {
        FILE * p(popen("iptables-restore", "w"));
        fwrite(f_output.c_str(), sizeof(char), f_output.length(), p);
        int const r(pclose(p));
        if(r != 0)
        {
            SNAP_LOG_ERROR
                << "the IPv4 firewall could not be loaded."
                << SNAP_LOG_SEND;
            return false;
        }
    }

    {
        FILE * p(popen("ip6tables-restore", "w"));
        fwrite(f_output.c_str(), sizeof(char), f_output.length(), p);
        int const r(pclose(p));
        if(r != 0)
        {
            SNAP_LOG_ERROR
                << "the IPv6 firewall could not be loaded."
                << SNAP_LOG_SEND;
            return false;
        }
    }

    // let other tools and services know we successfully installed the
    // firewall
    //
    snapdev::file_contents installed(flag_name.c_str(), true);
    installed.contents("yes\n");
    if(!installed.write_all())
    {
        SNAP_LOG_WARNING
            << "could not create firewall flag \""
            << g_basic_flag
            << "\"."
            << SNAP_LOG_SEND;
    }

    return true;
}


void ipload::show()
{
    std::cout << f_output;
}


void ipload::show_dependencies()
{
    std::cout << "# --------------------\n";
    std::cout << "# --- dependencies ---\n";
    std::cout << "# --------------------\n";
    std::cout << "\n";
    for(auto const & t : f_tables)
    {
        std::cout << "###\n### Table: " << t.first << "\n###\n\n";
        chain_reference::map_t const & chains(t.second->get_chain_references());
        for(auto const & c : chains)
        {
            std::cout << "\n##\n## Chain: " << c.first << "\n##\n";
            section_reference::vector_t refs(c.second->get_section_references());
            for(auto const & s : refs)
            {
                rule::vector_t const & list(s->get_rules());
                if(!list.empty()
                || f_verbose)
                {
                    std::cout << "# Section: " << s->get_name() << "\n";
                }
                for(auto const & r : list)
                {
                    std::cout << r->get_name() << ':';
                    advgetopt::string_list_t after(r->get_after());
                    for(auto const & a : after)
                    {
                        std::cout << ' ' << a;
                    }
                    std::cout << '\n';
                }
            }
        }
        std::cout << '\n';
    }

    std::cout << "# --------------------\n";
    std::cout << "\n";
}



// vim: ts=4 sw=4 et
