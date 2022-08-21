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
 * This implementation offers a way to easily and safely add and remove
 * IP addresses one wants to block/unblock temporarily.
 *
 * The tool makes use of the iptables tool to add and remove rules
 * to one specific table which is expected to be included in your
 * INPUT rules (with a `-j \<table-name>`).
 */


// self
//
#include    "command.h"


// iplock
//
#include    <iplock/version.h>


//// libaddr
////
//#include    <libaddr/addr_parser.h>
//
//
//// boost
////
//#include    <boost/algorithm/string/replace.hpp>
//#include    <boost/filesystem.hpp>
//#include    <boost/lexical_cast.hpp>


// C++
//
#include    <iostream>
//#include    <fstream>
//#include    <sstream>


// C
//
#include    <net/if.h>
//#include    <stdio.h>


// last include
//
#include    <snapdev/poison.h>



namespace tool
{


///** \brief Command line options.
// *
// * This table includes all the options supported by iplock on the
// * command line.
// */
//advgetopt::option const g_iplock_options[] =
//{
//    // COMMANDS
//    //
//    advgetopt::define_option(
//          advgetopt::Name("batch")
//        , advgetopt::ShortName('a')
//        , advgetopt::Flags(advgetopt::command_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
//                    , advgetopt::GETOPT_FLAG_REQUIRED>())
//        , advgetopt::Help("Text file containing rules to add to the firewall.")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("block")
//        , advgetopt::ShortName('b')
//        , advgetopt::Flags(advgetopt::standalone_command_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
//        , advgetopt::Help("Block the speficied IP address. If already blocked, do nothing.")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("count")
//        , advgetopt::ShortName('n')
//        , advgetopt::Flags(advgetopt::standalone_command_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
//        , advgetopt::Help("Return the number of times each IP address was"
//                " blocked since the last counter reset. You may use the"
//                " --reset along this command to atomically reset the"
//                " counters as you retrieve them.")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("flush")
//        , advgetopt::ShortName('f')
//        , advgetopt::Flags(advgetopt::standalone_command_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
//                    , advgetopt::GETOPT_FLAG_SHOW_USAGE_ON_ERROR>())
//        , advgetopt::Help("Flush all rules specified in chain.")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("unblock")
//        , advgetopt::ShortName('u')
//        , advgetopt::Flags(advgetopt::option_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS
//                    , advgetopt::GETOPT_FLAG_COMMAND_LINE>())
//        , advgetopt::Help("Unblock the specified IP address. If not already blocked, do nothing.")
//    ),
//
//    // OPTIONS
//    //
//    advgetopt::define_option(
//          advgetopt::Name("quiet")
//        , advgetopt::ShortName('q')
//        , advgetopt::Flags(advgetopt::option_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
//                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
//                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
//        , advgetopt::Help("Prevent iptables from printing messages in stdout or stderr.")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("reset")
//        , advgetopt::ShortName('r')
//        , advgetopt::Flags(advgetopt::option_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
//                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
//                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
//        , advgetopt::Help("Use with the --count command to retrieve the counters and reset them atomically.")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("scheme")
//        , advgetopt::ShortName('s')
//        , advgetopt::Flags(advgetopt::any_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
//                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
//                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE
//                    , advgetopt::GETOPT_FLAG_REQUIRED>())
//        , advgetopt::Help("Configuration file to define iptables commands. This is one name (no '/' or '.'). The default is \"http\".")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("total")
//        , advgetopt::ShortName('t')
//        , advgetopt::Flags(advgetopt::option_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
//                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
//                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
//        , advgetopt::Help("Write the grand total only when --count is specified.")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("verbose")
//        , advgetopt::ShortName('v')
//        , advgetopt::Flags(advgetopt::option_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
//                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
//                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
//        , advgetopt::Help("Show commands being executed.")
//    ),
//    advgetopt::define_option(
//          advgetopt::Name("--")
//        , advgetopt::Flags(advgetopt::command_flags<
//                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
//                    , advgetopt::GETOPT_FLAG_DEFAULT_OPTION
//                    , advgetopt::GETOPT_FLAG_MULTIPLE>())
//    ),
//    advgetopt::end_options()
//};
//
//
//
//advgetopt::group_description const g_group_descriptions[] =
//{
//    advgetopt::define_group(
//          advgetopt::GroupNumber(advgetopt::GETOPT_FLAG_GROUP_COMMANDS)
//        , advgetopt::GroupName("command")
//        , advgetopt::GroupDescription("Commands:")
//    ),
//    advgetopt::define_group(
//          advgetopt::GroupNumber(advgetopt::GETOPT_FLAG_GROUP_OPTIONS)
//        , advgetopt::GroupName("option")
//        , advgetopt::GroupDescription("Options:")
//    ),
//    advgetopt::end_groups()
//};
//
//
//
//
//// TODO: once we have stdc++20, remove all defaults
//#pragma GCC diagnostic ignored "-Wpedantic"
//advgetopt::options_environment const g_iplock_options_environment =
//{
//    .f_project_name = "iplock",
//    .f_group_name = nullptr,
//    .f_options = g_iplock_options,
//    .f_options_files_directory = nullptr,
//    .f_environment_variable_name = "IPLOCK_OPTIONS",
//    .f_environment_variable_intro = nullptr,
//    .f_section_variables_name = nullptr,
//    .f_configuration_files = nullptr,
//    .f_configuration_filename = nullptr,
//    .f_configuration_directories = nullptr,
//    .f_environment_flags = advgetopt::GETOPT_ENVIRONMENT_FLAG_SYSTEM_PARAMETERS
//                         | advgetopt::GETOPT_ENVIRONMENT_FLAG_PROCESS_SYSTEM_PARAMETERS,
//    .f_help_header = "Usage: %p [-<opt>] [ip]\n"
//                     "where -<opt> is one or more of:",
//    .f_help_footer = nullptr,
//    .f_version = IPLOCK_VERSION_STRING,
//    .f_license = "This software is licenced under the MIT",
//    .f_copyright = "Copyright (c) 2007-" BOOST_PP_STRINGIZE(UTC_BUILD_YEAR) " by Made to Order Software Corporation",
//    .f_build_date = UTC_BUILD_DATE,
//    .f_build_time = UTC_BUILD_TIME,
//    .f_groups = g_group_descriptions
//};
//
//
//



/** \brief Scheme file options.
 *
 * This table includes all the variables supported by iplock in a
 * scheme file such as http.conf.
 */
advgetopt::option const g_iplock_configuration_options[] =
{
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "batch",
        nullptr,
        "Command use to add multiple firewall rules from a file (e.g. iptables-restore).",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "batch_footer",
        nullptr,
        "Footer to mark the end of the batch file which the batch tool processes.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "block",
        nullptr,
        "Command used to add a block rule to the firewall (e.g. iptables -w).",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "chain",
        nullptr,
        "The name of the chain that iplock is expected to work with.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "check",
        nullptr,
        "The command used to perform a check of the current firewall rules.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "flush",
        nullptr,
        "The name of the command which will flush rules from a table.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "interface",
        nullptr,
        "The name of the interface that iplock is expected to work with.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "unblock",
        nullptr,
        "Command used to remove a block rule to the firewall (e.g. iptables -w).",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_END,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    }
};



/** \brief The list of files (one) to the iplock.conf configuration file.
 *
 * This vector includes the project name ("iplock") and the path
 * to the iplock configuration file.
 *
 * The project name is used so one can place another copy of the
 * iplock.conf file in a sub-directory named ".../iplock.d/..."
 *
 * Note that we do not give users a way to enter their own configuration
 * files. Those files can only be edited by root.
 */
constexpr char const * const g_iplock_configuration_files[]
{
    "/etc/iplock/iplock.conf",
    nullptr
};



// TODO: once we have stdc++20, remove all defaults
#pragma GCC diagnostic ignored "-Wpedantic"
advgetopt::options_environment const g_iplock_configuration_options_environment =
{
    .f_project_name = "iplock",
    .f_group_name = nullptr,
    .f_options = g_iplock_configuration_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = nullptr,
    .f_environment_variable_intro = nullptr,
    .f_section_variables_name = nullptr,
    .f_configuration_files = g_iplock_configuration_files,
    .f_configuration_filename = nullptr,
    .f_configuration_directories = nullptr,
    .f_environment_flags = 0,
    .f_help_header = nullptr,
    .f_help_footer = nullptr,
    .f_version = IPLOCK_VERSION_STRING,
    //.f_license = nullptr,
    //.f_copyright = nullptr,
    //.f_build_date = UTC_BUILD_DATE,
    //.f_build_time = UTC_BUILD_TIME
};



//
//
//
///** \brief Scheme file options.
// *
// * This table includes all the variables supported by iplock in a
// * scheme file such as http.conf.
// */
//advgetopt::option const g_iplock_block_or_unblock_options[] =
//{
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "batch",
//        nullptr,
//        "Rule to add a specified IP address in a batch-friendly fashion.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "block",
//        nullptr,
//        "Block the speficied IP address. If already blocked, do nothing.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "check",
//        nullptr,
//        "Command to check whether a rule already exists or not.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "flush",
//        nullptr,
//        "Flush the chain.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "ports",
//        nullptr,
//        "Comma separated list of ports.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "unblock",
//        nullptr,
//        "Unblock the specified IP address. If not already blocked, do nothing.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE,
//        "whitelist",
//        nullptr,
//        "List of comma separated IPs to never block.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_END,
//        nullptr,
//        nullptr,
//        nullptr,
//        nullptr
//    }
//};
//
//
//// Note: this one is not const because we change the list of configuration
////       file dynamically (the name of the scheme changes)
////
//// TODO: once we have stdc++20, remove all defaults
//#pragma GCC diagnostic ignored "-Wpedantic"
//advgetopt::options_environment g_iplock_block_or_unblock_options_environment =
//{
//    .f_project_name = "schemes",
//    .f_group_name = nullptr,
//    .f_options = g_iplock_block_or_unblock_options,
//    .f_options_files_directory = nullptr,
//    .f_environment_variable_name = nullptr,
//    .f_environment_variable_intro = nullptr,
//    .f_section_variables_name = nullptr,
//    .f_configuration_files = nullptr,
//    .f_configuration_filename = nullptr,
//    .f_configuration_directories = nullptr,
//    .f_environment_flags = 0,
//    .f_help_header = nullptr,
//    .f_help_footer = nullptr,
//    .f_version = IPLOCK_VERSION_STRING,
//    .f_license = nullptr,
//    .f_copyright = nullptr,
//    //.f_build_date = UTC_BUILD_DATE,
//    //.f_build_time = UTC_BUILD_TIME
//};
//
//
//
//
///** \brief Scheme file options.
// *
// * This table includes all the variables supported by iplock in a
// * scheme file such as http.conf.
// */
//advgetopt::option const g_iplock_count_options[] =
//{
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "acceptable_targets",
//        nullptr,
//        "The list of comma separated target names that will be counted.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "bytes_column",
//        nullptr,
//        "The column representing the number of bytes transferred.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "count",
//        nullptr,
//        "The command line to print out the counters from iptables.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "count_and_reset",
//        nullptr,
//        "The command line to print out and reset the counters from iptables.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "ignore_line_starting_with",
//        nullptr,
//        "Ignore any line starting with the specified value.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "ip_column",
//        nullptr,
//        "The column in which our IP is found (changes depending on whether you use an input or output IP--we are limited to the input a.k.a \"source\" IP address for now.).",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "lines_to_ignore",
//        nullptr,
//        "The number of lines to ignore at the start.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "packets_column",
//        nullptr,
//        "The column representing the number of packets received/sent.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "target_column",
//        nullptr,
//        "The column representing the number of packets received/sent.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_END,
//        nullptr,
//        nullptr,
//        nullptr,
//        nullptr
//    }
//};
//
//
///** \brief The configuration files for the --count command line option.
// *
// * This vector includes a set of parameters used to load the --count
// * options from a configuration file.
// */
//constexpr char const * const g_iplock_count_configuration_files[]
//{
//    "/etc/iplock/count.conf",
//    nullptr
//};
//
//
//
//// TODO: once we have stdc++20, remove all defaults
//#pragma GCC diagnostic ignored "-Wpedantic"
//advgetopt::options_environment const g_iplock_count_options_environment =
//{
//    .f_project_name = "iplock",
//    .f_group_name = nullptr,
//    .f_options = g_iplock_count_options,
//    .f_options_files_directory = nullptr,
//    .f_environment_variable_name = nullptr,
//    .f_environment_variable_intro = nullptr,
//    .f_section_variables_name = nullptr,
//    .f_configuration_files = g_iplock_count_configuration_files,
//    .f_configuration_filename = nullptr,
//    .f_configuration_directories = nullptr,
//    .f_environment_flags = 0,
//    .f_help_header = nullptr,
//    .f_help_footer = nullptr,
//    .f_version = IPLOCK_VERSION_STRING,
//    //.f_license = nullptr,
//    //.f_copyright = nullptr,
//    //.f_build_date = UTC_BUILD_DATE,
//    //.f_build_time = UTC_BUILD_TIME
//};













command::command(
          iplock * parent
        , char const * command_name
        , advgetopt::getopt::pointer_t opt)
    : f_iplock(parent)
    , f_opt(opt)
    , f_quiet(opt->is_defined("quiet"))
    , f_verbose(opt->is_defined("verbose"))
{
    // fake a pair of argc/argv which are empty
    //
    char const * argv[2]
    {
        command_name,
        nullptr
    };

    f_iplock_opt = std::make_shared<advgetopt::getopt>(
                g_iplock_configuration_options_environment,
                1,
                const_cast<char **>(argv));

    if(!f_iplock_opt->is_defined("chain"))
    {
        std::cerr << "iplock:error: the \"chain\" parameter is required in \"iplock.conf\"." << std::endl;
        exit(1);
    }

    f_chain = f_iplock_opt->get_string("chain");
    if(f_chain.empty()
    || f_chain.size() > 30)
    {
        std::cerr << "iplock:error: the \"chain\" parameter cannot be more than 30 characters nor empty." << std::endl;
        exit(1);
    }

    std::for_each(
              f_chain.begin()
            , f_chain.end()
            , [&](auto const & c)
            {
                if((c < 'a' || c > 'z')
                && (c < 'A' || c > 'Z')
                && (c < '0' || c > '9')
                && c != '_')
                {
                    std::cerr << "error:iplock: invalid \"chain=...\" option \"" << f_chain << "\", only [a-zA-Z0-9_]+ are supported." << std::endl;
                    exit(1);
                }
            });

    f_interface = f_iplock_opt->get_string("interface");
    if(f_interface.empty()
    || f_interface.size() >= IFNAMSIZ)
    {
        std::cerr << "iplock:error: the \"interface\" parameter cannot be more than "
                  << IFNAMSIZ
                  << " characters nor empty." << std::endl;
        exit(1);
    }

    // there is a size limit, but not characters
    //std::for_each(
    //          f_interface.begin()
    //        , f_interface.end()
    //        , [&](auto const & c)
    //        {
    //            if((c < 'a' || c > 'z')
    //            && (c < 'A' || c > 'Z')
    //            && (c < '0' || c > '9')
    //            && c != '_')
    //            {
    //                std::cerr << "error:iplock: invalid \"interface=...\" option \"" << f_interface << "\", only [a-zA-Z0-9_]+ are supported." << std::endl;
    //                exit(1);
    //            }
    //        });
}


command::~command()
{
}


void command::verify_ip(std::string const & ip)
{
    // TODO: add support for IPv6 -- we now has our libaddr
    //       library in a contrib...
    //
    int c(1);
    int n(-1);
    char const * s(ip.c_str());
    while(*s != '\0')
    {
        if(*s >= '0' && *s <= '9')
        {
            if(n == -1)
            {
                n = *s - '0';
            }
            else
            {
                n = n * 10 + *s - '0';

                // make sure it does not overflow
                if(n > 255)
                {
                    std::cerr << "iplock:error: IPv4 numbers are limited to a value between 0 and 255, \"" << ip << "\" is invalid." << std::endl;
                    exit(1);
                }
            }
        }
        else if(*s == '.')
        {
            if(n == -1)
            {
                std::cerr << "iplock:error: IPv4 addresses are currently limited to IPv4 syntax only (a.b.c.d) \"" << ip << "\" is invalid." << std::endl;
            }
            // reset the number
            n = -1;
            ++c;
        }
        else
        {
            std::cerr << "iplock:error: IPv4 addresses are currently limited to IPv4 syntax only (a.b.c.d) \"" << ip << "\" is invalid." << std::endl;
            exit(1);
        }
        ++s;
    }
    if(c != 4 || n == -1)
    {
        std::cerr << "iplock:error: IPv4 addresses are currently limited to IPv4 syntax with exactly 4 numbers (a.b.c.d), " << c << " found in \"" << ip << "\" is invalid." << std::endl;
        exit(1);
    }
}




} // namespace tool
// vim: ts=4 sw=4 et
