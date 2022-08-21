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
#include    "count.h"


// iplock
//
#include    <iplock/version.h>


// snapdev
//
#include    <snapdev/string_replace_many.h>


//// libaddr
////
//#include    <libaddr/addr_parser.h>


// boost
//
//#include    <boost/algorithm/string/replace.hpp>
//#include    <boost/filesystem.hpp>
#include    <boost/lexical_cast.hpp>


// C++
//
#include    <iostream>
//#include    <fstream>
//#include    <sstream>


//// C
////
//#include    <net/if.h>
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
//
//
//
///** \brief Scheme file options.
// *
// * This table includes all the variables supported by iplock in a
// * scheme file such as http.conf.
// */
//advgetopt::option const g_iplock_configuration_options[] =
//{
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "batch",
//        nullptr,
//        "Command use to add multiple firewall rules from a file (e.g. iptables-restore).",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "batch_footer",
//        nullptr,
//        "Footer to mark the end of the batch file which the batch tool processes.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "block",
//        nullptr,
//        "Command used to add a block rule to the firewall (e.g. iptables -w).",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "chain",
//        nullptr,
//        "The name of the chain that iplock is expected to work with.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "check",
//        nullptr,
//        "The command used to perform a check of the current firewall rules.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "flush",
//        nullptr,
//        "The name of the command which will flush rules from a table.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "interface",
//        nullptr,
//        "The name of the interface that iplock is expected to work with.",
//        nullptr
//    },
//    {
//        '\0',
//        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
//        "unblock",
//        nullptr,
//        "Command used to remove a block rule to the firewall (e.g. iptables -w).",
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
///** \brief The list of files (one) to the iplock.conf configuration file.
// *
// * This vector includes the project name ("iplock") and the path
// * to the iplock configuration file.
// *
// * The project name is used so one can place another copy of the
// * iplock.conf file in a sub-directory named ".../iplock.d/..."
// *
// * Note that we do not give users a way to enter their own configuration
// * files. Those files can only be edited by root.
// */
//constexpr char const * const g_iplock_configuration_files[]
//{
//    "/etc/iplock/iplock.conf",
//    nullptr
//};
//
//
//
//
//// TODO: once we have stdc++20, remove all defaults
//#pragma GCC diagnostic ignored "-Wpedantic"
//advgetopt::options_environment const g_iplock_configuration_options_environment =
//{
//    .f_project_name = "iplock",
//    .f_group_name = nullptr,
//    .f_options = g_iplock_configuration_options,
//    .f_options_files_directory = nullptr,
//    .f_environment_variable_name = nullptr,
//    .f_environment_variable_intro = nullptr,
//    .f_section_variables_name = nullptr,
//    .f_configuration_files = g_iplock_configuration_files,
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
//
//
//
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



/** \brief Scheme file options.
 *
 * This table includes all the variables supported by iplock in a
 * scheme file such as http.conf.
 */
advgetopt::option const g_iplock_count_options[] =
{
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "acceptable_targets",
        nullptr,
        "The list of comma separated target names that will be counted.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "bytes_column",
        nullptr,
        "The column representing the number of bytes transferred.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "count",
        nullptr,
        "The command line to print out the counters from iptables.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "count_and_reset",
        nullptr,
        "The command line to print out and reset the counters from iptables.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "ignore_line_starting_with",
        nullptr,
        "Ignore any line starting with the specified value.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "ip_column",
        nullptr,
        "The column in which our IP is found (changes depending on whether you use an input or output IP--we are limited to the input a.k.a \"source\" IP address for now.).",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "lines_to_ignore",
        nullptr,
        "The number of lines to ignore at the start.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "packets_column",
        nullptr,
        "The column representing the number of packets received/sent.",
        nullptr
    },
    {
        '\0',
        advgetopt::GETOPT_FLAG_CONFIGURATION_FILE | advgetopt::GETOPT_FLAG_REQUIRED,
        "target_column",
        nullptr,
        "The column representing the number of packets received/sent.",
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


/** \brief The configuration files for the --count command line option.
 *
 * This vector includes a set of parameters used to load the --count
 * options from a configuration file.
 */
constexpr char const * const g_iplock_count_configuration_files[]
{
    "/etc/iplock/count.conf",
    nullptr
};



// TODO: once we have stdc++20, remove all defaults
#pragma GCC diagnostic ignored "-Wpedantic"
advgetopt::options_environment const g_iplock_count_options_environment =
{
    .f_project_name = "iplock",
    .f_group_name = nullptr,
    .f_options = g_iplock_count_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = nullptr,
    .f_environment_variable_intro = nullptr,
    .f_section_variables_name = nullptr,
    .f_configuration_files = g_iplock_count_configuration_files,
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




/** \brief Free a FILE object.
 *
 * This deleter is used to make sure that FILE objects get freed
 * whenever the object holding it gets destroyed.
 *
 * \param[in] f  The FILE object to be freed.
 */
void file_deleter(FILE * f)
{
    fclose(f);
}


/** \brief Free a FILE object opened by popen().
 *
 * This deleter is used to make sure that FILE objects get freed
 * whenever the object holding it gets destroyed.
 *
 * \param[in] pipe  The FILE object to be freed.
 */
void pipe_deleter(FILE * pipe)
{
    pclose(pipe);
}










/** \class count
 * \brief Generate a count of all the entries by IP address.
 *
 * This class goes through the list of rules we added so far in the
 * named chain and prints out the results to stdout.
 *
 * If multiple ports get blocked, then the total for all those ports
 * is reported.
 */


count::count(iplock * parent, advgetopt::getopt::pointer_t opt)
    : command(parent, "iplock --count", opt)
    , f_reset(opt->is_defined("reset"))
{
    if(opt->is_defined("scheme"))
    {
        std::cerr << "iplock:error: --scheme is not supported by --count." << std::endl;
        exit(1);
    }

    // read the count configuration file
    //
    // fake a pair of argc/argv which are empty
    //
    {
        char const * argv[2]
        {
              "iplock_count"
            , nullptr
        };
        f_count_opt = std::make_shared<advgetopt::getopt>(
                      g_iplock_count_options_environment
                    , 1
                    , const_cast<char **>(argv));
    }

    // parse the list of targets immediately
    //
    {
        std::string const targets(f_count_opt->get_string("acceptable_targets"));
        char const * t(targets.c_str());
        while(*t != '\0')
        {
            if(std::isspace(*t) || *t == ',')
            {
                ++t;
                continue;
            }

            // got a target name
            //
            std::string target;
            for(; *t != '\0' && *t != ',' && !isspace(*t); ++t)
            {
                // verify that it is an acceptable character for a target name
                //
                if((*t < 'a' || *t > 'z')
                && (*t < 'A' || *t > 'Z')
                && (*t < '0' || *t > '0')
                && *t != '_')
                {
                    std::cerr << "iplock:error: a target name only supports [a-zA-Z0-9_]+ characters." << std::endl;
                    exit(1);
                }
                target += *t;
            }
            if(target.empty()
            || target.size() > 30)
            {
                std::cerr << "iplock:error: a target name cannot be empty or larger than 30 characters." << std::endl;
                exit(1);
            }
            f_targets.push_back(target);
        }
    }
}


count::~count()
{
}


void count::run()
{
    // the iptables -L command line option does not give you any formatting
    // or filtering power so we instead define many parameters in the
    // count.conf configuration file which we use here to parse the data
    // out
    //
    struct data_t
    {
        typedef std::map<std::string, data_t>   ip_map_t;

                        data_t(int64_t packets = 0, int64_t bytes = 0)
                            : f_packets(packets)
                            , f_bytes(bytes)
                        {
                        }

        data_t &        operator += (data_t const & rhs)
                        {
                            f_packets += rhs.f_packets;
                            f_bytes += rhs.f_bytes;

                            return *this;
                        }

        int64_t         f_packets = 0;
        int64_t         f_bytes = 0;
    };

    // run the command and retrieve its output
    //
    std::string cmd;
    if(f_reset)
    {
        cmd = f_count_opt->get_string("count_and_reset");
    }
    else
    {
        cmd = f_count_opt->get_string("count");
    }
    cmd = snapdev::string_replace_many(cmd, {
                { "[chain]",     f_chain },
                { "[interface]", f_interface },
            });

    if(f_verbose)
    {
        std::cerr << "iplock:info: command to read counters: \"" << cmd << "\"." << std::endl;
    }

    std::shared_ptr<FILE> f(popen(cmd.c_str(), "r"), pipe_deleter);

    // we have a first very simple loop that allows us to read
    // lines to be ignored by not saving them anywhere
    //
    for(long lines_to_ignore(f_count_opt->get_long("lines_to_ignore")); lines_to_ignore > 0; --lines_to_ignore)
    {
        for(;;)
        {
            int const c(fgetc(f.get()));
            if(c == EOF)
            {
                std::cerr << "iplock:error: unexpected EOF while reading a line of output." << std::endl;
                exit(1);
            }
            if(c == '\n' || c == '\r')
            {
                break;
            }
        }
    }

    // the column we are currently interested in
    //
    // WARNING: in the configuration file, those column numbers are 1 based
    //          just like the rule number in iptables...
    //
    long const packets_column(f_count_opt->get_long("packets_column") - 1);
    long const bytes_column(f_count_opt->get_long("bytes_column") - 1);
    long const target_column(f_count_opt->get_long("target_column") - 1);
    long const ip_column(f_count_opt->get_long("ip_column") - 1);

    // make sure it is not completely out of range
    //
    if(packets_column < 0 || packets_column >= 100
    || bytes_column < 0   || bytes_column >= 100
    || target_column < 0  || target_column >= 100
    || ip_column < 0      || ip_column >= 100)
    {
        std::cerr << "iplock:error: unexpectendly small or large column number (number is expected to be between 1 and 99)." << std::endl;
        exit(1);
    }

    // make sure the user is not trying to get different values from
    // the exact same column (that is a configuration bug!)
    //
    if(packets_column == bytes_column
    || packets_column == target_column
    || packets_column == ip_column
    || bytes_column == target_column
    || bytes_column == ip_column
    || target_column == ip_column)
    {
        std::cerr << "iplock:error: all column numbers defined in count.conf must be different." << std::endl;
        exit(1);
    }

    // compute the minimum size that the `columns` vector must be to
    // be considered valid
    //
    size_t const min_column_count(std::max(packets_column, std::max(bytes_column, std::max(target_column, ip_column))) + 1);

    // get the starting column to be ignored (i.e. the -Z option adds
    // a line at the bottom which says "Zeroing chain `<chain-name>`"
    //
    std::string const ignore_line_starting_with(f_count_opt->get_string("ignore_line_starting_with"));

    // number of IP addresses allowed in the output or 0 for all
    //
    int const ip_max(f_opt->size("--"));

    // a map indexed by IP addresses with all the totals
    //
    data_t::ip_map_t totals;

    bool const merge_totals(f_opt->is_defined("total"));

    for(;;)
    {
        // read one line of output, immediately break it up in columns
        //
        std::vector<std::string> columns;
        std::string column;
        for(;;)
        {
            int const c(fgetc(f.get()));
            if(c == EOF)
            {
                if(!column.empty())
                {
                    std::cerr << "iplock:error: unexpected EOF while reading a line of output." << std::endl;
                    exit(1);
                }
                break;
            }
            if(c == '\n' || c == '\r')
            {
                break;
            }
            if(c == ' ')
            {
                // ignore empty columns (this happens because there are
                // many spaces between each column)
                //
                if(!column.empty()
                && (!columns.empty() || ignore_line_starting_with != column))
                {
                    columns.push_back(column);
                    column.clear();
                }
                continue;
            }
            column += c;

            // prevent columns that are too wide
            //
            if(column.length() > 256)
            {
                std::cerr << "iplock:error: unexpected long column, stopping process." << std::endl;
                exit(1);
            }
        }

        // are we done? (found EOF after the last line, thus no columns)
        //
        if(columns.empty())
        {
            break;
        }

        // make sure we have enough columns
        //
        if(columns.size() < min_column_count)
        {
            std::cerr << "iplock:error: not enough columns to satisfy the configuration column numbers." << std::endl;
            exit(1);
        }

        // filter by targets?
        //
        if(!f_targets.empty()
        && std::find(f_targets.begin(), f_targets.end(), columns[target_column]) == f_targets.end())
        {
            // target filtering missed
            //
            continue;
        }

        // get the source IP
        // make sure to remove the mask if present
        //
        std::string source_ip(columns[ip_column]);
        std::string::size_type pos(source_ip.find('/'));
        if(pos != std::string::npos)
        {
            source_ip = source_ip.substr(0, pos);
        }

        // filter by IP?
        //
        if(ip_max > 0)
        {
            bool found(false);
            for(int idx(0); idx < ip_max; ++idx)
            {
                std::string const ip(f_opt->get_string("--", idx));
                verify_ip(ip); // TODO: this should be done in a loop ahead of time instead of each time we loop here!

                if(source_ip == ip)
                {
                    found = true;
                    break;
                }
            }
            if(!found)
            {
                // ip filter missed
                //
                continue;
            }
        }

        // we got a valid set of columns, get the counters
        //
        int64_t const packets(boost::lexical_cast<int64_t>(columns[packets_column]));
        int64_t const bytes(boost::lexical_cast<int64_t>(columns[bytes_column]));

        // add this line's counters to the existing totals
        //
        data_t const line_counters(packets, bytes);
        if(merge_totals)
        {
            // user wants one grand total, ignore source_ip
            //
            totals["0.0.0.0"] += line_counters;
        }
        else
        {
            totals[source_ip] += line_counters;
        }
    }

    // done with the pipe
    //
    f.reset();

    // got the totals now!
    //
    for(auto const & t : totals)
    {
        std::cout << t.first << " " << t.second.f_packets << " " << t.second.f_bytes << std::endl;
    }
}



} // namespace tool
// vim: ts=4 sw=4 et
