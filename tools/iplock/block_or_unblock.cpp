//
// Copyright (c) 2007-2022  Made to Order Software Corp.  All Rights Reserved.
//
// https://snapwebsites.org/project/iplock
// contact@m2osw.com
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//


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
#include    "block_or_unblock.h"


//// iplock
////
//#include    <iplock/version.h>


// snapdev
//
#include    <snapdev/string_replace_many.h>


// libaddr
//
#include    <libaddr/addr_parser.h>


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
//
//









block_or_unblock::block_or_unblock(iplock * parent, char const * command_name, advgetopt::getopt::pointer_t opt)
    : scheme(parent, command_name, opt)
{
    if(opt->is_defined("reset"))
    {
        std::cerr << "error:iplock: --reset is not supported by --block or --unblock." << std::endl;
        exit(1);
    }
    if(opt->is_defined("total"))
    {
        std::cerr << "error:iplock: --total is not supported by --block or --unblock." << std::endl;
        exit(1);
    }

    // make sure there is at least one IP address
    //
    if(opt->size("--") == 0)
    {
        std::cerr << "error:iplock: --block and --unblock require at least one IP address." << std::endl;
        exit(1);
    }

    // get the list of ports immediately
    //
    if(f_ports.empty())
    {
        std::cerr << "iplock:error: you must specify at least one port." << std::endl;
        exit(1);
    }
}


block_or_unblock::~block_or_unblock()
{
}


void block_or_unblock::handle_ips(std::string const & name, int run_on_result)
{
    // position where each rule gets insert (if the command is --block)
    //
    int num(1);

    std::string const check_command( get_command("check") );
    std::string const check_cmdline( get_scheme_string("check") );
    //
    std::string const block_command( get_command(name) );
    std::string const block_cmdline( get_scheme_string(name) );

#if 0
std::cout << "name=" << name << std::endl;
std::cout << "check_command: " << check_command << std::endl << "block_command: " << block_command << std::endl;
std::cout << "check_cmdline: " << check_cmdline << std::endl << "block_cmdline: " << block_cmdline << std::endl;
#endif

    addr::addr_range::vector_t whitelist_ips;
    if(f_scheme_opt->is_defined("whitelist"))
    {
        std::string const whitelist(f_scheme_opt->get_string("whitelist"));
        addr::addr_parser p;
        p.set_protocol(IPPROTO_TCP);        // define a protocol because otherwise we get same IPs with various protocols...
        p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_COMMAS, true);
        p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_SPACES, true);
        p.set_allow(addr::allow_t::ALLOW_MASK, true);
        p.set_allow(addr::allow_t::ALLOW_PORT, false);
        whitelist_ips = p.parse(whitelist);
    }

    int const max(f_opt->size("--"));
    for(int idx(0); idx < max; ++idx)
    {
        std::string const ip(f_opt->get_string("--", idx));

        // TBD: should we verify all the IPs before starting to add/remove
        //      any one of them to the firewall? (i.e. be a little more
        //      atomic kind of a thing?)
        //
        verify_ip(ip);

        // are we here to block (1) or unblock (0)?
        //
        if(run_on_result == 1)
        {
            // is this IP address white listed? if so, skip it
            // as we do not want to block white listed IPs
            //
            addr::addr_parser p;
            p.set_allow(addr::allow_t::ALLOW_PORT, false);
            addr::addr_range::vector_t ips(p.parse(ip));
            if(ips.size() > 0
            && addr::address_match_ranges(whitelist_ips, ips[0].get_from()))
            {
                if(f_verbose)
                {
                    std::cerr << "iplock:notice: ip address " << ip << " is whitelisted, ignoring." << std::endl;
                }
                continue;
            }
        }

        for(auto const port : f_ports)
        {
            // replace the variables in the command line
            //
            std::string check_cmd(snapdev::string_replace_many(check_cmdline, {
                            { "[command]", check_command },
                            { "[chain]", f_chain },
                            { "[port]", std::to_string(static_cast<unsigned int>(port)) },
                            { "[ip]", ip },
                            { "[num]", std::to_string(num) },
                            { "[interface]", f_interface },
                        }));

            // although the -C does nothing, it will print a message
            // in stderr if the rule does not exist
            //
            check_cmd += " 1>/dev/null 2>&1";

            if(f_verbose)
            {
                std::cout << check_cmd << std::endl;
            }
            int const rc(system(check_cmd.c_str()));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
            if(!WIFEXITED(rc))
            {
                if(!f_verbose)
                {
                    // if not verbose, make sure to show the command so the
                    // user knows what failed
                    //
                    int const save_errno(errno);
                    std::cerr << check_cmd << std::endl;
                    errno = save_errno;
                }
                perror("iplock: netfilter command failed");

                // TBD: we cannot continue without a valid answer on this
                //      one so we just try further...
                //
                continue;
            }
            int const exit_code(WEXITSTATUS(rc));
#pragma GCC diagnostic pop

            if(exit_code == run_on_result)
            {
                // replace the variables in the command line
                //
                std::string cmd(snapdev::string_replace_many(block_cmdline, {
                                { "[command]", block_command },
                                { "[chain]", f_chain },
                                { "[port]", std::to_string(static_cast<unsigned int>(port)) },
                                { "[ip]", ip },
                                { "[num]", std::to_string(num) },
                                { "[interface]", f_interface },
                            }));

                // if user specified --quiet ignore all output
                //
                if(f_quiet)
                {
                    cmd += " 1>/dev/null 2>&1";
                }

                // if user specified --verbose show the command being run
                //
                if(f_verbose)
                {
                    std::cout << cmd << std::endl;
                }

                // run the command now
                //
                int const r(system(cmd.c_str()));
                if(r != 0)
                {
                    if(!f_verbose)
                    {
                        // if not verbose, make sure to show the command so the
                        // user knows what failed
                        //
                        int const save_errno(errno);
                        std::cerr << cmd << std::endl;
                        errno = save_errno;
                    }
                    perror("iplock: netfilter command failed");
                }

                // [num] is used by the -I command line option
                //
                // i.e. we insert at the beginning, but in the same order
                //      that the user defined his ports
                //
                ++num;
            }
        }
    }
}



} // namespace tool
// vim: ts=4 sw=4 et
