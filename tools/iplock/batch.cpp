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
 * \brief batch tool.
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
#include    "batch.h"

#include    "flush.h"
#include    "scheme.h"


// iplock
//
//#include    <iplock/version.h>


// snapdev
//
#include    <snapdev/string_replace_many.h>


// libaddr
//
#include    <libaddr/addr_parser.h>


// boost
//
//#include    <boost/algorithm/string/replace.hpp>
#include    <boost/filesystem.hpp>
//#include    <boost/lexical_cast.hpp>


// C++
//
#include    <iostream>
#include    <fstream>
#include    <sstream>


// C
//
//#include    <net/if.h>
#include    <stdio.h>


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
//
//
///** \brief Free a FILE object.
// *
// * This deleter is used to make sure that FILE objects get freed
// * whenever the object holding it gets destroyed.
// *
// * \param[in] f  The FILE object to be freed.
// */
//void file_deleter(FILE * f)
//{
//    fclose(f);
//}
//
//
///** \brief Free a FILE object opened by popen().
// *
// * This deleter is used to make sure that FILE objects get freed
// * whenever the object holding it gets destroyed.
// *
// * \param[in] pipe  The FILE object to be freed.
// */
//void pipe_deleter(FILE * pipe)
//{
//    pclose(pipe);
//}
//




/** \class batch
 * \brief Block the specified IP addresses.
 *
 * This class goes through the list of IP addresses specified on the
 * command line and add them to the chain as defined in ipconfig.conf.
 *
 * By default, the scheme is set to "http". It can be changed with
 * the --scheme command line option.
 */

batch::batch(iplock * parent, advgetopt::getopt::pointer_t opt)
    : command(parent, "iplock --batch", opt)
    , f_ip_addr_filename(opt->get_string("batch"))
{
}


batch::~batch()
{
}


void batch::run()
{
    typedef std::vector<std::string>        ip_list_t;
    typedef std::map<std::string,ip_list_t> scheme_map_t;
    scheme_map_t scheme_map;

    // First, read the input file. The format for each line is:
    // [ip_address] [scheme]
    //
    {
        std::ifstream ip_addrs(f_ip_addr_filename);
        if(!ip_addrs)
        {
            std::cerr << "Cannot open '" << f_ip_addr_filename << "'" << std::endl;
            exit(1);
        }

        for(int line_num = 0; !ip_addrs.eof(); ++line_num)
        {
            std::string line;
            std::getline(ip_addrs, line);

            if(line[0] == '#' || line.empty())
            {
                // Ignore comments and empty lines
                continue;
            }

            std::string::size_type const space(line.find(' '));
            if(std::string::npos == space)
            {
                std::cerr
                    << "error: an IP address followed by a scheme is required [line='"
                    << line
                    << "', num="
                    << line_num
                    << "]!\n";
                exit(1);
            }

            std::string const addr(line.substr(0, space));
            std::string const scheme (line.substr(space + 1));

            if(scheme.empty())
            {
                std::cerr
                    << "error: an IP address is followed by an empty scheme [line='"
                    << line
                    << "', num="
                    << line_num
                    << "]!\n";
                exit(1);
            }

            scheme_map[scheme].push_back(addr);
        }
    }

    // Next, flush all of the rules for the "unwanted" table.
    //
    flush fl(f_iplock, f_opt, "iplock --batch");
    fl.run();

    // Then, create the output folder and iplock file.
    //
    std::string const private_folder("/var/cache/iplock/private");
    boost::filesystem::create_directory(private_folder);
    boost::filesystem::permissions( private_folder
                                  , boost::filesystem::owner_read
                                  | boost::filesystem::owner_write
                                  | boost::filesystem::owner_exe
                                  );
    std::stringstream ss;
    ss << private_folder << "/iplock." << getpid();
    std::string const outfile(ss.str());

    // Open the output rules file.
    //
    std::ofstream rules( outfile );
    rules << "# Generated by iplock" << std::endl
          << "*filter"               << std::endl
          << ":unwanted - [0:0]"     << std::endl
             ;

    // Now iterate through the schemes and process each IP address in that scheme.
    //
    for( auto const & pair : scheme_map )
    {
        std::string const & scheme(pair.first);
        ip_list_t const   & ip_list(pair.second);

        // Read the scheme object for the current scheme.
        //
        ::tool::scheme sme(f_iplock, "iplock --batch", f_opt, scheme.c_str());
        std::string const options(sme.get_scheme_string("batch"));

        // Iterate through all of the ip addresses, and each specified port.
        //
        for(auto const & ip_addr : ip_list)
        {
            for(auto const port : sme.get_ports())
            {
                // Concatenate the rule to the rules file.
                //
                //-A unwanted -s 3.1.1.1/32 -i eth0 -p tcp -m tcp --dport 80 -j DROP
                //-A unwanted -s 3.1.1.1/32 -i eth0 -p tcp -m tcp --dport 443 -j DROP
                //
                std::string rule_options(snapdev::string_replace_many(options, {
                                { "[command]",   "" },
                                { "[chain]",     f_chain },
                                { "[port]",      std::to_string(static_cast<unsigned int>(port)) },
                                { "[ip]",        ip_addr },
                                { "[interface]", f_interface },
                            }));

                rules << rule_options << std::endl;
            }
        }
    }

    // Append footer, flush and close the file.
    //
    rules << f_iplock_opt->get_string("batch_footer") << std::endl;
    rules.flush();
    rules.close();

    // Get batch command, and call it with our new file as argument.
    //
    std::stringstream fullcmd;
    fullcmd << f_iplock_opt->get_string("batch")
            << " "
            << outfile;

    // If user specified --quiet, ignore all output.
    //
    if(f_quiet)
    {
        fullcmd << " 1>/dev/null 2>&1";
    }

    // If user specified --verbose, show the command being run.
    //
    if(f_verbose)
    {
        std::cout << fullcmd.str() << std::endl;
    }

    // Run the rules restore command.
    //
    int const rc(system(fullcmd.str().c_str()));

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
            std::cerr << fullcmd.str() << std::endl;
            errno = save_errno;
        }
        perror("iplock: netfilter command failed");
    }
#pragma GCC diagnostic pop

#ifndef _DEBUG
    // Only remove if we are not in debug mode
    //
    unlink( outfile.c_str() );
#endif
}



} // namespace tool
// vim: ts=4 sw=4 et
