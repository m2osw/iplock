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


// C++
//
#include    <iostream>


// C
//
#include    <net/if.h>


// last include
//
#include    <snapdev/poison.h>



namespace tool
{



/** \brief Scheme file options.
 *
 * This table includes all the variables supported by iplock in a
 * scheme file such as http.conf.
 */
advgetopt::option const g_iplock_configuration_options[] =
{
    advgetopt::define_option(
          advgetopt::Name("batch")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("/sbin/iptables-restore --noflush")
        , advgetopt::Help("Command use to add multiple firewall rules from a file (e.g. iptables-restore).")
    ),
    advgetopt::define_option(
          advgetopt::Name("batch-cache")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("/var/cache/iplock")
        , advgetopt::Help("Directory where batch temporary scripts get saved.")
    ),
    advgetopt::define_option(
          advgetopt::Name("batch-footer")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("COMMIT")
        , advgetopt::Help("Footer to mark the end of the batch file which the batch tool processes.")
    ),
    advgetopt::define_option(
          advgetopt::Name("block")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("/sbin/iptables -w -t filter")
        , advgetopt::Help("Command used to add a block rule to the firewall (e.g. iptables -w).")
    ),
    advgetopt::define_option(
          advgetopt::Name("chain")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("unwanted")
        , advgetopt::Help("The name of the chain that iplock is expected to work with.")
    ),
    advgetopt::define_option(
          advgetopt::Name("check")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("/sbin/iptables -w -t filter")
        , advgetopt::Help("The command used to perform a check of the current firewall rules.")
    ),
    advgetopt::define_option(
          advgetopt::Name("flush")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("/sbin/iptables -w -t filter -F [chain]")
        , advgetopt::Help("The name of the command which will flush rules from a table.")
    ),
    advgetopt::define_option(
          advgetopt::Name("interface")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        // NO DEFAULT -- user must specify that one in his iplock.conf file
        , advgetopt::Help("The name of the interface that iplock is expected to work with..")
    ),
    advgetopt::define_option(
          advgetopt::Name("unblock")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("/sbin/iptables -w -t filter")
        , advgetopt::Help("Command used to remove a block rule from the firewall (e.g. iptables -w).")
    ),

    advgetopt::end_options()
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








command::command(
          iplock * parent
        , char const * command_name
        , advgetopt::getopt::pointer_t opts)
    : f_iplock(parent)
    , f_opts(opts)
    , f_quiet(opts->is_defined("quiet"))
    , f_verbose(opts->is_defined("verbose"))
{
    // fake a pair of argc/argv which are empty
    //
    char const * argv[2]
    {
        command_name,
        nullptr
    };

    f_iplock_opts = std::make_shared<advgetopt::getopt>(
                g_iplock_configuration_options_environment,
                1,
                const_cast<char **>(argv));

    if(!f_iplock_opts->is_defined("chain"))
    {
        std::cerr << "iplock:error: the \"chain\" parameter is required in \"iplock.conf\"." << std::endl;
        exit(1);
    }

    f_chain = f_iplock_opts->get_string("chain");
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

    f_interface = f_iplock_opts->get_string("interface");
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


int command::exit_code() const
{
    return f_exit_code;
}


} // namespace tool
// vim: ts=4 sw=4 et
