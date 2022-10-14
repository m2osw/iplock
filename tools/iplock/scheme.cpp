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
#include    "scheme.h"


// iplock
//
#include    <iplock/version.h>
#include    <iplock/exception.h>


// C++
//
#include    <iostream>


// last include
//
#include    <snapdev/poison.h>



namespace tool
{



/** \brief Scheme file options.
 *
 * This table includes all the variables supported by iplock in a
 * scheme file such as http.conf.
 *
 * There are no defaults because each scheme is expected to define all
 * of their own parameters. The main scheme (the one .conf file appearing
 * under `/etc/iplock/schemes/...`) must defines all the parameters to
 * make sure it works as expected.
 */
advgetopt::option const g_iplock_scheme_options[] =
{
    advgetopt::define_option(
          advgetopt::Name("batch")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Rule to add a specified IP address in a batch-friendly fashion.")
    ),
    advgetopt::define_option(
          advgetopt::Name("block")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Command to block the speficied IP address.")
    ),
    advgetopt::define_option(
          advgetopt::Name("check")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Command to check whether a rule already exists or not.")
    ),
    advgetopt::define_option(
          advgetopt::Name("flush")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Command to flush the chain.")
    ),
    advgetopt::define_option(
          advgetopt::Name("ports")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Comma separated list of ports.")
    ),
    advgetopt::define_option(
          advgetopt::Name("unblock")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Command to unblock the specified IP address.")
    ),
    advgetopt::define_option(
          advgetopt::Name("allowlist")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("List of comma separated IPs to never block.")
    ),

    advgetopt::end_options()
};


// Note: this one is not const because we change the list of configuration
//       file dynamically (the name of the scheme changes)
//
// TODO: once we have stdc++20, remove all defaults
#pragma GCC diagnostic ignored "-Wpedantic"
advgetopt::options_environment g_iplock_scheme_options_environment =
{
    .f_project_name = "schemes",
    .f_group_name = nullptr,
    .f_options = g_iplock_scheme_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = nullptr,
    .f_environment_variable_intro = nullptr,
    .f_section_variables_name = nullptr,
    .f_configuration_files = nullptr,
    .f_configuration_filename = nullptr,
    .f_configuration_directories = nullptr,
    .f_environment_flags = 0,
    .f_help_header = nullptr,
    .f_help_footer = nullptr,
    .f_version = IPLOCK_VERSION_STRING,
    .f_license = nullptr,
    .f_copyright = nullptr,
    //.f_build_date = UTC_BUILD_DATE,
    //.f_build_time = UTC_BUILD_TIME
};







scheme::scheme(
          iplock * parent
        , char const * command_name
        , advgetopt::getopt::pointer_t opts
        , std::string const & scheme_name)
    : command(parent, command_name, opts)
    , f_scheme(scheme_name.empty()
                    ? opts->get_string("scheme")
                    : scheme_name)
{
    // the filename to define the ports, block, unblock commands
    //

    // the scheme cannot be an empty string
    //
    if(f_scheme.empty())
    {
        std::cerr << "error:iplock: the name specified with --scheme cannot be empty." << std::endl;
        exit(1);
    }

    // make sure we accept that string as the name of a scheme
    //
    std::for_each(f_scheme.begin()
                , f_scheme.end()
                , [&](auto const & c)
                {
                    if((c < 'a' || c > 'z')
                    && (c < 'A' || c > 'Z')
                    && (c < '0' || c > '9')
                    && c != '_')
                    {
                        std::cerr << "error:iplock: invalid --scheme option \""
                                  << f_scheme
                                  << "\", only [a-zA-Z0-9_]+ are supported."
                                  << std::endl;
                        exit(1);
                    }
                });

    // read the scheme configuration file
    //
    // since the name of the file can change, we use a fully dynamically
    // allocated vector and a specific sub-directory so users cannot
    // end up accessing another file instead of an actual scheme file
    //
    // note that the schemes-README.md is fine because it does not end
    // with .conf
    //
    std::string const scheme_path("/etc/iplock/schemes/" + f_scheme + ".conf");
    char const * const scheme_configuration_files[]
    {
          scheme_path.c_str()
        , nullptr
    };
    g_iplock_scheme_options_environment.f_configuration_files = scheme_configuration_files;

    char const * argv[2]
    {
          "iplock_scheme"
        , nullptr
    };
    f_scheme_opts = std::make_shared<advgetopt::getopt>(
                g_iplock_scheme_options_environment,
                1,
                const_cast<char **>(argv));

    // get the list of ports immediately
    //
    {
        std::string const ports(f_scheme_opts->get_string("ports"));
        char const * p(ports.c_str());
        while(*p != '\0')
        {
            if(std::isspace(*p) || *p == ',')
            {
                ++p;
                continue;
            }
            if(*p < '0' || *p > '9')
            {
                std::cerr << "iplock:error: invalid port specification in \"" << ports << "\", we only expect numbers separated by commas." << std::endl;
                exit(1);
            }

            // got a port
            //
            int port_number(*p - '0');
            for(++p; *p != '\0' && *p >= '0' && *p <= '9'; ++p)
            {
                port_number = port_number * 10 + *p - '0';
                if(port_number > 0xFFFF)
                {
                    std::cerr << "iplock:error: one of the port numbers in \"" << ports << "\" is too large." << std::endl;
                    exit(1);
                }
            }
            if(port_number == 0)
            {
                std::cerr << "iplock:error: you cannot (un)block port number 0." << std::endl;
                exit(1);
            }
            f_ports.push_back(static_cast<uint16_t>(port_number));
        }
    }
}


std::string scheme::get_command(std::string const & name) const
{
    return f_iplock_opts->get_string(name);
}


std::string scheme::get_scheme_string(std::string const & name) const
{
    return f_scheme_opts->get_string(name);
}


port_list_t const & scheme::get_ports() const
{
    return f_ports;
}


void scheme::run()
{
    throw ::iplock::logic_error("scheme::run() called.");
}


} // namespace tool
// vim: ts=4 sw=4 et
