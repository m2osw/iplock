// Copyright (c) 2014-2024  Made to Order Software Corp.  All Rights Reserved
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

#include    "controller.h"


// iplock
//
#include    <iplock/exception.h>
#include    <iplock/version.h>


// snaplogger
//
#include    <snaplogger/logger.h>
#include    <snaplogger/message.h>


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
 * This table includes all the variables supported by iplock in its
 * configuration file. For security reasons, we read this file separate
 * from the command line options with a forced path.
 */
advgetopt::option const g_iplock_configuration_options[] =
{
    // options used by all commands
    advgetopt::define_option(
          advgetopt::Name("allowed_sets")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("unwanted")
        , advgetopt::Help("Comma separated list of sets that can be updated with iplock.")
    ),
    advgetopt::define_option(
          advgetopt::Name("allowlist")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("")
        , advgetopt::Help("List of comma separated IPs to never block.")
    ),

    // options used by the --count command
    advgetopt::define_option(
          advgetopt::Name("acceptable_targets")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("DROP")
        , advgetopt::Help("List of comma separated target names that will be counted.")
    ),
    advgetopt::define_option(
          advgetopt::Name("bytes_column")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("2")
        , advgetopt::Validator("integer(1...100)")
        , advgetopt::Help("Column representing the number of bytes transferred.")
    ),
    advgetopt::define_option(
          advgetopt::Name("chain")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("INPUT")
        , advgetopt::Help("The name of the chain to take counters from.")
    ),
    advgetopt::define_option(
          advgetopt::Name("ignore_line_starting_with")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("Zeroing")
        , advgetopt::Help("Ignore any line with this value in its first column.")
    ),
    advgetopt::define_option(
          advgetopt::Name("ip_column")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("8")
        , advgetopt::Validator("integer(1...100)")
        , advgetopt::Help("Column in which our IP is found (changes depending on whether you use an input or output IP--we are limited to the input a.k.a \"source\" IP address for now.).")
    ),
    advgetopt::define_option(
          advgetopt::Name("lines_to_ignore")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("2")
        , advgetopt::Validator("integer(0...100000)")
        , advgetopt::Help("Number of lines to ignore at the start.")
    ),
    advgetopt::define_option(
          advgetopt::Name("packets_column")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("1")
        , advgetopt::Validator("integer(1...100)")
        , advgetopt::Help("Column representing the number of packets received/sent.")
    ),
    advgetopt::define_option(
          advgetopt::Name("target_column")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("3")
        , advgetopt::Validator("integer(1...100)")
        , advgetopt::Help("Column specifying the target (action).")
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


advgetopt::conf_file_setup const g_config_setup =
        advgetopt::conf_file_setup(
                  "iplock.conf" // this is not used but it has to be defined
                , advgetopt::line_continuation_t::line_continuation_unix
                , advgetopt::ASSIGNMENT_OPERATOR_EQUAL | advgetopt::ASSIGNMENT_OPERATOR_EXTENDED
                , advgetopt::COMMENT_INI | advgetopt::COMMENT_SHELL
                , advgetopt::SECTION_OPERATOR_INI_FILE
                , advgetopt::NAME_SEPARATOR_UNDERSCORES);


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
    .f_license = nullptr,
    .f_copyright = nullptr,
    .f_build_date = UTC_BUILD_DATE,
    .f_build_time = UTC_BUILD_TIME,
    .f_groups = nullptr,
    .f_config_setup = &g_config_setup,
};








command::command(
          controller * parent
        , char const * command_name)
    : f_controller(parent)
    , f_command_name(command_name)
    , f_quiet(f_controller->opts().is_defined("quiet"))
    , f_verbose(f_controller->opts().is_defined("verbose")
        || snaplogger::logger::get_instance()->get_lowest_severity() <= snaplogger::severity_t::SEVERITY_VERBOSE)
{
    if(f_verbose)
    {
        // make it verbose if --verbose was used
        //
        // Note: if the severity is already lower, this call has no effect
        //
        snaplogger::logger::get_instance()->reduce_severity(snaplogger::severity_t::SEVERITY_VERBOSE);
    }

    char const * argv[2] = { command_name, nullptr };

    f_iplock_config = std::make_shared<advgetopt::getopt>(
                g_iplock_configuration_options_environment,
                1,
                const_cast<char **>(argv));
}

command::~command()
{
}


std::string & command::get_set_name()
{
    if(f_set_name.empty())
    {
        // this comes from the command line
        //
        f_set_name = f_controller->opts().get_string("set");

        // the list of allowed sets comes from the /etc/iplock/iplock.conf file
        // (so only admins and other packages can change the list)
        //
        advgetopt::split_string(f_iplock_config->get_string("allowed_sets"), f_allowed_set_names, {","});
        if(std::find(f_allowed_set_names.begin(), f_allowed_set_names.end(), f_set_name) == f_allowed_set_names.end())
        {
            iplock::invalid_parameter e(
                  "set \""
                + f_set_name
                + "\" is not allowed. Please try with an allowed sets instead."
                  " To see the list of allowed set try the --list-allowed-sets command line option.");
            e.set_parameter("set_name", f_set_name);
            SNAP_LOG_ERROR
                << e
                << SNAP_LOG_SEND;
            throw e;
        }
    }

    return f_set_name;
}


bool command::needs_root() const
{
    return true;
}


std::string const & command::get_command_name() const
{
    return f_command_name;
}


int command::exit_code() const
{
    return f_exit_code;
}


} // namespace tool
// vim: ts=4 sw=4 et
