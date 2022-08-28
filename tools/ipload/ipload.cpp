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

#include    "default_firewall.h"
#include    "basic_ipv4.h"
#include    "basic_ipv6.h"
#include    "utils.h"


// iplock
//
#include    <iplock/exception.h>
#include    <iplock/version.h>


// libaddr
//
#include    <libaddr/addr_parser.h>


// advgetopt
//
#include    <advgetopt/exception.h>


// snaplogger
//
#include    <snaplogger/message.h>
#include    <snaplogger/options.h>


// snapdev
//
#include    <snapdev/file_contents.h>
#include    <snapdev/glob_to_list.h>
#include    <snapdev/string_replace_many.h>


// boost
//
#include    <boost/preprocessor/stringize.hpp>


// C++
//
//#include    <iostream>
//#include    <fstream>
//#include    <sstream>


// C
//
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
          advgetopt::Name("load")
        , advgetopt::ShortName('l')
        , advgetopt::Flags(advgetopt::command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("Load or reload all the rules.")
    ),
    advgetopt::define_option(
          advgetopt::Name("show")
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("Show the rules. Like --load but instead of loading the rules to iptables, show them in your console.")
    ),
    advgetopt::define_option(
          advgetopt::Name("verify")
        , advgetopt::Flags(advgetopt::standalone_command_flags<
                      advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("Verify the rules. Like --load but without the final step of actually loading the rules in iptables.")
    ),

    // OPTIONS
    //
    advgetopt::define_option(
          advgetopt::Name("comment")
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::Help("Add comments to the output of the --show command (although iptable-restore does not support those).")
    ),
    advgetopt::define_option(
          advgetopt::Name("no-defaults")
        , advgetopt::ShortName('N')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::Help("Prevent ipload from using defaults to setup the firewall.")
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
          advgetopt::Name("rules")
        , advgetopt::ShortName('r')
        , advgetopt::Flags(advgetopt::option_flags<
                      advgetopt::GETOPT_FLAG_GROUP_OPTIONS
                    , advgetopt::GETOPT_FLAG_COMMAND_LINE
                    , advgetopt::GETOPT_FLAG_ENVIRONMENT_VARIABLE>())
        , advgetopt::DefaultValue("/usr/share/iplock/ipload:/etc/iplock/ipload")
        , advgetopt::Help("Path to the rules to load in iptables.")
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
    .f_license = "GNU GPL 3",
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

    if(f_opts.is_defined("load"))
    {
        f_command |= COMMAND_LOAD;
    }
    if(f_opts.is_defined("show"))
    {
        f_command |= COMMAND_SHOW;
    }
    if(f_opts.is_defined("verify"))
    {
        f_command |= COMMAND_VERIFY;
    }

    switch(f_command)
    {
    case COMMAND_LOAD:
    case COMMAND_SHOW:
    case COMMAND_VERIFY:
        break;

    case 0:
        SNAP_LOG_ERROR
            << "you need to enter one of the supported commands: --load, --show, or --verify."
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
    case COMMAND_LOAD:
        // all iptables commands require the user to be root.
        //
        make_root();
        load_basic();
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
        }
        if(!convert())
        {
            return 1;
        }
        load_to_iptables();
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
        show();
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


bool ipload::load_data()
{
    if(f_variables == nullptr)
    {
        f_variables = std::make_shared<advgetopt::variables>();
    }

    std::string const paths(f_opts.get_string("rules"));

    advgetopt::string_list_t path_list;
    advgetopt::split_string(paths, path_list, {":"});

    for(auto const & path : path_list)
    {
        snapdev::glob_to_list<std::list<std::string>> glob;
        if(!glob.read_path<
                 snapdev::glob_to_list_flag_t::GLOB_FLAG_IGNORE_ERRORS,
                 snapdev::glob_to_list_flag_t::GLOB_FLAG_RECURSIVE>(path + "/*.conf"))
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
        for(auto const & n : glob)
        {
            load_config(n);
        }
    }

    if(f_parameters.empty())
    {
        SNAP_LOG_FATAL
            << "no chains/sections/rules found with path(s) \""
            << paths
            << "\"."
            << SNAP_LOG_SEND;
        return false;
    }

    return true;
}


void ipload::create_defaults()
{
    // the load_data() fails (no files, in most cases) then we want a
    // fallback to block the firewall (because by default the Linux
    // firewall is wide open)
    //
    snapdev::file_contents defaults("/tmp/default_firewall.conf", true);
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

    advgetopt::conf_file::parameters_t config_params;
    load_conf_file(defaults.filename(), config_params);
    add_params(config_params);
}


void ipload::load_config(std::string const & filename)
{
    advgetopt::conf_file::parameters_t config_params;

    load_conf_file(filename, config_params);

    advgetopt::string_list_t extra_files(advgetopt::insert_group_name(filename, "ipload", "iplock"));
    for(auto const & e : extra_files)
    {
        load_conf_file(e, config_params);
    }

    add_params(config_params);
}


void ipload::add_params(advgetopt::conf_file::parameters_t config_params)
{
    // now save all the parameters loaded from that one file and overrides
    // into our main list of parameters; here overrides are not allowed
    // except for the special case of "rules::<name>::enabled" for which
    // the value "false" has higher priority
    //
    for(auto const & p : config_params)
    {
        auto it(f_parameters.find(p.first));
        if(it == f_parameters.end())
        {
            // not yet defined, we can just copy the value
            //
            f_parameters[p.first] = p.second;
            continue;
        }

        // it exists, we are allowed to diable an entry using the
        // 'enabled = false' technique, otherwise, it is an error
        //
        // size == "rules::" + at least 1 char + "::enabled"
        //
        if(p.first.length() >= (7 + 1 + 9)
        && strncmp(p.first.c_str(), "rules::", 7) == 0
        && strncmp(p.first.c_str() + p.first.length() - 9, "::enabled", 9) == 0)
        {
            if(advgetopt::is_false(it->second))
            {
                // it's already false, nothing to change and acceptable
                //
                continue;
            }

            if(advgetopt::is_false(p.second))
            {
                // the new one is false, make sure the old one is too
                //
                f_parameters[p.first] = "0"; // "0" is shorter than "false"
                continue;
            }

            SNAP_LOG_RECOVERABLE_ERROR
                << "the \""
                << p.first
                << "\" parameter cannot be duplicated unless set to true once in the main definition and false everywhere else."
                << SNAP_LOG_SEND;
        }
        else
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "the \""
                << p.first
                << "\" parameter cannot be duplicated (\""
                << p.second.get_value()
                << "\" versus \""
                << it->second.get_value()
                << "\")."
                << SNAP_LOG_SEND;
        }
    }
}


void ipload::load_conf_file(
      std::string const & filename
    , advgetopt::conf_file::parameters_t & config_params)
{
    advgetopt::conf_file_setup conf_setup(filename);
    if(!conf_setup.is_valid())
    {
        return;
    }
    advgetopt::conf_file::pointer_t conf(advgetopt::conf_file::get_conf_file(conf_setup));

    // any file can include some variables
    //
    // TODO: look into not allowing overrides
    //
    snapdev::NOT_USED(conf->section_to_variables("variables", f_variables));

    // retrieve all the parameters in our own variable
    // here parameters are expected to be overwritten between files
    //
    advgetopt::conf_file::parameters_t const params(conf->get_parameters());
    for(auto const & p : params)
    {
        config_params[p.first] = p.second;
    }
}


void ipload::load_basic()
{
    // user doesn't want defaults?
    //
    if(f_opts.is_defined("no-defaults"))
    {
        return;
    }

    // avoid running this code more than once
    //
    std::string const flag("/run/iplock/basic.installed");
    snapdev::file_contents installed(flag, true);
    if(installed.exists())
    {
        return;
    }
    installed.contents("yes\n");
    if(!installed.write_all())
    {
        SNAP_LOG_WARNING
            << "could not create flag \""
            << flag
            << "\"."
            << SNAP_LOG_SEND;
    }

    // install a default, very basic IPv4 firewall
    //
    {
        FILE * p(popen("iptables-restore", "w"));
        fwrite(tools_ipload::basic_ipv4, sizeof(char), tools_ipload::basic_ipv4_size, p);
        int const r(pclose(p));
        if(r != 0)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "the basic IPv4 firewall could not be loaded."
                << SNAP_LOG_SEND;
        }
    }

    // install a default, very basic IPv4 firewall
    //
    {
        FILE * p(popen("ip6tables-restore", "w"));
        fwrite(tools_ipload::basic_ipv6, sizeof(char), tools_ipload::basic_ipv6_size, p);
        int const r(pclose(p));
        if(r != 0)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "the basic IPv6 firewall could not be loaded."
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
    section::vector_t sections;
    rule::vector_t rules;

    auto p(f_parameters.begin());
    while(p != f_parameters.end())
    {
        if(p->first == "log-introducer") // dashes are changed to '-' by advgetopt
        {
            f_log_introducer = p->second;
            while(f_log_introducer.back() == ' ')
            {
                f_log_introducer.pop_back();
            }
            ++p;
            continue;
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
            for(auto const & t : f_tables)
            {
                if(t->get_prefix() == tbl->get_prefix())
                {
                    SNAP_LOG_ERROR
                        << "each table must use a different prefix: \""
                        << t->get_name()
                        << "\" and \""
                        << tbl->get_name()
                        << "\" have the same prefix \""
                        << t->get_prefix()
                        << "\". Only one table can use the empty (a.k.a. \"default\") prefix."
                        << SNAP_LOG_SEND;
                    valid = false;
                }
            }
            f_tables.push_back(tbl);
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
            chain::pointer_t c(std::make_shared<chain>(p, f_parameters, f_variables));
            f_chains[snapdev::string_replace_many(c->get_name(), {{"-","_"}})] = c;
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
            sections.push_back(std::make_shared<section>(p, f_parameters, f_variables));
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
            rules.push_back(std::make_shared<rule>(p, f_parameters, f_variables));
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

    if(!process_chains())
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

    return valid;
}


bool ipload::process_chains()
{
    bool valid(true);
    for(auto const & c : f_chains)
    {
        std::string const & name(c.first);
        std::int64_t len(-1);
        table::pointer_t tbl;
        for(auto const & t : f_tables)
        {
            std::string const & prefix(t->get_prefix());

            // the prefix already includes the '_' separator unless empty
            //
            if(strncmp(name.c_str(), prefix.c_str(), prefix.length()) == 0)
            {
                // this is a match!
                //
                if(static_cast<std::int64_t>(prefix.length()) > len)
                {
                    tbl = t;
                    len = prefix.length();
                }
            }
        }
        if(tbl == nullptr)
        {
            SNAP_LOG_ERROR
                << "could not find a table for chain \""
                << name
                << "\"."
                << SNAP_LOG_SEND;
            valid = false;
        }
        else
        {
            tbl->add_chain(c.second);
        }
    }

    return valid;
}


bool ipload::process_sections(section::vector_t sections)
{
    bool valid(true);

    for(auto const & c : f_chains)
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

    return valid;
}


bool ipload::process_rules(rule::vector_t rules)
{
    bool valid(true);

    for(auto const & r : rules)
    {
        advgetopt::string_list_t const & chain_names(r->get_chains());
        for(auto const & name : chain_names)
        {
            auto it(f_chains.find(name));
            if(it == f_chains.end())
            {
                SNAP_LOG_ERROR
                    << "could not find a chain \""
                    << name
                    << "\" for rule \""
                    << r->get_name()
                    << "\"."
                    << SNAP_LOG_SEND;
                valid = false;
            }
            else if(!it->second->add_rule(r))
            {
                valid = false;
            }
        }
    }

    return valid;
}




bool ipload::generate_tables(std::ostream & out)
{
    for(auto const & t : f_tables)
    {
        out << "*" << t->get_name() << "\n";

        chain::vector_t const & chains(t->get_chains());

        // first we want a list of chains at the start of the filter
        // definition; we first print iptables internal names, mainly
        // for organization, then user defined chains
        //
        for(auto const & c : chains)
        {
            if(!c->is_system_chain())
            {
                continue;
            }
            if(!generate_chain_name(out, c))
            {
                return false;
            }
        }
        for(auto const & c : chains)
        {
            if(c->is_system_chain())
            {
                continue;
            }
            if(!generate_chain_name(out, c))
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
            if(!c->is_system_chain())
            {
                continue;
            }
            if(!generate_chain(out, c))
            {
                return false;
            }
        }
        for(auto const & c : chains)
        {
            if(c->is_system_chain())
            {
                continue;
            }
            if(!generate_chain(out, c))
            {
                return false;
            }
        }
    }

    return true;
}


bool ipload::generate_chain_name(std::ostream & out, chain::pointer_t c)
{
    out << ":"
        << c->get_name()
        << ' '
        << (c->is_system_chain() ? c->get_policy_name() : "-")
        << " [0:0]\n";

    return true;
}


bool ipload::generate_chain(std::ostream & out, chain::pointer_t c)
{
    // the sections are there to group rules; in themselves they do not
    // generate anything in the output (except if we want to add comments
    // when the --show option is used)
    //
    section_reference::vector_t refs(c->get_section_references());
    for(auto const & s : refs)
    {
        if(!generate_rules(out, c, s))
        {
            return false;
        }
    }

    return true;
}


bool ipload::generate_rules(std::ostream & out, chain::pointer_t c, section_reference::pointer_t s)
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
        std::string const chain_name(snapdev::string_replace_many(
                  c->get_name()
                , {{"-", "_"}}));
        if(std::find(chains.begin(), chains.end(), chain_name) == chains.end())
        {
            throw iplock::logic_error(
                      "chain \""
                    + c->get_name()
                    + "\" not found in rule \""
                    + r->get_name()
                    + "\" list of chains.");
        }
#endif

        r->set_log_introducer(f_log_introducer);
        out << r->to_iptables_rules(c->get_name());

        if(!r->is_valid())
        {
            valid = false;
        }
    }

    return valid;
}


void ipload::load_to_iptables()
{
}


void ipload::show()
{
    std::cout << f_output;
}


// vim: ts=4 sw=4 et
