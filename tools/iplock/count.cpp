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


// boost
//
#include    <boost/lexical_cast.hpp>


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
 */
advgetopt::option const g_iplock_count_options[] =
{
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
          advgetopt::Name("count")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("iptables -t filter -L [chain] -nvx")
        , advgetopt::Help("Command to print out the counters from iptables.")
    ),
    advgetopt::define_option(
          advgetopt::Name("count_and_reset")
        , advgetopt::Flags(advgetopt::any_flags<
                      advgetopt::GETOPT_FLAG_CONFIGURATION_FILE
                    , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("iptables -t filter -L -Z [chain] -nvx")
        , advgetopt::Help("Command to print out and reset the counters from iptables.")
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
        , advgetopt::Validator("integer(0...)")
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


count::count(iplock * parent, advgetopt::getopt::pointer_t opts)
    : command(parent, "iplock --count", opts)
    , f_reset(opts->is_defined("reset"))
{
    if(opts->is_defined("scheme"))
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
        f_count_opts = std::make_shared<advgetopt::getopt>(
                                  g_iplock_count_options_environment
                                , 1
                                , const_cast<char **>(argv));
    }

    // parse the list of targets immediately
    //
    {
        std::string const targets(f_count_opts->get_string("acceptable_targets"));
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
        cmd = f_count_opts->get_string("count_and_reset");
    }
    else
    {
        cmd = f_count_opts->get_string("count");
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
    for(long lines_to_ignore(f_count_opts->get_long("lines_to_ignore")); lines_to_ignore > 0; --lines_to_ignore)
    {
        for(;;)
        {
            int const c(fgetc(f.get()));
            if(c == EOF)
            {
                std::cerr << "iplock:error: unexpected EOF while reading a line of output." << std::endl;
                f_exit_code = 1;
                return;
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
    long const packets_column(f_count_opts->get_long("packets_column") - 1);
    long const bytes_column(f_count_opts->get_long("bytes_column") - 1);
    long const target_column(f_count_opts->get_long("target_column") - 1);
    long const ip_column(f_count_opts->get_long("ip_column") - 1);

    // make sure it is not completely out of range
    //
    if(packets_column < 0 || packets_column >= 100
    || bytes_column < 0   || bytes_column >= 100
    || target_column < 0  || target_column >= 100
    || ip_column < 0      || ip_column >= 100)
    {
        // WARNING: by now we have a ... - 1 to each column number, so we
        //          really expect a column number from 1 to 100 even though
        //          here we check for a range between 0 and 99 inclusive
        std::cerr << "iplock:error: unexpectendly small or large column number (number is expected to be between 1 and 100)." << std::endl;
        f_exit_code = 1;
        return;
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
        f_exit_code = 1;
        return;
    }

    // compute the minimum size that the `columns` vector must be to
    // be considered valid
    //
    size_t const min_column_count(std::max({packets_column, bytes_column, target_column, ip_column}) + 1);

    // get the starting column to be ignored (i.e. the -Z option adds
    // a line at the bottom which says "Zeroing chain `<chain-name>`"
    //
    std::string const ignore_line_starting_with(f_count_opts->get_string("ignore_line_starting_with"));

    // number of IP addresses allowed in the output or 0 for all
    //
    int const ip_max(f_opts->size("--"));

    // a map indexed by IP addresses with all the totals
    //
    data_t::ip_map_t totals;

    bool const merge_totals(f_opts->is_defined("total"));

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
                    f_exit_code = 1;
                    return;
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
                f_exit_code = 1;
                return;
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
            f_exit_code = 1;
            return;
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
                std::string const ip(f_opts->get_string("--", idx));
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
