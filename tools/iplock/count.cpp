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

#include    "controller.h"


// iplock
//
#include    <iplock/exception.h>


// snaplogger
//
#include    <snaplogger/message.h>


// snapdev
//
#include    <snapdev/string_replace_many.h>


// libaddr
//
#include    <libaddr/addr_parser.h>


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


count::count(controller * parent)
    : command(parent, "count")
    , f_reset(f_controller->opts().is_defined("reset"))
{
    // parse the list of targets
    //
    std::string const targets(f_iplock_config->get_string("acceptable_targets"));
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
            && (*t < '0' || *t > '9')
            && *t != '_'
            && *t != '-')
            {
                throw iplock::invalid_parameter("a target name only supports [a-zA-Z0-9_-]+ characters.");
            }
            target += *t;
        }
        if(target.empty()
        || target.size() > 30)
        {
            throw iplock::invalid_parameter("a target name cannot be empty or larger than 30 characters.");
        }
        f_targets.push_back(target);
    }

    // verify the chain name
    //
    f_chain = f_iplock_config->get_string("chain");
    if(f_chain.empty()
    || f_chain.size() > 30)
    {
        throw iplock::invalid_parameter("the \"chain\" parameter cannot be empty or larger than 30 characters.");
    }
    std::for_each(
              f_chain.begin()
            , f_chain.end()
            , [&](auto const & c)
            {
                if((c < 'a' || c > 'z')
                && (c < 'A' || c > 'Z')
                && (c < '0' || c > '9')
                && c != '_'
                && c != '-')
                {
                    iplock::invalid_parameter e(
                          "invalid \"chain=...\" option \""
                        + f_chain
                        + "\", only [a-zA-Z0-9_-]+ are supported.");
                    e.set_parameter("chain", f_chain);
                    throw e;
                }
            });

}


count::~count()
{
}


void count::run()
{
// TODO: the count uses the iptables counters, but now we make use of ipset
//       so we want to support that other set of counters -- that said, we
//       can keep the iptables feature and have a way to distinguish between
//       whether the user wants to see a chain or the ipset counters...

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
    std::string cmd("[command] -t filter -L [reset] [chain] -nvx");
    std::string iptables("iptables");
    // TODO:
    //if(ipv6) {
    //    iptables = "ip6tables";
    //}
    cmd = snapdev::string_replace_many(cmd, {
                { "[command]",   iptables },
                { "[reset]",     (f_reset ? "-Z" : "") },
                { "[chain]",     f_chain },
            });

    if(f_verbose)
    {
        SNAP_LOG_VERBOSE
            << "command to read counters: \""
            << cmd
            << "\"."
            << SNAP_LOG_SEND;
    }

    std::shared_ptr<FILE> f(popen(cmd.c_str(), "r"), pipe_deleter);

    // we have a first very simple loop that allows us to read
    // lines to be ignored by not saving them anywhere
    //
    for(long lines_to_ignore(f_iplock_config->get_long("lines_to_ignore")); lines_to_ignore > 0; --lines_to_ignore)
    {
        for(;;)
        {
            int const c(fgetc(f.get()));
            if(c == EOF)
            {
                SNAP_LOG_ERROR
                    << "unexpected EOF while reading a line of output."
                    << SNAP_LOG_SEND;
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
    long const packets_column(f_iplock_config->get_long("packets_column") - 1);
    long const bytes_column(f_iplock_config->get_long("bytes_column") - 1);
    long const target_column(f_iplock_config->get_long("target_column") - 1);
    long const ip_column(f_iplock_config->get_long("ip_column") - 1);

    // make sure it is not completely out of range
    //
    if(packets_column < 0 || packets_column >= 100
    || bytes_column < 0   || bytes_column >= 100
    || target_column < 0  || target_column >= 100
    || ip_column < 0      || ip_column >= 100)
    {
        // WARNING: by now we have `<value> - 1` for each column number, so we
        //          really expect a column number from 1 to 100 even though
        //          here we check for a range between 0 and 99 inclusive
        //
        SNAP_LOG_ERROR
            << "unexpectendly small or large column number (number is expected to be between 1 and 100)."
            << SNAP_LOG_SEND;
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
        SNAP_LOG_ERROR
            << "all column numbers defined in iplock.conf must be different."
            << SNAP_LOG_SEND;
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
    std::string const ignore_line_starting_with(f_iplock_config->get_string("ignore_line_starting_with"));

    // number of IP addresses allowed in the output or 0 for all
    //
    int const ip_max(f_controller->opts().size("--"));

    // a map indexed by IP addresses with all the totals
    //
    data_t::ip_map_t totals;

    bool const merge_totals(f_controller->opts().is_defined("total"));

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
                    SNAP_LOG_ERROR
                        << "unexpected EOF while reading a line of output."
                        << SNAP_LOG_SEND;
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
                SNAP_LOG_ERROR
                    << "unexpected long column, stop processing."
                    << SNAP_LOG_SEND;
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
            SNAP_LOG_ERROR
                << "not enough columns to satisfy the configuration column numbers."
                << SNAP_LOG_SEND;
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
                std::string const ip(f_controller->opts().get_string("--", idx));
                parse_ip(ip); // TODO: this should be done in a loop ahead of time instead of each time we loop here!

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


addr::addr count::parse_ip(std::string const & ip)
{
    addr::addr_parser p;
    p.set_protocol(IPPROTO_TCP);
    p.set_allow(addr::allow_t::ALLOW_REQUIRED_ADDRESS, true);
    p.set_allow(addr::allow_t::ALLOW_PORT, false);  // this is 'true' by default
    addr::addr_range::vector_t addresses(p.parse(ip));
    if(addresses.size() != 1)
    {
        iplock::invalid_parameter e(
              "address \""
            + ip
            + "\" is not a valid IPv4 or IPv6 address: "
            + p.error_messages()
            + ".");
        e.set_parameter("ip", ip);
        e.set_parameter("parse_error", p.error_messages());
        throw e;
    }
    return addresses[0].get_from();
}



} // namespace tool
// vim: ts=4 sw=4 et
