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
#include    "block_or_unblock.h"

#include    "controller.h"


// iplock
//
#include    <iplock/exception.h>


// snapdev
//
#include    <snapdev/file_contents.h>
#include    <snapdev/string_replace_many.h>


// snaplogger
//
#include    <snaplogger/logger.h>
#include    <snaplogger/message.h>


// C++
//
#include    <iostream>


// last include
//
#include    <snapdev/poison.h>



namespace tool
{



block_or_unblock::block_or_unblock(controller * parent, char const * command_name)
    : command(parent, command_name)
{
    if(f_controller->opts().is_defined("reset"))
    {
        throw iplock::invalid_parameter("--reset is not supported by the --block or --unblock commands.");
    }
    if(f_controller->opts().is_defined("total"))
    {
        throw iplock::invalid_parameter("--total is not supported by the --block or --unblock commands.");
    }
}


block_or_unblock::~block_or_unblock()
{
}


void block_or_unblock::handle_ips(std::string const & cmd, mode_t mode)
{
    f_command = cmd;
    f_mode = mode;

    get_allowlist();

    // first use the IPs specified on the command line
    //
    int const max(f_controller->opts().size("--"));
    for(int idx(0); idx < max; ++idx)
    {
        add_ips(f_controller->opts().get_string("--", idx));
    }

    // second, check if the user specified a file, if so also add the
    // IPs from that file
    //
    if(f_controller->opts().is_defined("ips"))
    {
        snapdev::file_contents ips(f_controller->opts().get_string("ips"));
        if(ips.read_all())
        {
            add_ips(ips.contents());
        }
        else
        {
            SNAP_LOG_MAJOR
                << "file \""
                << f_controller->opts().get_string("ips")
                << "\" does not exist."
                << SNAP_LOG_SEND;
            f_exit_code = 1;
        }
    }

    if(f_set_rules.empty())
    {
        if(f_found_ips)
        {
            if(f_verbose)
            {
                SNAP_LOG_VERBOSE
                    << "iplock:notice: all IPs are allowlisted."
                    << SNAP_LOG_SEND;
            }
        }
        else
        {
            SNAP_LOG_ERROR
                << "no IPs were specified with the --block or --unblock command."
                << SNAP_LOG_SEND;
            f_exit_code = 1;
        }
        return;
    }

    if(snaplogger::logger::get_instance()->get_lowest_severity() <= snaplogger::severity_t::SEVERITY_DEBUG)
    {
        // in "debug mode", also show the f_set_rules
        //
        std::cout
            << "# Set rules to be passed to the ipset command:\n"
            << f_set_rules
            << '\n';  // add an empty line to make it easier to see the ipset command
    }

    char const * load_cmd("/sbin/ipset restore -!");
    if(f_verbose)
    {
        SNAP_LOG_VERBOSE
            << load_cmd
            << SNAP_LOG_SEND;
    }
    FILE * pipe(popen(load_cmd, "w"));
    if(fwrite(f_set_rules.c_str(), sizeof(char), f_set_rules.size(), pipe) != f_set_rules.size())
    {
        int const e(errno);
        SNAP_LOG_ERROR
            << "applying "
            << (mode == mode_t::MODE_BLOCK ? "block" : "unblock")
            << " rules failed with "
            << e
            << ", "
            << strerror(e)
            << SNAP_LOG_SEND;
        f_exit_code = 1;
    }
    int const r(pclose(pipe));
    if(r != 0)
    {
        SNAP_LOG_ERROR
            << "running \""
            << load_cmd
            << "\" returned exit code "
            << r
            << "."
            << SNAP_LOG_SEND;
        f_exit_code = 1;
    }
}


void block_or_unblock::get_allowlist()
{
    if(f_mode != mode_t::MODE_BLOCK
    || !f_iplock_config->is_defined("allowlist"))
    {
        return;
    }

    addr::addr_parser p;
    p.set_protocol(IPPROTO_TCP);        // define a protocol because otherwise we get duplicates with various protocols...
    p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_COMMAS, true);
    p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_SPACES, true);
    p.set_allow(addr::allow_t::ALLOW_MASK, true);
    p.set_allow(addr::allow_t::ALLOW_PORT, false);
    f_allowlist_ips = p.parse(f_iplock_config->get_string("allowlist"));
}


void block_or_unblock::add_ips(std::string const & ips)
{
    addr::addr_parser p;
    p.set_protocol(IPPROTO_TCP);        // define a protocol because otherwise we get duplicates with various protocols...
    p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_COMMAS, true);
    p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_SPACES, true);
    p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_NEWLINES, true);
    p.set_allow(addr::allow_t::ALLOW_MASK, true);
    p.set_allow(addr::allow_t::ALLOW_PORT, false);
    p.set_allow(addr::allow_t::ALLOW_COMMENT_HASH, true);
    p.set_allow(addr::allow_t::ALLOW_COMMENT_SEMICOLON, true);
    addr::addr_range::vector_t ranges(p.parse(ips));

    if(ranges.empty())
    {
        return;
    }
    f_found_ips = true;

    for(auto const & r : ranges)
    {
        if(!r.has_from()
        || r.has_to())
        {
            // I don't think this can happen with the options used above,
            // but just in case, since we do not currently support this...
            //
            SNAP_LOG_ERROR
                << "the --block and --unblock commands do not yet support IP ranges."
                << SNAP_LOG_SEND;
            f_exit_code = 1;
            continue;
        }

        addr::addr a(r.get_from());
        std::string const ip(a.to_ipv4or6_string(addr::STRING_IP_ADDRESS | addr::STRING_IP_MASK_IF_NEEDED));

        // if we are trying to block but the address is allowlisted,
        // then skip that IP
        //
        if(f_mode == mode_t::MODE_BLOCK
        && addr::address_match_ranges(f_allowlist_ips, a))
        {
            if(f_verbose)
            {
                SNAP_LOG_VERBOSE
                    << "iplock:notice: ip address "
                    << ip
                    << " is allowlisted, ignoring."
                    << SNAP_LOG_SEND;
            }
            continue;
        }

        std::string list_name(get_set_name());
        list_name += "_ipv";
        list_name += a.is_ipv4() ? '4' : '6';

        f_set_rules += snapdev::string_replace_many(f_command, {
                        { "[set]", list_name },
                        { "[ip]", ip },
                    });
        f_set_rules += '\n';
    }
}



} // namespace tool
// vim: ts=4 sw=4 et
