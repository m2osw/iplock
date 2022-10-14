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
#include    "block_or_unblock.h"


// snapdev
//
#include    <snapdev/string_replace_many.h>


// libaddr
//
#include    <libaddr/addr_parser.h>


// C++
//
#include    <iostream>


// last include
//
#include    <snapdev/poison.h>



namespace tool
{



block_or_unblock::block_or_unblock(iplock * parent, char const * command_name, advgetopt::getopt::pointer_t opts)
    : scheme(parent, command_name, opts)
{
    if(opts->is_defined("reset"))
    {
        std::cerr << "error:iplock: --reset is not supported by --block or --unblock." << std::endl;
        exit(1);
    }
    if(opts->is_defined("total"))
    {
        std::cerr << "error:iplock: --total is not supported by --block or --unblock." << std::endl;
        exit(1);
    }

    // make sure there is at least one IP address
    //
    if(opts->size("--") == 0)
    {
        std::cerr << "error:iplock: --block and --unblock require at least one IP address." << std::endl;
        exit(1);
    }

    // get the list of ports immediately
    //
    if(f_ports.empty())
    {
        std::cerr << "error:iplock: you must specify at least one port." << std::endl;
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

    addr::addr_range::vector_t allowlist_ips;
    if(f_scheme_opts->is_defined("allowlist"))
    {
        std::string const allowlist(f_scheme_opts->get_string("allowlist"));
        addr::addr_parser p;
        p.set_protocol(IPPROTO_TCP);        // define a protocol because otherwise we get same IPs with various protocols...
        p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_COMMAS, true);
        p.set_allow(addr::allow_t::ALLOW_MULTI_ADDRESSES_SPACES, true);
        p.set_allow(addr::allow_t::ALLOW_MASK, true);
        p.set_allow(addr::allow_t::ALLOW_PORT, false);
        allowlist_ips = p.parse(allowlist);
    }

    int const max(f_opts->size("--"));
    for(int idx(0); idx < max; ++idx)
    {
        std::string const ip(f_opts->get_string("--", idx));

        // TBD: should we verify all the IPs before starting to add/remove
        //      any one of them to the firewall? (i.e. be a little more
        //      atomic kind of a thing?)
        //
        verify_ip(ip);

        // are we here to block (1) or unblock (0)?
        //
        if(run_on_result == 1)
        {
            // is this IP address allowlisted? if so, skip it
            // as we do not want to block allowlisted IPs
            //
            addr::addr_parser p;
            p.set_allow(addr::allow_t::ALLOW_PORT, false);
            addr::addr_range::vector_t ips(p.parse(ip));
            if(ips.size() > 0
            && addr::address_match_ranges(allowlist_ips, ips[0].get_from()))
            {
                if(f_verbose)
                {
                    std::cerr << "iplock:notice: ip address " << ip << " is allowlisted, ignoring." << std::endl;
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
