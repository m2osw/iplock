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
#pragma once


// cppprocess
//
#include    <cppprocess/process.h>


// eventdispatcher
//
#include    <eventdispatcher/signal_child.h>
#include    <eventdispatcher/message.h>


// snapdev
//
#include    <snapdev/timespec_ex.h>


// C++
//
#include <vector>



namespace ipwall
{



enum class status_t
{
    BLOCK_INFO_UNDEFINED,       // never banned before
    BLOCK_INFO_BANNED,
    BLOCK_INFO_UNBANNED,        // has been banned before
};



class block_info
{
public:
    typedef std::vector<block_info>   block_info_vector_t;

                        block_info(std::string const & uri);
                        block_info(ed::message const & message, status_t status = status_t::BLOCK_INFO_BANNED);

    bool                is_valid() const;

    //void                save(libdbproxy::table::pointer_t firewall_table, std::string const & server_name);

    void                set_uri(std::string const & uri);
    void                set_scheme(std::string scheme);
    void                set_ip(std::string const & ip);
    void                set_block_limit(std::string const & period);
    void                keep_longest(block_info const & block);

    void                set_ban_count(std::int64_t count);
    std::int64_t        get_ban_count() const;
    //std::int64_t        get_total_ban_count(libdbproxy::table::pointer_t firewall_table, std::string const & server_name) const;
    void                set_packet_count(std::int64_t count);
    std::int64_t        get_packet_count() const;
    void                set_byte_count(std::int64_t count);
    std::int64_t        get_byte_count() const;

    std::string         canonicalized_uri() const;
    std::string         get_scheme() const;
    std::string         get_ip() const;
    snapdev::timespec_ex const &
                        get_block_limit() const;

    bool                operator == (block_info const & rhs) const;
    bool                operator < (block_info const & rhs) const;

    bool                iplock_block();
    bool                iplock_unblock();

private:
    bool                iplock(std::string const & cmd);
    void                process_done(
                              ed::child_status status
                            , cppprocess::process::pointer_t iplock_process);
    void                check_if_active(std::string const & ipwall_service_name);
    void                firewall_is_active();

    status_t            f_status = status_t::BLOCK_INFO_BANNED;
    std::string         f_scheme = std::string("http");
    std::string         f_ip = std::string();
    std::string         f_reason = std::string();
    snapdev::timespec_ex
                        f_block_limit = snapdev::timespec_ex();
    std::int64_t        f_ban_count = 0LL;
    std::int64_t        f_packet_count = 0LL;
    std::int64_t        f_byte_count = 0LL;
};



} // namespace ipwall
// vim: ts=4 sw=4 et
