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


// self
//
#include    "block_info.h"


// cppprocess
//
#include <cppprocess/io_capture_pipe.h>


// snaplogger
//
#include <snaplogger/message.h>


// libaddr
//
#include    <libaddr/addr_parser.h>
#include    <libaddr/exception.h>


// last include
//
#include <snapdev/poison.h>



namespace ipwall
{



block_info::block_info(ed::message const & message, status_t status)
{
    // retrieve scheme and IP
    //
    if(!message.has_parameter("uri"))
    {
        // TODO: create a snap_exception instead
        //
        throw std::runtime_error("a BLOCK message \"uri\" parameter is mandatory.");
    }

    set_uri(message.get_parameter("uri"));

    if(!message.has_parameter("period"))
    {
        // if period was not specified, block for a day
        //
        set_block_limit("day");
    }
    else
    {
        set_block_limit(message.get_parameter("period"));
    }

    if(message.has_parameter("reason"))
    {
        f_reason = message.get_parameter("reason");
    }

    f_status = status;
}


block_info::block_info(std::string const & uri)
{
    set_uri(uri);
    set_block_limit(std::string());

    // TBD: call load() but then we need a pointer to server_name
    //      and the snapfirewall_table
}


/** \brief Check whether this block info is considered valid.
 *
 * A block info may be setup to an invalid IP address or some other
 * invalid parameter. In that case we may end up with an invalid
 * \p block_info object. For example, a local IP address is never
 * blocked by snapfirewall since the default set of rules already
 * blocks all local network IP addresses.
 *
 * This function returns true if the object is considered valid and
 * can be used for a block and saved in the database.
 *
 * \return true if valid.
 *
 * \sa set_uri()
 */
bool block_info::is_valid() const
{
    return !f_ip.empty();
}


//void block_info::save(libdbproxy::table::pointer_t firewall_table, std::string const & server_name)
//{
//    if(!is_valid())
//    {
//        return;
//    }
//
//    // this is probably wrong, we may not want to save anything
//    // if still undefined
//    //
//    if(f_status == status_t::BLOCK_INFO_UNDEFINED)
//    {
//        f_status = status_t::BLOCK_INFO_BANNED;
//    }
//
//    // we want to check the info row to see whether we had an old entry
//    // because we have to remove it! (otherwise the block would stop
//    // at the time the old entry was entered instead of the new time!)
//    //
//    libdbproxy::row::pointer_t info_row(firewall_table->getRow(std::string("ip::%1").arg(f_ip)));
//    std::string const block_limit_key(std::string("%1::block_limit").arg(server_name));
//
//    // here we create a row if the item is banned
//    // and we drop the row if the item got unbanned
//    //
//    // TODO: we need to handle the case where the item get re-banned before
//    //       it gets unbanned; we need to delete the old one
//    //
//    {
//        libdbproxy::row::pointer_t ban_row(firewall_table->getRow(server_name));
//
//        // for a block, if the existing limit is further in the past,
//        // then it accept the new block, if the existing limit is in
//        // the future, then the old limit still applies and we ignore
//        // the new limit; this happens if an IP is first block for 1 year
//        // and later is blocked for 1 day (although once blocked an IP
//        // should not trigger any more blocks, but it can easily happen
//        // in a cluster)
//        //
//        // Timeline:
//        // =========
//        //
//        //              +-- current block
//        //              |
//        //              v
//        // -----+-------+-----------+------>
//        //      ^                   ^
//        //      |                   |
//        //      |                   +--- new block in the future, accepted
//        //      |
//        //      +--- new block in the past, ignored
//        //
//        //
//        // for an unblock, it does not apply because the unblock must always
//        // happens now.
//        //
//        if(info_row->exists(block_limit_key))
//        {
//            libdbproxy::value old_limit_value(info_row->getCell(block_limit_key)->getValue());
//            int64_t const old_limit(old_limit_value.safeInt64Value());
//
//            if(f_status == status_t::BLOCK_INFO_BANNED
//            && old_limit >= f_block_limit)
//            {
//                // it is already blocked for a longer time than the new
//                // time, keep the longest
//                //
//                // TODO: should we still look into saving the reason?
//                //       and ban counters?
//                //
//                return;
//            }
//            if(old_limit != f_block_limit)
//            {
//                // drop the old row
//                //
//                ban_row->dropCell(old_limit_value.binaryValue());
//            }
//        }
//
//        QByteArray limit_value;
//        libdbproxy::setInt64Value(limit_value, f_block_limit);
//        if(f_status == status_t::BLOCK_INFO_BANNED)
//        {
//            ban_row->getCell(limit_value)->setValue(canonicalized_uri());
//        }
//        else
//        {
//            // Note: this does not seem useful with the new scheme since
//            //       the cell should be dropped in the previous if() block
//            //       unless `old_limit == f_block_limit`...
//            //
//            ban_row->dropCell(limit_value);
//        }
//    }
//
//    {
//        info_row->getCell(block_limit_key)->setValue(f_block_limit);
//        info_row->getCell(std::string("%1::status").arg(server_name))->setValue(std::string(f_status == status_t::BLOCK_INFO_BANNED ? "banned" : "unbanned"));
//
//        if(!f_reason.isEmpty())
//        {
//            std::string const reason_key(std::string("%1::reason").arg(server_name));
//            if(info_row->exists(reason_key))
//            {
//                std::string const old_reasons(info_row->getCell(reason_key)->getValue().stringValue());
//                if(old_reasons != f_reason) // avoid an update (i.e. a tombstone) if same
//                {
//                    if(old_reasons.indexOf(f_reason) == -1)
//                    {
//                        // separate reasons with a "\n"
//                        info_row->getCell(reason_key)->setValue(old_reasons + "\n" + f_reason);
//                    }
//                    else
//                    {
//                        info_row->getCell(reason_key)->setValue(f_reason);
//                    }
//                }
//            }
//            else
//            {
//                info_row->getCell(reason_key)->setValue(f_reason);
//            }
//        }
//
//        // TODO: what we really want here are statistics such as # of packets
//        //       per hour, etc. so we know whether we should extend the ban
//        //       or remove it, dynamically. Also this will be part of the
//        //       history of this IP address with our services.
//        //
//        // No lock is required to increase that counter because the counter
//        // is specific to this computer and only one instance of snapfirewall
//        // runs on one computer
//        //
//        if(f_ban_count > 0)
//        {
//            std::string const ban_count_key(std::string("%1::ban_count").arg(server_name));
//            // add the existing value first
//            //
//            f_ban_count += info_row->getCell(ban_count_key)->getValue().safeInt64Value();
//            info_row->getCell(ban_count_key)->setValue(f_ban_count);
//
//            // since this counter is cumulative, we have to reset it to zero
//            // each time otherwise we would double it each time we save
//            //
//            f_ban_count = 0;
//        }
//        if(f_packet_count > 0)
//        {
//            info_row->getCell(std::string("%1::packet_count").arg(server_name))->setValue(f_packet_count);
//        }
//        if(f_byte_count > 0)
//        {
//            info_row->getCell(std::string("%1::byte_count").arg(server_name))->setValue(f_byte_count);
//        }
//
//        // save when it was created / modified
//        //
//        int64_t const now(snap::snap_communicator::get_current_date());
//        std::string const created_key(std::string("%1::created").arg(server_name));
//        if(!info_row->exists(created_key))
//        {
//            info_row->getCell(created_key)->setValue(now);
//        }
//        info_row->getCell(std::string("%1::modified").arg(server_name))->setValue(now);
//    }
//}


void block_info::set_uri(std::string const & uri)
{
    std::string::size_type const pos(uri.find("://"));
    if(pos > 0)
    {
        // there is a scheme and an IP
        //
        set_scheme(uri.substr(0, pos));
        set_ip(uri.substr(pos + 3));
    }
    else
    {
        // no scheme specified, directly use the IP
        //
        set_ip(uri);
    }
}


void block_info::set_ip(std::string const & ip)
{
    // make sure IP is not empty
    //
    if(ip.empty())
    {
        SNAP_LOG_ERROR
            << "BLOCK without a URI (or at least an IP in the \"uri\" parameter.) BLOCK will be ignored."
            << SNAP_LOG_SEND;
        return;
    }

    try
    {
        // at some point we could support "udp"?
        //
        // it does not matter much here, I would think, since we will ignore the
        // port from the addr object, we are just verifying the IP address
        //
        addr::addr a(addr::string_to_addr(ip, "", 123, "tcp"));

        switch(a.get_network_type())
        {
        case addr::network_type_t::NETWORK_TYPE_UNDEFINED:
        case addr::network_type_t::NETWORK_TYPE_PRIVATE:
        case addr::network_type_t::NETWORK_TYPE_CARRIER:
        case addr::network_type_t::NETWORK_TYPE_LINK_LOCAL:
        case addr::network_type_t::NETWORK_TYPE_LOOPBACK:
        case addr::network_type_t::NETWORK_TYPE_ANY:
            SNAP_LOG_ERROR
                << "BLOCK with an unexpected IP address type in \""
                << ip
                << "\". BLOCK will be ignored."
                << SNAP_LOG_SEND;
            return;

        case addr::network_type_t::NETWORK_TYPE_MULTICAST:
        case addr::network_type_t::NETWORK_TYPE_PUBLIC: // == NETWORK_TYPE_UNKNOWN
            break;

        }
    }
    catch(addr::addr_invalid_argument const & e)
    {
        SNAP_LOG_ERROR
            << "BLOCK with an invalid IP address in \""
            << ip
            << "\". BLOCK will be ignored. Error: "
            << e.what()
            << SNAP_LOG_SEND;
        return;
    }

    f_ip = ip;
}


void block_info::set_scheme(std::string scheme)
{
    // verify the scheme
    //
    // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    //
    // See:
    // https://tools.ietf.org/html/rfc3986#section-3.1
    //
    bool bad_scheme(false);
    int const max(scheme.length());
    if(max > 0)
    {
        int const c(scheme[0]);
        if(c >= 'A' && c <= 'Z')
        {
            // transform to lowercase (canonicalization)
            //
            scheme[0] = c | 0x20;
        }
        else
        {
            bad_scheme = c < 'a' || c > 'z';
        }
    }
    if(!bad_scheme)
    {
        for(int idx(1); idx < max; ++idx)
        {
            int const c(scheme[idx]);
            if(c >= 'A' && c <= 'Z')
            {
                // transform to lowercase (canonicalization)
                //
                scheme[idx] = c | 0x20;
            }
            else if((c < 'a' || c > 'z')
                 && (c < '0' || c > '9')
                 && c != '+'
                 && c != '-'
                 && c != '.')
            {
                bad_scheme = true;
                break;
            }
        }
    }

    // further we limit the length of the protocol to 20 characters
    //
    if(bad_scheme || scheme.length() > 20)
    {
        // invalid protocol, forget about the wrong one
        //
        // (i.e. an invalid protocol is not fatal at this point)
        //
        SNAP_LOG_ERROR
            << "unsupported scheme \""
            << scheme
            << "\" to block an IP address. We will use the default of \"http\"."
            << SNAP_LOG_SEND;
        scheme.clear();
    }

    if(scheme.empty())
    {
        // TODO: make this a fluid setting so the user can choose what the
        //       default scheme should be
        //
        scheme = "http";
    }

    // now that we have a valid scheme, make sure there is a
    // corresponding iplock configuration file
    //
    std::string filename("/etc/iplock/schemes/");
    filename += scheme;
    filename += ".conf";
    if(access(filename.c_str(), F_OK) != 0)
    {
        filename = "/etc/iplock/schemes/schemes.d/";
        // TODO: under the .d we need to test with numbers (??-<scheme>.conf)
        filename += scheme;
        filename += ".conf";
        if(access(filename.c_str(), F_OK) != 0)
        {
            if(scheme != "http")
            {
                // no message if http.conf does not exist; the iplock.conf
                // is the default and is to block HTTP so all good anyway
                //
                SNAP_LOG_WARNING
                    << "unsupported scheme \""
                    << scheme
                    << "\" to block an IP address. The iplock default will be used."
                    << SNAP_LOG_SEND;
            }
            return;
        }
    }

    f_scheme = scheme;
}


void block_info::set_block_limit(std::string const & period)
{
    snapdev::timespec_ex now(snapdev::timespec_ex::gettime());
    //std::int64_t const now(ed::communicator::get_current_date());
    if(!period.empty())
    {
        // IMPORTANT NOTE: We have a "5min" period for test purposes
        //                 but do NOT document it because we do not
        //                 want to actually offer to anyone; blocking
        //                 an IP address for just 5min is a waste of
        //                 time, block it at least for 1 hour, probably
        //                 for 1 day or more
        //
        if(period == "5min")
        {
            f_block_limit = now + snapdev::timespec_ex(5.0 * 60.0);
            return;
        }
        else if(period == "hour")
        {
            f_block_limit = now + snapdev::timespec_ex(60.0 * 60.0);
            return;
        }
        else if(period == "day")
        {
            f_block_limit = now + snapdev::timespec_ex(24.0 * 60.0 * 60.0);
            return;
        }
        else if(period == "week")
        {
            f_block_limit = now + snapdev::timespec_ex(7.0 * 24.0 * 60.0 * 60.0);
            return;
        }
        else if(period == "month")
        {
            f_block_limit = now + snapdev::timespec_ex(31.0 * 24.0 * 60.0 * 60.0);
            return;
        }
        else if(period == "year")
        {
            f_block_limit = now + snapdev::timespec_ex(366.0 * 24.0 * 60.0 * 60.0);
            return;
        }
        else if(period == "forever")
        {
            // 5 years is certainly very much like forever on the Internet!
            //
            f_block_limit = now + snapdev::timespec_ex(5.0 * 366.0 * 24.0 * 60.0 * 60.0);
            return;
        }
        else
        {
            // keep default of 1 day, but log an error
            //
            SNAP_LOG_ERROR
                << "unknown period \""
                << period
                << "\" to block an IP address. Revert to default of 1 day."
                << SNAP_LOG_SEND;
        }
    }

    // default is now + 1 day
    //
    f_block_limit = now + snapdev::timespec_ex(24.0 * 60.0 * 60.0);
}


/** \brief Received the another ban on the same IP, so extend the duration.
 *
 * This should not happen since a first ban should prevent further access
 * from that one user and thus further sight of the IP.
 *
 * Yet it can happen if the scheme does not block all the ports and the
 * new scheme is "all". Note that the 'this' object will have its scheme
 * set to "all" if the scheme of \p block is "all".
 *
 * As a side effect, this function adds all the counters from \p block
 * to 'this' counters.
 *
 * \param[in] block  The block being checked against 'this' block.
 */
void block_info::keep_longest(block_info const & block)
{
    if(block.f_scheme == "all"
    && f_scheme != "all")
    {
        // for obvious security reasons, we first block with the "all"
        // scheme then unblock with the specific scheme used by that
        // entry before the change
        //
        std::string const old_scheme(f_scheme);
        f_scheme = "all";
        iplock_block();
        f_scheme = old_scheme;
        iplock_unblock();
        f_scheme = "all";
    }

    if(f_block_limit < block.f_block_limit)
    {
        f_block_limit = block.f_block_limit;
    }

    f_ban_count += block.f_ban_count;
    f_packet_count += block.f_packet_count;
    f_byte_count += block.f_byte_count;
}


void block_info::set_ban_count(int64_t count)
{
    f_ban_count = count;
}


int64_t block_info::get_ban_count() const
{
    return f_ban_count;
}


/** \brief Get the total number of bans that this IP received.
 *
 * \note
 * This is mainly for documentation at this point as we are more likely
 * to get the counter directly from the database without the pending
 * value that may be in the running snapfirewalls. also the grand
 * total would include all the computers and not just the one running.
 */
//int64_t block_info::get_total_ban_count(libdbproxy::table::pointer_t firewall_table, std::string const & server_name) const
//{
//    // the total number of bans is the current counter plus the saved
//    // counter so we have to retrieve the saved counter first
//    //
//    libdbproxy::row::pointer_t row(firewall_table->getRow(std::string("ip::%1").arg(f_ip)));
//    std::string const ban_count_key(std::string("%1::ban_count").arg(server_name));
//    int64_t const saved_ban_count(row->getCell(ban_count_key)->getValue().safeInt64Value());
//
//    return f_ban_count + saved_ban_count;
//}


void block_info::set_packet_count(int64_t count)
{
    f_packet_count = count;
}


int64_t block_info::get_packet_count() const
{
    return f_packet_count;
}


void block_info::set_byte_count(int64_t count)
{
    f_byte_count = count;
}


int64_t block_info::get_byte_count() const
{
    return f_byte_count;
}


std::string block_info::canonicalized_uri() const
{
    // if no IP defined, return an empty string
    //
    if(f_ip.empty())
    {
        return f_ip;
    }

    // if no scheme is defined (maybe it was invalid) then just return
    // the IP
    //
    if(f_scheme.empty())
    {
        return f_ip;
    }

    // both scheme and IP are valid, return both
    //
    return f_scheme + "://" + f_ip;
}


std::string block_info::get_scheme() const
{
    return f_scheme;
}


std::string block_info::get_ip() const
{
    return f_ip;
}


snapdev::timespec_ex const & block_info::get_block_limit() const
{
    return f_block_limit;
}


/** \brief Check whether two block_info objects are considered equal.
 *
 * Note that the test compares the scheme and the ip. If either one of
 * the block_info objects has as the scheme "all", then it automatically
 * matches the other scheme.
 *
 * \param[in] rhs  The right hand side object to test.
 *
 * \return true if both info objects are considered equal.
 */
bool block_info::operator == (block_info const & rhs) const
{
    if(f_scheme == "all"
    || rhs.f_scheme == "all")
    {
        return f_ip == rhs.f_ip;
    }

    return f_scheme == rhs.f_scheme
        && f_ip == rhs.f_ip;
}


bool block_info::operator < (block_info const & rhs) const
{
    return f_block_limit < rhs.f_block_limit;
}


bool block_info::iplock_block()
{
    f_status = status_t::BLOCK_INFO_BANNED;
    return iplock("--block");
}


bool block_info::iplock_unblock()
{
    f_status = status_t::BLOCK_INFO_UNBANNED;
    return iplock("--unblock");
}


bool block_info::iplock(std::string const & cmd)
{
    if(!is_valid())
    {
        // the IP or period are missing
        //
        return false;
    }

    cppprocess::process::pointer_t iplock_process(std::make_shared<cppprocess::process>("block/unblock an IP address"));
    iplock_process->set_command("iplock");

    // whether we block or unblock the specified IP address
    //
    iplock_process->add_argument(cmd);
    iplock_process->add_argument(f_ip);

    // once we have support for configuration files and varying schemes
    //
    if(!f_scheme.empty())
    {
        iplock_process->add_argument("--scheme");
        iplock_process->add_argument(f_scheme);
    }

    // keep the stderr output withe stdout
    //
    iplock_process->add_argument("2>&1");

    cppprocess::io_capture_pipe::pointer_t output_pipe(std::make_shared<cppprocess::io_capture_pipe>());
    iplock_process->set_output_io(output_pipe);

    int const r(iplock_process->start());
    if(r != 0)
    {
        // Note: if the IP was not already defined, this command
        //       generates an error
        //
        int const e(errno);
        SNAP_LOG_ERROR
            << "an error occurred ("
            << r
            << ") trying to start \""
            << iplock_process->get_command_line()
            << "\", errno: "
            << e
            << " -- "
            << strerror(e)
            << SNAP_LOG_SEND;
        return false;
    }

    // get a signal on the child's death to log errors if such happens
    //
    ed::signal_child::pointer_t child_signal(ed::signal_child::get_instance());
    child_signal->add_listener(
              iplock_process->process_pid()
            , std::bind(&block_info::process_done, this, std::placeholders::_1, iplock_process));

    return true;
}


void block_info::process_done(
      ed::child_status status
    , cppprocess::process::pointer_t iplock_process)
{
    cppprocess::io_capture_pipe::pointer_t output_pipe(std::dynamic_pointer_cast<cppprocess::io_capture_pipe>(iplock_process->get_output_io()));
    if(status.is_signaled())
    {
        SNAP_LOG_ERROR
            << "iploack received a signal and died: "
            << status.terminate_signal()
            << " -- Console Output:\n"
            << output_pipe->get_output()
            << SNAP_LOG_SEND;
    }
    else if(status.is_exited())
    {
        if(status.exit_code() != 0)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "an error occurred running iplock: "
                << status.exit_code()
                << " -- Console Output:\n"
                << output_pipe->get_output()
                << SNAP_LOG_SEND;
        }
    }
}



} // namespace ipwall
// vim: ts=4 sw=4 et
