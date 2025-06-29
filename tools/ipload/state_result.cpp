// Copyright (c) 2022-2025  Made to Order Software Corp.  All Rights Reserved
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
#include    "state_result.h"


// iplock
//
#include    <iplock/exception.h>


// snaplogger
//
#include    <snaplogger/message.h>


// last include
//
#include    <snapdev/poison.h>



namespace
{



struct flag_name_t
{
    int             f_flag = 0;
    char const *    f_name = nullptr;
};


flag_name_t g_flag_to_name[6] = {
    { TCP_SYN, "SYN" },
    { TCP_ACK, "ACK" },
    { TCP_FIN, "FIN" },
    { TCP_RST, "RST" },
    { TCP_URG, "URG" },
    { TCP_PSH, "PSH" },
};


std::string tcp_flags_to_string(int flags)
{
    // handle two special cases first
    //
    if(flags == TCP_ALL)
    {
        return "ALL";
    }
    if(flags == TCP_NONE)
    {
        return "NONE";
    }

    // user defined set of flags
    //
    std::string result;
    for(std::size_t idx(0); idx < std::size(g_flag_to_name); ++idx)
    {
        if((flags & g_flag_to_name[idx].f_flag) != 0)
        {
            if(!result.empty())
            {
                result += ',';
            }
            result += g_flag_to_name[idx].f_name;
        }
    }

    if(result.empty())
    {
        throw iplock::logic_error("no flags were transformed?");
    }

    return result;
}



} // no name namespace



bool state_result::is_valid() const
{
    if(!f_valid)
    {
        // errors were already emitted
        //
        return false;
    }

    if((f_tcp_compare & ~f_tcp_mask) != 0)
    {
        f_valid = false;
        SNAP_LOG_ERROR
            << "you cannot have TCP compare flags (0x"
            << std::hex << f_tcp_compare
            << ") that are not in the mask (0x"
            << f_tcp_mask
            << ") -- i.e. it would never match anything."
            << SNAP_LOG_SEND;
    }

    return f_valid;
}


bool state_result::get_invalid() const
{
    return f_invalid;
}


void state_result::set_invalid(bool invalid)
{
    f_invalid = invalid;
}


bool state_result::get_tcp_negate() const
{
    return f_tcp_negate;
}


void state_result::set_tcp_negate(bool negate)
{
    f_tcp_negate = negate;
}


int state_result::get_tcp_mask() const
{
    return f_tcp_mask;
}


void state_result::set_tcp_mask(int flags)
{
    f_tcp_mask = flags;
}


int state_result::get_tcp_compare() const
{
    return f_tcp_compare;
}


void state_result::set_tcp_compare(int flags)
{
    f_tcp_compare = flags;
}


int state_result::get_tcpmss_negate() const
{
    return f_tcpmss_negate;
}


void state_result::set_tcpmss_negate(bool negate)
{
    f_tcpmss_negate = negate;
}


int state_result::get_tcpmss_min() const
{
    return f_tcpmss_min;
}


void state_result::set_tcpmss_min(int mss)
{
    f_tcpmss_min = mss;
}


int state_result::get_tcpmss_max() const
{
    return f_tcpmss_max;
}


void state_result::set_tcpmss_max(int mss)
{
    f_tcpmss_max = mss;
}


bool state_result::get_established_related() const
{
    return f_established_related;
}


void state_result::set_established_related(bool established_related)
{
    f_established_related = established_related;
}


std::string state_result::get_icmp_type() const
{
    return f_icmp_type;
}


void state_result::set_icmp_type(std::string type)
{
    f_icmp_type = type;
}


std::string state_result::to_iptables_options(
      std::string const & protocol
    , bool for_ipv6) const
{
    if(!f_valid)
    {
        return std::string();
    }

    // this is not correct, these can be used along TCP flags so we need
    // to be able to go through both--also at the moment this is included
    // early in the rule
    //if(f_established_related)
    //{
    //    return " -m state --state ESTABLISHED,RELATED";
    //}

    if(protocol == "icmp")
    {
        if(!for_ipv6
        && !f_icmp_type.empty())
        {
            return " -m icmp --icmp-type " + f_icmp_type;
        }
        return std::string();
    }
    if(protocol == "icmpv6")
    {
        if(for_ipv6
        && !f_icmp_type.empty()
        && f_icmp_type != "any")    // the name "any" is not supported by IPv6 -- not having a type is equal to any
        {
            return " -m icmpv6 --icmpv6-type " + f_icmp_type;
        }
        return std::string();
    }

    if(protocol == "tcp")
    {
        if(f_tcp_mask == TCP_SYN | TCP_RST | TCP_ACK | TCP_FIN
        && f_tcp_compare == TCP_SYN)
        {
            if(f_tcp_negate)
            {
                return " -m tcp ! --syn";
            }
            return " -m tcp --syn";
        }

        std::string result;
        if(f_tcp_compare != TCP_UNDEFINED
        && f_tcp_mask != TCP_UNDEFINED)
        {
            // not a specific TCP flags so output the whole thing
            //
            result += " -m tcp";
            if(f_tcp_negate)
            {
                result += " !";
            }
            result += " --tcp-flags ";
            result += tcp_flags_to_string(f_tcp_mask);
            result += ' ';
            result += tcp_flags_to_string(f_tcp_compare);
        }

        return result;
    }

    if(protocol == "udp")
    {
        if(f_tcp_mask == TCP_SYN | TCP_RST | TCP_ACK | TCP_FIN
        && f_tcp_compare == TCP_SYN)
        {
            if(f_tcp_negate)
            {
                return " -m state ! --state NEW";
            }
            return " -m state --state NEW";
        }
    }

    return std::string();
}


bool state_result::operator == (state_result const & rhs) const
{
    return f_established_related == rhs.f_established_related
        && f_tcp_negate          == rhs.f_tcp_negate
        && f_tcp_mask            == rhs.f_tcp_mask
        && f_tcp_compare         == rhs.f_tcp_compare;
}



// vim: ts=4 sw=4 et
