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
#pragma once

/** \file
 * \brief ipload tool
 *
 * This tool loads configuration files in order to build the firewall
 * scripts and upload those script using iptables.
 */


//// self
////
//#include    "rule.h"
//
//#include    "utils.h"
//
//
//// iplock
////
//#include    <iplock/exception.h>
//
//
//// advgetopt
////
//#include    <advgetopt/validator_integer.h>
//
//
//// snaplogger
////
//#include    <snaplogger/message.h>


// C++
//
#include    <string>
#include    <vector>


//// C
////
//#include    <string.h>



constexpr int        TCP_SYN        = 0x0001;
constexpr int        TCP_ACK        = 0x0002;
constexpr int        TCP_FIN        = 0x0004;
constexpr int        TCP_RST        = 0x0008;
constexpr int        TCP_URG        = 0x0010;
constexpr int        TCP_PSH        = 0x0020;
constexpr int        TCP_UNDEFINED  = 0x8000;
constexpr int        TCP_ALL        = TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST | TCP_URG | TCP_PSH;
constexpr int        TCP_NONE       = 0;


class state_result
{
public:
    typedef std::vector<state_result>   vector_t;

    bool                is_valid() const;

    bool                get_tcp_negate() const;
    void                set_tcp_negate(bool negate);
    int                 get_tcp_mask() const;
    void                set_tcp_mask(int flags);
    int                 get_tcp_compare() const;
    void                set_tcp_compare(int flags);

    bool                get_established_related() const;
    void                set_established_related(bool established_related);

    std::string         get_icmp_type() const;
    void                set_icmp_type(std::string type);

    std::string         to_iptables_options() const;

    bool                operator == (state_result const & rhs) const;

private:
    mutable bool        f_valid = true;

    bool                f_established_related = false;

    bool                f_tcp_negate = false;
    int                 f_tcp_mask = TCP_UNDEFINED;
    int                 f_tcp_compare = TCP_UNDEFINED;

    std::string         f_icmp_type = std::string();
};



// vim: ts=4 sw=4 et
