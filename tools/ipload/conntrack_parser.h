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

// advgetopt
//
#include    <advgetopt/utils.h>


// libaddr
//
#include    <libaddr/addr_parser.h>



enum class negate_t
{
    NEGATE_ORIGINAL_SRC_ADDRESS = 0,
    NEGATE_ORIGINAL_DST_ADDRESS = 1,
    NEGATE_REPLY_SRC_ADDRESS = 2,
    NEGATE_REPLY_DST_ADDRESS = 3,

    NEGATE_ORIGINAL_SRC_PORTS = 4,
    NEGATE_ORIGINAL_DST_PORTS = 5,
    NEGATE_REPLY_SRC_PORTS = 6,
    NEGATE_REPLY_DST_PORTS = 7,

    NEGATE_STATES,
    NEGATE_PROTOCOL,
    NEGATE_STATUSES,
    NEGATE_EXPIRE,

    NEGATE_max
};

enum class direction_t
{
    DIRECTION_BOTH,
    DIRECTION_ORIGINAL,
    DIRECTION_REPLY,
};

class conntrack_parser
{
public:
    typedef std::shared_ptr<conntrack_parser>   pointer_t;
    typedef std::vector<pointer_t>              vector_t;

                                    conntrack_parser();
                                    conntrack_parser(conntrack_parser const & rhs) = delete;
    conntrack_parser &              operator = (conntrack_parser const & rhs) = delete;

    bool                            parse(std::string const & value);

    bool                            get_negate(negate_t idx) const;
    advgetopt::string_set_t const & get_states() const;
    advgetopt::string_set_t const & get_statuses() const;
    int                             get_protocol() const;
    addr::addr const &              get_address(int index) const;
    int                             get_start_port(int index) const;
    int                             get_end_port(int index) const;
    std::int64_t                    get_expire_start_time() const;
    std::int64_t                    get_expire_end_time() const;
    direction_t                     get_direction() const;

private:
    enum class token_t
    {
        TOKEN_EOF = -1,

        // used to index the address / port arrays
        //
        TOKEN_ORIGINAL_SOURCE = 0,
        TOKEN_ORIGINAL_DESTINATION = 1,
        TOKEN_REPLY_SOURCE = 2,
        TOKEN_REPLY_DESTINATION = 3,

        TOKEN_NEGATE,
        TOKEN_OPEN_PARENTHESIS,
        TOKEN_CLOSE_PARENTHESIS,
        TOKEN_COLON,
        TOKEN_COMMA,
        TOKEN_SLASH,
        TOKEN_INTEGER,
        TOKEN_IDENTIFIER,
        TOKEN_ADDRESS,
    };

    int                         getc();
    void                        ungetc(int c);
    void                        next_token();
    void                        parse_address_port(bool negate);
    void                        parse_time(bool negate);
    void                        parse_state_status_protocol(bool negate);

    std::string                 f_expression = std::string();

    char const *                f_in = nullptr;
    char                        f_unget = '\0';
    token_t                     f_last_token = token_t::TOKEN_EOF;
    std::string                 f_value = std::string();
    std::int64_t                f_integer = 0;

    bool                        f_valid = true;
    bool                        f_negate[static_cast<int>(negate_t::NEGATE_max)] = {};
    advgetopt::string_set_t     f_states = advgetopt::string_set_t();
    int                         f_protocol = -1;
    addr::addr                  f_address[4] = {};
    int                         f_start_port[4] = { -1, -1, -1, -1 };
    int                         f_end_port[4] = { -1, -1, -1, -1 };
    advgetopt::string_set_t     f_statuses = advgetopt::string_set_t();
    std::int64_t                f_expire_start_time = -1;
    std::int64_t                f_expire_end_time = -1;
    direction_t                 f_direction = direction_t::DIRECTION_BOTH;
};



// vim: ts=4 sw=4 et
