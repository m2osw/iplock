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



enum class recent_t
{
    RECENT_NONE,

    RECENT_SET,
    RECENT_CHECK,
    RECENT_UPDATE,
    RECENT_REMOVE,
};




class recent_parser
{
public:
    typedef std::vector<recent_parser>  vector_t;

                                    recent_parser();

    bool                            parse(std::string const & value);

    bool                            get_valid() const;
    bool                            get_negate() const;
    bool                            get_destination() const;
    bool                            get_reap() const;
    bool                            get_rttl() const;
    recent_t                        get_recent() const;
    std::string const &             get_name() const;
    std::int64_t                    get_ttl() const;
    std::int64_t                    get_hitcount() const;
    std::int64_t                    get_mask() const;

private:
    enum class token_t
    {
        TOKEN_EOF = -1,

        TOKEN_NEGATE,
        TOKEN_SLASH,
        TOKEN_INTEGER,
        TOKEN_IDENTIFIER,
        TOKEN_ADDRESS,
    };

    int                             getc();
    void                            ungetc(int c);
    void                            next_token();

    std::string                     f_expression = std::string();

    std::size_t                     f_in = 0;
    char                            f_unget = '\0';
    token_t                         f_last_token = token_t::TOKEN_EOF;
    std::string                     f_value = std::string();

    bool                            f_valid = true;
    bool                            f_negate = false;
    bool                            f_destination = false; // use destination instead of source
    bool                            f_reap = false;
    bool                            f_rttl = false;
    recent_t                        f_recent = recent_t::RECENT_NONE;
    std::string                     f_name = std::string();
    std::int64_t                    f_ttl = 0;
    std::int64_t                    f_hitcount = 0;
    std::int64_t                    f_mask = -1;
};



// vim: ts=4 sw=4 et
