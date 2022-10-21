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


// self
//
#include    "state_result.h"



class state_parser
{
public:
                        state_parser(char const * in);
                        state_parser(state_parser const & rhs) = delete;
    state_parser        operator = (state_parser const & rhs) = delete;

    state_result::vector_t
                        get_results() const;
    bool                parse();

private:
    enum token_t
    {
        TOKEN_EOF = -1,

        TOKEN_NEGATE = '!',
        TOKEN_OPEN_PARENTHESIS = '(',
        TOKEN_CLOSE_PARENTHESIS = ')',
        TOKEN_OR = '|',
        TOKEN_COMMA = ',',
        TOKEN_EQUAL = '=',
        TOKEN_DASH = '-',

        TOKEN_NEW = 1000,
        TOKEN_OLD,
        TOKEN_INVALID,
        TOKEN_ESTABLISHED,
        TOKEN_RELATED,
        TOKEN_TCPMSS,
        TOKEN_INTEGER,
        TOKEN_ALL,
        TOKEN_ANY,
        TOKEN_TIMESTAMP_REQUEST,
        TOKEN_TIMESTAMP_REPLY,
        TOKEN_NONE,
        TOKEN_SYN,
        TOKEN_ACK,
        TOKEN_FIN,
        TOKEN_RST,
        TOKEN_URG,
        TOKEN_PSH,
    };

    int                 getc();
    void                unget_last();
    void                next_token();
    void                start();
    void                negate();
    void                mask_compare();
    void                flag_list();
    void                flag_name();

    bool                f_valid = true;
    char const *        f_in = nullptr;
    token_t             f_last_token = TOKEN_EOF;
    std::int64_t        f_integer = 0;

    state_result        f_result = state_result();
    state_result::vector_t
                        f_result_list = state_result::vector_t();
    bool                f_standalone_flag_name = false;
    bool                f_special_flag_name = false;
};



// vim: ts=4 sw=4 et
