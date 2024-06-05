// Copyright (c) 2007-2024  Made to Order Software Corp.  All Rights Reserved
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

// C++
//
#include    <string>
#include    <vector>

// C
//
#include    <netinet/in.h>



namespace iplock
{



struct protocol_port
{
    typedef std::vector<protocol_port>      vector_t;

    std::string     protocol_name() const;

    int             f_protocol = IPPROTO_IP;
    int             f_port = 0;
    int             f_duration = 10;    // in seconds
};

std::string         parse_ports(
                              std::string const & ports
                            , protocol_port::vector_t & result);

bool                sorted_ports(protocol_port::vector_t const & ports);
bool                unique_ports(protocol_port::vector_t const & ports);


} // namespace iplock
// vim: ts=4 sw=4 et
