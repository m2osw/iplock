// Copyright (c) 2007-2022  Made to Order Software Corp.  All Rights Reserved
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
#include	<iplock/knock_ports.h>

#include	<iplock/exception.h>


// advgetopt
//
#include    <advgetopt/validator_integer.h>



namespace iplock
{



std::string protocol_port::protocol_name() const
{
    switch(f_protocol)
    {
    case IPPROTO_IP:
        return "ip";

    case IPPROTO_TCP:
        return "tcp";

    case IPPROTO_UDP:
        return "udp";

    default:
        throw iplock::logic_error("unknown protocol in protocol_port structure.");

    }
}


std::string parse_ports(
      std::string const & ports
    , protocol_port::vector_t & result)
{
    advgetopt::string_list_t list;
    advgetopt::split_string(ports, list, {","});
    for(auto const & l : list)
    {
        protocol_port pp;
        std::string port;
        std::string protocol;
        std::string::size_type const pos(l.find(':'));
        if(pos != std::string::npos)
        {
            if(pos == 0)
            {
                return "protocol cannot be empty";
            }
            protocol = l.substr(0, pos);
            port = l.substr(pos + 1);

            if(protocol == "tcp")
            {
                pp.f_protocol = IPPROTO_TCP;
            }
            else if(protocol == "udp")
            {
                pp.f_protocol = IPPROTO_UDP;
            }
            else
            {
                return "unsupported protocol (try with \"tcp:\" or \"udp:\".";
            }
        }
        else
        {
            port = l;
        }
        if(port.empty())
        {
            return "port cannot be empty";
        }
        std::int64_t p(0);
        advgetopt::validator_integer::convert_string(port, p);
        if(p < 0 || p > 65535)
        {
            return "port is out of range [0 .. 65535].";
        }
        pp.f_port = p;
        result.push_back(pp);
    }

    return std::string();
}


bool sorted_ports(protocol_port::vector_t const & ports)
{
    std::size_t const max(ports.size());
    if(max < 3)
    {
        return false;
    }

    bool up(ports[1].f_port > ports[0].f_port);
    for(std::size_t idx(2); idx < max; ++idx)
    {
        if(up != (ports[idx].f_port > ports[idx - 1].f_port))
        {
            return false;
        }
    }

    return true;
}



} // namespace iplock
// vim: ts=4 sw=4 et
