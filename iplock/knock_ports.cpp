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


// self
//
#include	<iplock/knock_ports.h>

#include	<iplock/exception.h>


// advgetopt
//
#include    <advgetopt/validator_duration.h>
#include    <advgetopt/validator_integer.h>


// C++
//
#include    <cmath>



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


/** \brief Parse a list of port with protocol and duration.
 *
 * This function reads a list of:
 *
 * \li protocol -- a name such as tcp followed by a colon; it is optional; if
 * not specified, use TCP; at this time we support "tcp" and "udp"
 * \li port -- a number from 0 to 65535; this is mandatory; there is no default
 * \li duration -- after a slash, you can indicate a duration; the default is
 * 10 seconds if not specified; you can include a duration unit such as 's'
 * for seconds and 'm' for minutes; you probably don't want to use a larger
 * duration ('h' for hours, 'd' for days...)
 *
 * The syntax looks like this:
 *
 * \code
 *     [<protocol>:]<port>[/<duration>[<unit>]]
 * \endcode
 *
 * The duration is in seconds by default (when no unit is specified).
 *
 * Multiple ports can be specified by separating each one by a comma. The
 * order is kept since it indicates the order in which the knocking has to
 * be porformed.
 *
 * The amount of time specified along the first port determines the amount
 * of time the client has to knock the next port. The duration on the last
 * port indicates the time the service port in link with this port knocking
 * is going to be accessible after a successful knock-knock.
 *
 * \param[in] ports  A string with the list of protocols, ports, durations.
 * \param[out] result  The resulting vector of protocols and ports.
 *
 * \return An empty string on success, an error message otherwise.
 */
std::string parse_ports(
      std::string const & ports
    , protocol_port::vector_t & result)
{
    result.clear();

    advgetopt::string_list_t list;
    advgetopt::split_string(ports, list, {","});
    for(auto & l : list)
    {
        protocol_port pp;
        std::string port;
        std::string protocol;
        std::string::size_type const slash(l.find('/'));
        if(slash != std::string::npos)
        {
            double duration;
            if(!advgetopt::validator_duration::convert_string(
                      l.substr(slash + 1)
                    , advgetopt::validator_duration::VALIDATOR_DURATION_DEFAULT_FLAGS
                    , duration))
            {
                return "duration is invalid";
            }

            // keep it at a minimum of 1 second
            //
            pp.f_duration = std::max(1, static_cast<int>(rint(duration)));

            l = l.substr(0, slash);
        }
        std::string::size_type const colon(l.find(':'));
        if(colon != std::string::npos)
        {
            if(colon == 0)
            {
                return "protocol cannot be empty";
            }
            protocol = l.substr(0, colon);
            port = l.substr(colon + 1, slash - colon - 1);

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


bool unique_ports(protocol_port::vector_t const & ports)
{
    std::set<int> s;
    for(auto const & pp : ports)
    {
        s.insert(pp.f_port);
    }
    return s.size() == ports.size();
}



} // namespace iplock
// vim: ts=4 sw=4 et
