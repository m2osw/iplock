// Copyright (c) 2022-2024  Made to Order Software Corp.  All Rights Reserved
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
#include    "table.h"

#include    "utils.h"


// iplock
//
#include    <iplock/exception.h>


// snaplogger
//
#include    <snaplogger/message.h>


// C
//
#include    <string.h>


// last include
//
#include    <snapdev/poison.h>







namespace
{



std::set<std::string> g_valid_tables = {
    "filter",
    "nat",
    "mangle",
    "raw",
    "security",
};



} // no name namespace



/** \brief Initialize the ipchain object.
 *
 * This function saves the name of the iptable chain in this object.
 *
 * \param[in] it  The iterator, on entry it points to the chain name.
 * \param[in] config_params  The complete list of parameters.
 * \param[in] variables  A pointer to a set of variables.
 */
table::table(
          advgetopt::conf_file::parameters_t::iterator & it
        , advgetopt::conf_file::parameters_t const & config_params
        , advgetopt::variables::pointer_t variables)
{
    // parse all the parameters we can find
    //
    advgetopt::string_list_t name_list;
    advgetopt::split_string(it->first, name_list, {"::"});
    if(name_list.size() != 3)
    {
        throw iplock::logic_error("the table name is expected to be exactly two names: \"table::<name>::<parameter>\"");
    }

    // this is the name of the chain
    //
    // it is used by the ipload tool to know in which iptables chain to save
    // rules that reference this chain
    //
    f_name = name_list[1];

    if(g_valid_tables.find(f_name) == g_valid_tables.end())
    {
        SNAP_LOG_ERROR
            << "unknown table \""
            << f_name
            << "\". Expected one of: "
            << snapdev::join_strings(g_valid_tables, ", ")
            << SNAP_LOG_SEND;
        f_valid = false;
    }

    std::string const complete_namespace("table::" + f_name + "::");
    for(; it != config_params.end(); ++it)
    {
        if(strncmp(it->first.c_str(), complete_namespace.c_str(), complete_namespace.length()) != 0)
        {
            // we've exhausted the list
            //
            break;
        }

        std::string value(variables->process_value(it->second));

        std::string_view const param_name(it->first.c_str() + complete_namespace.length(), it->first.length() - complete_namespace.length());
        bool found(true);
        switch(param_name[0])
        {
        case 'd':
            if(param_name == "description")
            {
                f_description = value;
            }
            else
            {
                found = false;
            }
            break;

        default:
            found = false;
            break;

        }
        if(!found)
        {
            SNAP_LOG_RECOVERABLE_ERROR
                << "unknown table parameter \""
                << it->first
                << "\"."
                << SNAP_LOG_SEND;
        }
    }
}


bool table::is_valid() const
{
    return f_valid;
}


bool table::empty() const
{
    for(auto const & c : f_chain_references)
    {
        if(!c.second->empty(f_name))
        {
            return false;
        }
    }
    return true;
}


std::string table::get_name() const
{
    return f_name;
}


std::string table::get_description() const
{
    return f_description;
}


void table::add_chain_reference(chain_reference::pointer_t c)
{
    if(f_chain_references.find(c->get_name()) != f_chain_references.end())
    {
        throw iplock::logic_error(
                  "table::add_chain_reference() called with a duplicate ("
                + c->get_name()
                + ").");
    }

    f_chain_references[c->get_name()] = c;
}


chain_reference::pointer_t table::get_chain_reference(std::string const & name) const
{
    auto it(f_chain_references.find(name));
    if(it == f_chain_references.end())
    {
        return chain_reference::pointer_t();
    }
    return it->second;
}


chain_reference::map_t const & table::get_chain_references() const
{
    return f_chain_references;
}



// vim: ts=4 sw=4 et
