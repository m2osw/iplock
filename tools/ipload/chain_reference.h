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
#pragma once

/** \file
 * \brief Defines the chain reference.
 *
 * This object links a set of chains to a table.
 *
 * The chain references handles a list of section references which include
 * a list of rules.
 *
 * We use a reference because the same chain may appear in different tables
 * when the rules for a given table/chain combo are unique to that combo.
 */


// self
//
#include    "chain.h"
#include    "section_reference.h"



class chain_reference
{
public:
    typedef std::shared_ptr<chain_reference>    pointer_t;
    typedef std::vector<pointer_t>              vector_t;
    typedef std::map<std::string, pointer_t>    map_t;

                                        chain_reference(
                                              chain::pointer_t c);

    bool                                is_valid() const;
    bool                                empty(std::string const & table_name) const;
    void                                add_section_reference(section_reference::pointer_t section_reference);
    bool                                add_rule(rule::pointer_t r);
    void                                compute_dependencies();

    section_reference::vector_t const & get_section_references() const;
    std::string const &                 get_name() const;
    std::string const &                 get_exact_name() const;
    bool                                get_condition() const;
    policy_t                            get_policy(std::string const & table_name) const;
    std::string                         get_policy_name(std::string const & table_name) const;
    type_t                              get_type(std::string const & table_name) const;
    std::string const &                 get_log() const;
    bool                                is_system_chain() const;

private:
    chain::pointer_t                    f_chain = chain::pointer_t();
    section_reference::vector_t         f_section_references = section_reference::vector_t();
    section_reference::pointer_t        f_default_section_references = section_reference::pointer_t();
    section_reference::map_t            f_section_references_by_name = section_reference::map_t();
    bool                                f_valid = true;
};



// vim: ts=4 sw=4 et
