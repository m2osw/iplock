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
 * \brief Defines the section reference.
 *
 * This object links a set of rules to a section.
 *
 * The section references are added to chains.
 */


// self
//
#include    "section.h"
#include    "rule.h"



class section_reference
{
public:
    typedef std::shared_ptr<section_reference>  pointer_t;
    typedef std::vector<pointer_t>              vector_t;
    typedef std::map<std::string, pointer_t>    map_t;

                                        section_reference(
                                              section::pointer_t s);

    bool                                is_valid() const;

    void                                add_rule(rule::pointer_t r);
    rule::vector_t const &              get_rules() const;

    std::string  const &                get_name() const;
    advgetopt::string_list_t const &    get_before() const;
    advgetopt::string_list_t const &    get_after() const;
    bool                                get_default() const;

private:
    section::pointer_t                  f_section = section::pointer_t();
    rule::vector_t                      f_rules = rule::vector_t();
    bool                                f_valid = true;
};



// vim: ts=4 sw=4 et
