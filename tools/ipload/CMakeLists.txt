# Copyright (c) 2012-2022  Made to Order Software Corp.  All Rights Reserved
#
# https://snapwebsites.org/project/iplock
# contact@m2osw.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

AsRc(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/basic_ipv4.cpp

    NAME
        basic_ipv4

    NAMESPACE
        tools_ipload

    INPUTS
        basic_ipv4.rules
)

AsRc(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/basic_ipv6.cpp

    NAME
        basic_ipv6

    NAMESPACE
        tools_ipload

    INPUTS
        basic_ipv6.rules
)

AsRc(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/default_firewall.cpp

    NAME
        default_firewall

    NAMESPACE
        tools_ipload

    INPUTS
        default_firewall.conf
)

AsRc(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/clear_firewall.cpp

    NAME
        clear_firewall

    NAMESPACE
        tools_ipload

    INPUTS
        clear_firewall.sh
)

project(ipload)

add_executable(${PROJECT_NAME}
    chain.cpp
    ipload.cpp
    main.cpp
    rule.cpp
    section.cpp
    section_reference.cpp
    state_parser.cpp
    state_result.cpp
    table.cpp
    utils.cpp

    ${CMAKE_CURRENT_BINARY_DIR}/basic_ipv4.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/basic_ipv6.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/default_firewall.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/clear_firewall.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}
        ${ADVGETOPT_INCLUDE_DIRS}
        ${BOOST_INCLUDE_DIRS}
        ${LIBADDR_INCLUDE_DIRS}
        ${LIBEXCEPT_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    iplock
    readline
)

install(
    TARGETS
        ${PROJECT_NAME}

    RUNTIME DESTINATION
        sbin
)


# vim: ts=4 sw=4 et
