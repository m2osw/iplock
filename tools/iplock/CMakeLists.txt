# Copyright (c) 2014-2024  Made to Order Software Corp.  All Rights Reserved
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

project(iplock-tool)

add_executable(${PROJECT_NAME}
    block.cpp
    block_or_unblock.cpp
    command.cpp
    controller.cpp
    count.cpp
    flush.cpp
    list.cpp
    list_allowed_sets.cpp
    main.cpp
    unblock.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}
        ${ADVGETOPT_INCLUDE_DIRS}
        ${CPPPROCESS_INCLUDE_DIRS}
        ${EVENTDISPATCHER_INCLUDE_DIRS}
        ${LIBADDR_INCLUDE_DIRS}
        ${LIBEXCEPT_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    iplock
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME iplock
)

install(
    TARGETS
        ${PROJECT_NAME}

    RUNTIME DESTINATION
        sbin
)


# vim: ts=4 sw=4 et
