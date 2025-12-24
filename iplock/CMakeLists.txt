# Copyright (c) 2012-2025  Made to Order Software Corp.  All Rights Reserved
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

AtomicNames(names.an)

##
## iplock library
##
project(iplock)

# Put the version in the header file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/version.h
)

add_library(${PROJECT_NAME} SHARED
    block_ip.cpp
    knock_ports.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/names.cpp
    wait_on_firewall.cpp
    version.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${ADVGETOPT_INCLUDE_DIRS}
        ${COMMUNICATOR_INCLUDE_DIRS}
        ${CPPPROCESS_INCLUDE_DIRS}
        ${EVENTDISPATCHER_INCLUDE_DIRS}
        ${FLUIDSETTINGS_INCLUDE_DIRS}
        ${LIBADDR_INCLUDE_DIRS}
        ${LIBEXCEPT_INCLUDE_DIRS}
        ${SNAPLOGGER_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    ${ADVGETOPT_LIBRARIES}
    ${COMMUNICATOR_LIBRARIES}
    ${EVENTDISPATCHER_LIBRARIES}
    ${FLUIDSETTINGS_LIBRARIES}
    ${CPPPROCESS_LIBRARIES}
    ${LIBADDR_LIBRARIES}
    ${LIBEXCEPT_LIBRARIES}
    ${SNAPLOGGER_LIBRARIES}
)


set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION
        ${IPLOCK_VERSION_MAJOR}.${IPLOCK_VERSION_MINOR}

    SOVERSION
        ${IPLOCK_VERSION_MAJOR}
)

install(
    TARGETS
        ${PROJECT_NAME}

    RUNTIME DESTINATION
        bin

    LIBRARY DESTINATION
        lib

    ARCHIVE DESTINATION
        lib
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/

    DESTINATION
        include/iplock

    FILES_MATCHING PATTERN
        "*.h"
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/names.h
        ${CMAKE_CURRENT_BINARY_DIR}/version.h

    DESTINATION
        include/iplock
)

# vim: ts=4 sw=4 et
