# Copyright (c) 2025-2026  Made to Order Software Corp.  All Rights Reserved
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

# Plugin names must use underscores
project(communicatord_wait_on_firewall)

add_library(${PROJECT_NAME} SHARED
    wait_on_firewall.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${ADVGETOPT_INCLUDE_DIRS}
        ${COMMUNICATOR_INCLUDE_DIRS}
        ${CPPPROCESS_INCLUDE_DIRS}
        ${EVENTDISPATCHER_INCLUDE_DIRS}
        ${SERVERPLUGINS_INCLUDE_DIRS}
        ${SNAPDEV_INCLUDE_DIRS}
        ${SNAPLOGGER_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        iplock
        #${ADVGETOPT_LIBRARIES}
        #${COMMUNICATOR_LIBRARIES}
        #${EVENTDISPATCHER_LIBRARIES}
        #${FLUIDSETTINGS_LIBRARIES}
        #${CPPPROCESS_LIBRARIES}
        #${LIBADDR_LIBRARIES}
        #${LIBEXCEPT_LIBRARIES}
        #${SNAPLOGGER_LIBRARIES}
)

install(
    TARGETS
        ${PROJECT_NAME}

    LIBRARY DESTINATION
        ${COMMUNICATOR_PLUGINS_INSTALL_DIR}
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/

    DESTINATION
        include/communicator/plugins

    FILES_MATCHING PATTERN
        "*.h"
)

# vim: ts=4 sw=4 et
