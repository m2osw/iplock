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

cmake_minimum_required(VERSION 3.10.2)

enable_language(CXX)

project(iplock_project)

find_package(AdvGetOpt        REQUIRED)
find_package(Boost            REQUIRED COMPONENTS filesystem system)
find_package(Communicatord    REQUIRED)
find_package(CppProcess       REQUIRED)
find_package(EventDispatcher  REQUIRED)
find_package(FluidSettings    REQUIRED)
find_package(LibAddr          REQUIRED)
find_package(LibExcept        REQUIRED)
find_package(SnapCMakeModules REQUIRED)
find_package(SnapDev          REQUIRED)
find_package(SnapLogger       REQUIRED)

SnapGetVersion(IPLOCK ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(
    ${PROJECT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Sub-directories
add_subdirectory(cmake)         # cmake files
add_subdirectory(iplock)        # library
add_subdirectory(tools)         # tools and daemon
add_subdirectory(doc)           # documentation
add_subdirectory(tests)         # tests of library


# vim: ts=4 sw=4 et
