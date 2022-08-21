# - Find IPLock
#
# IPLOCK_FOUND        - System has IPLock
# IPLOCK_INCLUDE_DIRS - The IPLock include directories
# IPLOCK_LIBRARIES    - The libraries needed to use IPLock
# IPLOCK_DEFINITIONS  - Compiler switches required for using IPLock
#
# License:
#
# Copyright (c) 2011-2022  Made to Order Software Corp.  All Rights Reserved
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

find_path(
    IPLOCK_INCLUDE_DIR
        iplock/version.h

    PATHS
        ENV IPLOCK_INCLUDE_DIR
)

find_library(
    IPLOCK_LIBRARY
        iplock

    PATHS
        ${IPLOCK_LIBRARY_DIR}
        ENV IPLOCK_LIBRARY
)

mark_as_advanced(
    IPLOCK_INCLUDE_DIR
    IPLOCK_LIBRARY
)

set(IPLOCK_INCLUDE_DIRS ${IPLOCK_INCLUDE_DIR})
set(IPLOCK_LIBRARIES    ${IPLOCK_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    IPLock
    REQUIRED_VARS
        IPLOCK_INCLUDE_DIR
        IPLOCK_LIBRARY
)

# vim: ts=4 sw=4 et
