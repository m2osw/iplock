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

project(iplock_configuration)

# Logger files
install(
    FILES
        logger/ipwall.conf

    DESTINATION
        ${SNAPLOGGER_SHARE_CONF_DIR}
)

# ipwall definitions for fluid-settings
install(
    FILES
        ipwall.ini

    DESTINATION
        ${FLUIDSETTINGS_DEFINITIONS_INSTALL_DIR}
)

# Define ipwall as a Communicator Service
install(
    FILES
        ipwall.service

    DESTINATION
        ${COMMUNICATOR_SERVICES_INSTALL_DIR}
)


# vim: ts=4 sw=4 et
