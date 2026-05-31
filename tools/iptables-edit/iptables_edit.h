// Copyright (c) 2026  Made to Order Software Corp.  All Rights Reserved
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


// self
//
//#include    "block_info.h"
//#include    "database_timer.h"
//#include    "interrupt.h"
//#include    "messenger.h"
//#include    "wakeup_timer.h"


// advgetopt
//
#include    <advgetopt/advgetopt.h>


// snapdev
//
#include    <snapdev/lockfile.h>



namespace iptables_edit
{



class editor
{
public:
    typedef std::shared_ptr<editor>      pointer_t;

                                editor(int argc, char * argv[]);
                                editor(editor const &) = delete;
                                ~editor();

    editor &                    operator = (editor const &) = delete;

    int                         run();

private:
    int                         execute_commands();
    int                         check_options();
    int                         must_be_root();
    int                         must_be_a_tty();
    int                         determine_internet_protocol();
    int                         create_temp_dir();
    int                         obtain_lock();
    static bool                 verify_table_name(std::string const & table_name);
    int                         get_current_firewall();
    int                         get_firewall(std::string const & filename, std::string const & backup = std::string());
    int                         edit_firewall();
    int                         file_changed(std::string const & filename, std::string const & backup);
    int                         compare_firewall();
    int                         save_firewall();
    int                         restore_firewall(std::string const & rules_filename);

    advgetopt::getopt           f_opts;
    bool                        f_ipv6 = false; // IPv4 by default
    std::string                 f_tmpdir = std::string();
    std::string                 f_filename = std::string();
    std::string                 f_backup = std::string();
    snapdev::lockfile::pointer_t
                                f_lock = snapdev::lockfile::pointer_t();
    double                      f_timeout = 5.0; // 5s by default
    std::string                 f_differing_line1 = std::string();
    std::string                 f_differing_line2 = std::string();
};



} // namespace iptables_edit
// vim: ts=4 sw=4 et
