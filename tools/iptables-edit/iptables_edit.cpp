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


// self
//
#include    "iptables_edit.h"


// iplock
//
#include    <iplock/version.h>


// snaplogger
//
#include    <snaplogger/message.h>
#include    <snaplogger/options.h>


// snapdev
//
#include    <snapdev/mkdir_p.h>
#include    <snapdev/pathinfo.h>
#include    <snapdev/stringize.h>
#include    <snapdev/timed_getchar.h>


// advgetopt
//
#include    <advgetopt/exception.h>
#include    <advgetopt/validator_duration.h>


// last include
//
#include    <snapdev/poison.h>



namespace iptables_edit
{
namespace
{


class lexer
{
public:
    lexer(std::string const & filename)
        : f_filename(filename)
        , f_input(f_filename)
    {
        if(!f_input.is_open())
        {
            SNAP_LOG_ERROR
                << "could not open file \""
                << f_filename
                << "\" for reading."
                << SNAP_LOG_SEND;
        }
    }

    std::string next()
    {
        if(!f_input.is_open())
        {
            return std::string();
        }

        for(;;)
        {
            std::string line;
            if(!std::getline(f_input, line))
            {
                return std::string();
            }

            // ignore empty lines
            //
            if(!line.empty())
            {
                // ignore comments
                //
                if(line[0] != '#')
                {
                    return line;
                }
            }
        }
    }

private:
    std::string         f_filename = std::string();
    std::ifstream       f_input = std::ifstream();
};


} // no name namespace



/** \class editor
 * \brief Tool used to edit the current iptables in a visual editor.
 *
 * This class handles all the necessary step to save the existing iptables,
 * allow the user to edit the rules, and finally "restore" the rules back
 * in the kernel with all your changes.
 *
 * The process requires you to be root. If not root, the tool fails early.
 *
 * The process makes two copies of the iptables rules. If by the time you
 * try to save the rules the tables already changed, the process fails
 * (i.e. various tools such as libvirt or drupal make dynamic changes to
 * your firewall, we also offer ipwall which can add/remove rules along
 * the way).
 *
 * The restore command uses the `iptables-apply` tool which means you get
 * a chance to not blow up your remote server if the change breaks your
 * SSH connection. This means your changes are thrown away after `timeout`
 * seconds and your connection can be restored.
 */



/** \brief Command line options.
 *
 * This table includes the iptables-edit specific options.
 */
advgetopt::option const g_options[] =
{
    // COMMANDS
    //
    advgetopt::define_option(
          advgetopt::Name("iptables-versions")
        , advgetopt::Flags(advgetopt::standalone_command_flags<
              advgetopt::GETOPT_FLAG_GROUP_COMMANDS>())
        , advgetopt::Help("Show the versions of the various tools used by iptables-edit.")
    ),

    // OPTIONS
    //
    advgetopt::define_option(
          advgetopt::Name("editor")
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS
            , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Name or full path to the visual editor to used. If not specified, use `sensible-editor`.")
    ),
    advgetopt::define_option(
          advgetopt::Name("ip")
        , advgetopt::ShortName('4')
        , advgetopt::Flags(advgetopt::standalone_all_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::Help("Edit the IPv4 table (this is the default).")
    ),
    advgetopt::define_option(
          advgetopt::Name("ip4")
        , advgetopt::Flags(advgetopt::standalone_all_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::Alias("ip")
    ),
    advgetopt::define_option(
          advgetopt::Name("ip6")
        , advgetopt::ShortName('6')
        , advgetopt::Flags(advgetopt::standalone_all_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS>())
        , advgetopt::Help("Edit the IPv6 table (this is the default).")
    ),
    advgetopt::define_option(
          advgetopt::Name("table")
        , advgetopt::ShortName('t')
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS
            , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::Help("Name of the specific table to edit.")
    ),
    advgetopt::define_option(
          advgetopt::Name("timeout")
        , advgetopt::Flags(advgetopt::all_flags<
              advgetopt::GETOPT_FLAG_GROUP_OPTIONS
            , advgetopt::GETOPT_FLAG_REQUIRED>())
        , advgetopt::DefaultValue("5s")
        , advgetopt::Validator("duration")
        , advgetopt::Help("Delay before restoring the previous version of the firewall.")
    ),
    advgetopt::end_options()
};


advgetopt::group_description const g_group_descriptions[] =
{
    advgetopt::define_group(
          advgetopt::GroupNumber(advgetopt::GETOPT_FLAG_GROUP_COMMANDS)
        , advgetopt::GroupName("command")
        , advgetopt::GroupDescription("Commands:")
    ),
    advgetopt::define_group(
          advgetopt::GroupNumber(advgetopt::GETOPT_FLAG_GROUP_OPTIONS)
        , advgetopt::GroupName("option")
        , advgetopt::GroupDescription("Options:")
    ),
    advgetopt::end_groups()
};


advgetopt::options_environment const g_options_environment =
{
    .f_project_name = "iptables-edit",
    .f_group_name = "iplock",
    .f_options = g_options,
    .f_options_files_directory = nullptr,
    .f_environment_variable_name = "IPTABLES_EDIT_OPTIONS",
    .f_environment_variable_intro = "IPTABLES_EDIT_",
    .f_section_variables_name = nullptr,
    .f_configuration_files = nullptr,
    .f_configuration_filename = "iptables-edit.conf",
    .f_configuration_directories = nullptr,
    .f_environment_flags = advgetopt::GETOPT_ENVIRONMENT_FLAG_SYSTEM_PARAMETERS
                         | advgetopt::GETOPT_ENVIRONMENT_FLAG_PROCESS_SYSTEM_PARAMETERS,
    .f_help_header = "Usage: %p [-<opt>]\n"
                     "where -<opt> is one or more of:",
    .f_help_footer = "%c\nLicense: %l",
    .f_version = IPLOCK_VERSION_STRING,
    .f_license = "GNU GPL 3",
    .f_copyright = "Copyright (c) 2026-"
                   SNAPDEV_STRINGIZE(UTC_BUILD_YEAR)
                   " by Made to Order Software Corporation -- All Rights Reserved",
    .f_build_date = UTC_BUILD_DATE,
    .f_build_time = UTC_BUILD_TIME,
    .f_groups = g_group_descriptions,
};






/** \brief This function initialize an iptables editor object.
 *
 * The constructor puts in place the command line options by
 * parsing them.
 *
 * As we are at it, we also load the configuration file and
 * setup the logger.
 *
 * \param[in] argc  The command line argc parameter.
 * \param[in] argv  The command line argv parameter.
 */
editor::editor(int argc, char * argv[])
    : f_opts(g_options_environment)
{
    snaplogger::add_logger_options(f_opts);
    f_opts.finish_parsing(argc, argv);
    if(!snaplogger::process_logger_options(
              f_opts
            , "/etc/iplock/logger"
            , std::cout
            , !isatty(fileno(stdin))))
    {
        // exit on any error
        //
        throw advgetopt::getopt_exit("logger options generated an error.", 0);
    }
}


/** \brief Clean up the editor.
 *
 * This function is used to do some clean up of the editor environment.
 * Especially, it may create some temporary files which it wants to
 * delete here.
 */
editor::~editor()
{
}






/** \brief Start the editor process.
 *
 * This function calls the necessary functions to implement the editor
 * functionality.
 *
 * \return 0 on success, 1 or some other number on error.
 */
int editor::run()
{
    int r(execute_commands());
    if(r != -1)
    {
        return r;
    }

    r = must_be_root();
    if(r != 0)
    {
        return r;
    }

    r = must_be_a_tty();
    if(r != 0)
    {
        return r;
    }

    r = determine_internet_protocol();
    if(r != 0)
    {
        return r;
    }

    r = create_temp_dir();
    if(r != 0)
    {
        return r;
    }

    r = obtain_lock();
    if(r != 0)
    {
        return r;
    }

    r = get_current_firewall();
    if(r != 0)
    {
        return r;
    }

    r = edit_firewall();
    if(r != 0)
    {
        return r;
    }

    r = file_changed(f_filename, f_backup);
    if(r != 1)
    {
        if(r == 0)
        {
            SNAP_LOG_MINOR
                << "file did not change, skip updating firewall."
                << SNAP_LOG_SEND;
            return 0;
        }
        SNAP_LOG_ERROR
            << "comparing your changes against the original failed ("
            << r
            << ")."
            << SNAP_LOG_SEND;
        return r;
    }

    r = compare_firewall();
    if(r != 0)
    {
        return r;
    }

    r = save_firewall();
    if(r != 0)
    {
        return r;
    }

    return 0;
}


/** \brief Execute a command.
 *
 * By default, the editor starts your editor with the specified table.
 * This function allows the editor to execute a command instead. In
 * most cases, those commands can be run early on.
 *
 * \return 0 commands were executed without error; 1 or more if an error
 * occurred while executing a command; -1 no commands were found.
 */
int editor::execute_commands()
{
    if(f_opts.is_defined("iptables-versions"))
    {
        int const r(system("iptables -V"));
        if(r != 0)
        {
            return r;
        }
        return 0;
    }

    return -1;
}


/** \brief Verify some command line options validity.
 *
 * At the moment, we want to verify that the --timeout parameter is valid
 * early on, before we do any editing. If not valid, then we would not
 * properly be able to wait for a confirmation after restoring the
 * firewall rules.
 *
 * \return 1 on error, 0 otherwise
 */
int editor::check_options()
{
    { // check --timeout <value>
        std::string const timeout(f_opts.get_string("timeout"));
        double timeout_duration(0.0);
        if(!advgetopt::validator_duration::convert_string(
                  timeout
                , advgetopt::validator_duration::VALIDATOR_DURATION_DEFAULT_FLAGS
                , 1.0
                , timeout_duration))
        {
            SNAP_LOG_ERROR
                << "the duration specified with --timeout is not valid: "
                << timeout
                << SNAP_LOG_SEND;
            return 1;
        }
        f_timeout = timeout_duration;
    }

    return 0;
}


/** \brief Make sure the caller is root, otherwise it won't work.
 *
 * At this point, we need the caller to be root to continue.
 *
 * This function  makes sure that the user is root. If not, it returns an
 * error (1).
 *
 * \return 1 if the user is not root, 0 otherwise.
 */
int editor::must_be_root()
{
    if(getuid() != 0)
    {
        SNAP_LOG_ERROR
            << "you must be root to edit the firewall rules."
            << SNAP_LOG_SEND;
        return 1;
    }

    return 0;
}


int editor::must_be_a_tty()
{
    if(!isatty(fileno(stdin)))
    {
        SNAP_LOG_ERROR
            << "you must use a TTY terminal to edit the firewall rules."
            << SNAP_LOG_SEND;
        return 1;
    }

    return 0;
}


/** \brief Check whether the user wants to edit IPv4 or IPv6 tables.
 *
 * The IPv4 and IPv6 tables are both editable but they are completely
 * separate so you need to specify which one you want to edit.
 *
 * This function checks the command line options for --ip and --ip6.
 * If both are specified, it is an error. By default, --ip is assumed.
 *
 * \return 0 if no error is found, 1 if --ip and --ip6 were both
 * specified.
 */
int editor::determine_internet_protocol()
{
    if(f_opts.is_defined("ip6"))
    {
        if(f_opts.is_defined("ip"))
        {
            SNAP_LOG_ERROR
                << "--ip and --ip6 are mutually exclusive."
                << SNAP_LOG_SEND;
            return 1;
        }
        f_ipv6 = true;
    }

    return 0;
}


/** \brief Create a temporary directory to save the files being edited.
 *
 * This function creates a temporary directory. It is used to save the
 * current version of the iptables, make a copy so we can edit it, and
 * then use the iptables-save again just before saving everything to
 * make sure the tables did not change before doing out updates.
 *
 * By default, this is "/tmp/iptables". You can change the path to the
 * temporary directory using the TMPDIR environment variable. The
 * ".../iptables" part is currently hard coded.
 *
 * The directory is created with permissions set to 0700 so only root
 * will have access to that directory.
 *
 * \return 0 on success, 1 on failure
 */
int editor::create_temp_dir()
{
    char const * tmpdir(getenv("TMPDIR"));
    if(tmpdir == nullptr)
    {
        tmpdir = "/tmp";
    }

    f_tmpdir = snapdev::pathinfo::canonicalize(tmpdir, "iplock");

    if(snapdev::mkdir_p(f_tmpdir, false, 0700) != 0)
    {
        SNAP_LOG_ERROR
            << "error: could not create temporary directory \""
            << f_tmpdir
            << "\""
            << SNAP_LOG_SEND;
        return 1;
    }

    return 0;
}


/** \brief Obtain a lock.
 *
 * This function creates a file (lock) so we make sure only one instance
 * of the editor runs at a time. There is really no need to run more than
 * one since the second save would fail (assuming the first made changes
 * to the file).
 *
 * \return 0 when the lock was obtained; 1 if it failed
 */
int editor::obtain_lock()
{
    std::string const filename(snapdev::pathinfo::canonicalize(f_tmpdir, "iptables-edit.lock"));
    f_lock = std::make_shared<snapdev::lockfile>(filename, snapdev::operation_t::OPERATION_EXCLUSIVE, S_IRUSR | S_IWUSR);
    if(!f_lock->try_lock())
    {
        SNAP_LOG_ERROR
            << "could not obtain lock. Is there another instance of the editor running?"
            << SNAP_LOG_SEND;
        return 1;
    }

    return 0;
}


/** \brief Verify that a name is valid as a chain name.
 *
 * Make sure a table name is valid. The official regex is something like
 * this:
 *
 * \code
 * ^[a-zA-Z_][a-zA-Z0-9_-]{0,28}$
 * \endcode
 *
 * Where the length can be 0 (empty string, no specific name). Here our
 * function returns false on empty strings. The caller has to handle those
 * specifically as required.
 *
 * \return true if the name is considered valid.
 */
bool editor::verify_table_name(std::string const & table_name)
{
    char const * s(table_name.c_str());
    if(*s != '_'
    && (*s < 'A' || *s > 'Z')
    && (*s < 'a' || *s > 'z'))
    {
        return false;
    }

    for(++s; *s != '0'; ++s)
    {
        if(*s != '_'
        && *s != '-'
        && (*s < 'A' || *s > 'Z')
        && (*s < 'a' || *s > 'z')
        && (*s < '0' || *s > '9'))
        {
            return false;
        }
    }

    return true;
}


/** \brief Retrieve the current firewall rules.
 *
 * This function saves the current firewall rules in two files. One file
 * is the one you are going to edit and the other is a backup to know
 * whether the firewall changed between the time you started editing it
 * and the time you are ready to save your changes. This is not 100%
 * safe (not atomic,) but still much safer in practice.
 *
 * \note
 * The filenames are unique. Since we prevent more than one editor
 * from running at the same time as another instance, it should be
 * safe.
 *
 * \return 0 on success, 1 on an error.
 */
int editor::get_current_firewall()
{
    // generate the output filenames
    //
    std::string const filename(f_ipv6 ? "ip6tables" : "iptables");
    f_filename = snapdev::pathinfo::canonicalize(f_tmpdir, filename);
    f_backup = f_filename + ".original";
    return get_firewall(f_filename, f_backup);
}


/** \brief Retrieve the firewall.
 *
 * This function runs the iptables-save command to retrieve the firewall
 * and save it in the specified file.
 *
 * \param[in] filename  Name of the file where to save the firewall rules.
 * \param[in] backup  If specified, make a copy of the rules in this file.
 *
 * \return 0 when no error occurred, 1 if an error occurs
 */
int editor::get_firewall(std::string const & filename, std::string const & backup)
{
    // ready the command
    //
    std::string cmd(f_ipv6 ? "ip6tables-save" : "iptables-save");
    if(f_opts.is_defined("table"))
    {
        std::string const table_name(f_opts.get_string("table"));
        if(!verify_table_name(table_name))
        {
            SNAP_LOG_ERROR
                << "invalid table \""
                << table_name
                << "\"."
                << SNAP_LOG_SEND;
            return 1;
        }
        cmd += " -t " + table_name;
    }

    // directly save to two files using 'tee'
    //
    if(!backup.empty())
    {
        cmd += " | tee ";
        cmd += backup;
    }
    cmd += " > ";
    cmd += filename;

    // run the command
    //
    int const r(system(cmd.c_str()));
    if(r != 0)
    {
        SNAP_LOG_ERROR
            << "could not retrieve the firewall rules."
            << SNAP_LOG_SEND;
        return 1;
    }

    return 0;
}


/** \brief Start the user editor.
 *
 * This function starts the user editor with the firewall file.
 *
 * \return 0 when no error occurred; 1 if the editor did not start
 */
int editor::edit_firewall()
{
    struct stat st;
    char const * editors[] = {
        "/usr/bin/sensible-editor",
        "/usr/bin/vim",
        "/usr/bin/vi",
        "/usr/bin/nano",
    };
    std::string editor_name;
    for(size_t i(0); i < std::size(editors); ++i)
    {
        if(stat(editors[i], &st) == 0)
        {
            editor_name = editors[i];
            break;
        }
    }
    if(editor_name.empty())
    {
        SNAP_LOG_ERROR
            << "sensible-editor not found."
            << SNAP_LOG_SEND;
        return 1;
    }

    std::string cmd(editor_name);
    cmd += ' ';
    cmd += f_filename;
    int const r(system(cmd.c_str()));
    if(r != 0)
    {
        SNAP_LOG_ERROR
            << "could not start editor \""
            << editor_name
            << "\"."
            << SNAP_LOG_SEND;
        return 1;
    }

    return 0;
}


/** \brief Change whether the user changed the file.
 *
 * This function compares the iptables file with the original. If there
 * were no changes, then we can just quit. The user made no changes.
 *
 * \todo
 * This uses "cmp ..." when we should (1) ignore any comment (lines starting
 * with '#", (2) empty lines, (3) changes in spaces only [extra spaces can
 * be ignored]. This would be easier for us to do manually than trying to
 * use tools with lots of piping. Next version... [this would be easy with
 * a lexer]
 *
 * \param[in] filename  The name of one file.
 * \param[in] backup  The name of the other file to compare against.
 *
 * \return 0 if there were no changes, 1 if there were changes, something
 * else on errors
 */
int editor::file_changed(std::string const & filename, std::string const & backup)
{
    lexer l1(filename);
    lexer l2(backup);
    for(;;)
    {
        std::string t1(l1.next());
        std::string t2(l2.next());
        if(t1 != t2)
        {
            if(!t1.empty()
            && t1[0] == ':'
            && !t2.empty()
            && t2[0] == ':')
            {
                std::string::size_type const s1(t1.find('['));
                std::string::size_type const s2(t1.find('['));
                if(s1 == s2)
                {
                    std::string_view const v1(t1.data(), s1);
                    std::string_view const v2(t2.data(), s2);
                    if(v1 == v2)
                    {
                        // these are actually equal if we ignore the
                        // counters; so go on
                        //
                        continue;
                    }
                }
            }
            f_differing_line1 = t1;
            f_differing_line2 = t2;
            return 1;
        }
        if(t1.empty()) // got a errors in both files (rather unlikely) or EOF
        {
            return 0;
        }
    }
}


/** \brief Compare the current firewall with the original.
 *
 * This function retrieves a new copy of the firewall rules and compares
 * it with the original retrieved before the editing started. If it did
 * change, then this is considered an issue and we drop the editing
 * from the user (oops). This happens only if another tool somehow
 * changes the firewall before the user has a chance to save his
 * changes.
 *
 * Note that if editing a specific table, then only that specific table
 * needs to change for this function to fail. So it's a good idea to
 * use the --table command line option. In most cases, tools that
 * dynamically update the firewall will do so in their own rules.
 *
 * \return 0 on success (it did not change); 1 if any error occurs
 */
int editor::compare_firewall()
{
    // get a fresh copy of the firewall rules
    //
    std::string const current(f_filename + ".current");
    int r(get_firewall(current));
    if(r != 0)
    {
        SNAP_LOG_ERROR
            << "could not retrieve a copy of the firewall rules for verification."
            << SNAP_LOG_SEND;
        return r;
    }

    // compare our original (before user's changes) with the current copy
    //
    if(file_changed(f_backup, current) != 0)
    {
        SNAP_LOG_ERROR
            << "the firewall rules changed between the time you started editing and now; not applying your changes: \""
            << f_differing_line1
            << "\" vs \""
            << f_differing_line2
            << "\"."
            << SNAP_LOG_SEND;
        return 1;
    }

    return 0;
}


/** \brief Everything worked so far, now save (restore) the new rules.
 *
 * The used started the editor successfully. Changes were made, the
 * original and current iptables rules are the same, this function
 * saves the user changes in the firewall using the iptables-restore
 * command.
 *
 * The command requests the user to answer with Y if they want to keep
 * the rules. If no answer is returned within the amount of time
 * specified with --timeout, then the function fails and restores the
 * original rules.
 *
 * \return 0 on success; 1 on failure
 */
int editor::save_firewall()
{
    int r(restore_firewall(f_filename));
    if(r != 0)
    {
        return r;
    }

    // simulate the iptables-apply; wait for a Y answer, if not
    // received within timeout then restore the firewall with the
    // original
    //
    std::cout << "Your edits were applied. Please confirm that you want to keep them.\n"
        << "You have "
        << f_timeout
        << " seconds to reply or the original firewall rules will be restored.\n\n"
        << "Keep changes? (y/N) "
        << std::flush;
    int const ch(snapdev::timed_getchar(f_timeout));
    if(ch != '\n')
    {
        std::cout << std::endl;
    }
    if(ch != 'y' && ch != 'Y')
    {
        // user did not answer quickly enough, restore the firewall to
        // the original
        //
        SNAP_LOG_WARNING
            << (ch == '\0'
                    ? "we did not receive a positive answer in time"
                    : "it looks like you changed your mind")
            << ", restoring the original rules."
            << SNAP_LOG_SEND;
        snapdev::NOT_USED(restore_firewall(f_backup));
        return 1;
    }

    return 0;
}


/** \brief Restore the specified firewall rules.
 *
 * By default, the \p rules_filename is set to f_filename. If that fails,
 * then nothing more happens.
 *
 * If the rules were restored, that means the firewall was updated. In
 * that case, the user may be blocked and cannot access their server.
 * For that reason, we have a confirmation prompt. If the user does not
 * answer the prompt quickly enough, then the original, f_backup, gets
 * restored. That original should give the user his access back to
 * their server.
 *
 * \param[in] rules_filename  The name of the file used to restore the
 * firewall rules.
 *
 * \return 0 on success, 1 on error.
 */
int editor::restore_firewall(std::string const & rules_filename)
{
    std::string cmd("iptables-restore");
    if(f_opts.is_defined("table"))
    {
        std::string const table_name(f_opts.get_string("table"));
        if(!verify_table_name(table_name))
        {
            // this should never happen since we already verified this
            // parameter when retrieving the firewall earlier
            //
            SNAP_LOG_ERROR
                << "invalid table \""
                << table_name
                << "\"."
                << SNAP_LOG_SEND;
            return 1;
        }
        cmd += " -T " + table_name;
    }
    cmd += ' ';
    std::string cmd_on_failure(cmd);   // save in case of failure below
    cmd += rules_filename;
    int const r(system(cmd.c_str()));
    if(r != 0)
    {
        SNAP_LOG_ERROR
            << "restoring the firewall rules failed."
            << SNAP_LOG_SEND;
        return 1;
    }

    return 0;
}



} // namespace iptables_edit
// vim: ts=4 sw=4 et
