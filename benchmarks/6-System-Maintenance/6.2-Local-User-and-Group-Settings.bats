#!/usr/bin/env bats
#
# ================================================
# This script is used to monitoring the base of operating system for vulnerabilities
# Based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# bats-core docs: https://bats-core.readthedocs.io/en/stable/tutorial.html
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
# ================================================
#
# this function is called before each test
# the load function is used to load the helpers
# it loads the bats-support, bats-assert and bats-files helpers
# it also sets the PATH to include the src/ directory
# 
setup() {
    # load the helpers
    load '../../test/test_helper/bats-support/load'
    load '../../test/test_helper/bats-assert/load'
    load '../../test/test_helper/bats-files/load'
    # get the containing directory of this file
    # use $BATS_TEST_FILENAME instead of ${BASH_SOURCE[0]} or $0,
    # as those will point to the bats executable's location or the preprocessed file respectively
    DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" >/dev/null 2>&1 && pwd )"
    # make executables in src/ visible to PATH
    PATH="$DIR/../src:$PATH"

    # load the files helper
    # this helper is used to check the status for files
    load '../../test/test_helper/bats-cis-files/load'
}

# Section: 6 System Maintenance
# ================================================
# test for 6.2 Local User and Group Settings
# ================================================
# 6.2 Local User and Group Settings
# 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords (Automated)
@test "6.2.1 Ensure accounts in /etc/passwd use shadowed passwords (Automated)" {
    # All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user
    # A user account with an empty second field in /etc/passwd allows the account to be logged into by providing only the username
    run bash -c "awk -F: '(\$2 != "x" ) { print $1 \" is not set to shadowed passwords \"}' /etc/passwd 2>/dev/null"
    assert_output ""
    assert_success
}

# 6.2.2 Ensure /etc/shadow password fields are not empty (Automated)
@test "6.2.2 Ensure /etc/shadow password fields are not empty (Automated)" {
    # accounts in the /etc/shadow file must be have a password
    # this check identify the accounts that do not have a password
    run bash -c "awk -F: '(\$2 == \"\" ) { print \$1 \" does not have a password \"}' /etc/shadow 2>/dev/null"
    assert_output ""
    assert_success
}

# 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group (Automated)
@test "6.2.3 Ensure all groups in /etc/passwd exist in /etc/group (Automated)" {
    # identify groups defined in the /etc/passwd file but not in the /etc/group file
    run ensure_all_groups_in_passwdfile_exist_in_groupfile
    assert_output ""
    assert_success
}

# 6.2.4 Ensure shadow group is empty (Automated)
@test "6.2.4 Ensure shadow group is empty (Automated)" {
    # no users should be assigned to the shadow group
    run bash -c "awk -F: '(\$1==\"shadow\") {print $NF}' /etc/group"
    assert_output ""
    assert_success

    # no users should be assigned to the shadow group
    run bash -c "awk -F: -v GID=\"\$(awk -F: '(\$1==\"shadow\") {print \$3}' /etc/group)\" '(\$4==GID) {print \$1}' /etc/passwd 2>/dev/null"
    assert_output ""
    assert_success
}

# 6.2.5 Ensure no duplicate UIDs exist (Automated)
@test "6.2.5 Ensure no duplicate UIDs exist (Automated)" {
    # users must be assigned unique UIDs for accountability and to ensure appropriate access protections
    run ensure_no_duplicate_UIDs_exist
    assert_output ""
    assert_success
}

# 6.2.6 Ensure no duplicate GIDs exist (Automated)
@test "6.2.6 Ensure no duplicate GIDs exist (Automated)" {
    # user groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.
    run ensure_no_duplicate_GIDs_exist
    assert_output ""
    assert_success
}

# 6.2.7 Ensure no duplicate user names exist (Automated)
@test "6.2.7 Ensure no duplicate user names exist (Automated)" {
    # if a user is assigned a duplicate user name, it will create and have access to files with 
    # the first UID for that username in /etc/passwd
    run ensure_no_duplicate_user_names_exist
    assert_output ""
    assert_success
}

# 6.2.8 Ensure no duplicate group names exist (Automated)
@test "6.2.8 Ensure no duplicate group names exist (Automated)" {
    # if a group is assigned a duplicate group name, it will create and have access to files with
    # the first GID for that group in /etc/group
    run ensure_no_duplicate_group_names_exist
    assert_output ""
    assert_success
}

# 6.2.9 Ensure root PATH Integrity (Automated)
@test "6.2.9 Ensure root PATH Integrity (Automated)" {
    # The root user can execute any command on the system and could be fooled into 
    # executing programs unintentionally if the PATH is not set correctly.
    run ensure_root_path_integrity
    assert_output ""
    assert_success
}

# 6.2.10 Ensure root is the only UID 0 account (Automated)
@test "6.2.10 Ensure root is the only UID 0 account (Automated)" {
    # any account with UID 0 has superuser privileges on the system
    run bash -c "awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd 2>/dev/null | grep -q root"
    assert_success
}

# 6.2.11 Ensure local interactive user home directories exist (Automated)
@test "6.2.11 Ensure local interactive user home directories exist (Automated)" {
    # users can be defined in /etc/passwd without a home directory or with a home directory 
    # that does not actually exist
    run ensure_local_interactive_user_home_directories_exist
    assert_output --partial "PASSED"
    assert_success
}

# 6.2.12 Ensure local interactive users own their home directories (Automated)
@test "6.2.12 Ensure local interactive users own their home directories (Automated)" {
    # since the user is accountable for files stored in the user home directory, the user must 
    # be the owner of the directory
    run ensure_local_interactive_users_own_their_home_directories
    assert_output --partial "PASSED"
    assert_success
}

# 6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive (Automated)
@test "6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive (Automated)" {
    # group or world-writable user home directories may enable malicious users to steal or 
    # modify other users' data or to gain another user's system privileges.
    run ensure_local_interactive_user_home_directories_are_mode_750_or_more_restrictive
    assert_output --partial "PASSED"
    assert_success
}

# 6.2.14 Ensure no local interactive user has .netrc files (Automated)
@test "6.2.14 Ensure no local interactive user has .netrc files (Automated)" {
    # the .netrc file presents a significant security risk since it stores passwords in unencrypted form
    run ensure_no_local_interactive_user_has_netrc_files
    assert_output --partial "PASSED"
    assert_success
}

# 6.2.15 Ensure no local interactive user has .forward files (Automated)
@test "6.2.15 Ensure no local interactive user has .forward files (Automated)" {
    # the .forward file also poses a risk as it can be used to execute commands that may perform unintended actions
    run ensure_no_local_interactive_user_has_forward_files
    assert_output --partial "PASSED"
    assert_success
}

# 6.2.16 Ensure no local interactive user has .rhosts files (Automated)
@test "6.2.16 Ensure no local interactive user has .rhosts files (Automated)" {
    # the .rhosts may have been brought over from other systems and could contain information 
    # useful to an attacker for those other systems
    run ensure_no_local_interactive_user_has_rhosts_files
    assert_output --partial "PASSED"
    assert_success
}

# 6.2.17 Ensure local interactive user dot files are not group or world writable (Automated)
@test "6.2.17 Ensure local interactive user dot files are not group or world writable (Automated)" {
    # group or world-writable user configuration files may enable malicious users to steal or 
    # modify other users' data or to gain another user's system privileges
    run ensure_local_interactive_user_dot_files_are_not_group_or_world_writable    
    assert_output --partial "PASSED"
    assert_success
}