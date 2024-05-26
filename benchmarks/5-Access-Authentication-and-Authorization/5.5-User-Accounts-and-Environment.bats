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

    # load the access helper
    # this helper is used to check the status for access
    load '../../test/test_helper/bats-cis-access/load'
}

# Section: 5 Access, Authentication and Authorization
# ================================================
# test for 5.5 User Accounts and Environment
# ================================================
# 5.5 User Accounts and Environment
# 5.5.1 Set Shadow Password Suite Parameters
# 5.5.1.1 Ensure minimum days between password changes is configured (Automated)
@test "5.5.1.1 Ensure minimum days between password changes is configured (Automated)" {
    # verify PASS_MIN_DAYS conforms to site policy (no less than 1 day)
    run is_valid_password_min_days_policy
    assert_success

    # review list of users and PASS_MIN_DAYS to Verify that all users' PASS_MIN_DAYS conforms to site policy (no less than 1 day)
    run ensure_minimum_days_between_password_changes_is_configured
    assert_success
}

# 5.5.1.2 Ensure password expiration is 365 days or less (Automated)
@test "5.5.1.2 Ensure password expiration is 365 days or less (Automated)" {
    # verify PASS_MAX_DAYS conforms to site policy, does not exceed 365 days, and is greater than PASS_MIN_DAYS
    run is_valid_expiration_password_policy
    assert_success

    # review list of users and PASS_MAX_DAYS to verify that all users' PASS_MAX_DAYS conforms to site policy
    # does not exceed 365 days, and is no less than PASS_MIN_DAYS
    run ensure_password_expiration_is_365_days_or_less
    assert_success
}

# 5.5.1.3 Ensure password expiration warning days is 7 or more (Automated)
@test "5.5.1.3 Ensure password expiration warning days is 7 or more (Automated)" {
    # verify PASS_WARN_AGE conforms to site policy (No less than 7 days)
    run is_valid_expiration_password_warning_policy
    assert_success

    # review list of users and PASS_WARN_AGE to verify that all users' PASS_WARN_AGE conforms to site policy (No less than 7 days)
    run ensure_password_expiration_warning_days_is_7_or_more
    assert_success
}

# 5.5.1.4 Ensure inactive password lock is 30 days or less (Automated)
@test "5.5.1.4 Ensure inactive password lock is 30 days or less (Automated)" {
    # verify INACTIVE conforms to sire policy (no more than 30 days)
    run is_valid_password_inactive_days_policy
    assert_success

    # review list of users and INACTIVE to verify that all users' INACTIVE conforms to site policy (no more than 30 days)
    run ensure_inactive_password_lock_is_30_days_or_less
    assert_success
}

# 5.5.1.5 Ensure all users last password change date is in the past (Automated)
@test "5.5.1.5 Ensure all users last password change date is in the past (Automated)" {
    # if a users recorded password change date is in the future
    # then they could bypass any set password expiration
    run ensure_all_users_last_password_change_date_is_in_the_past
    assert_output ""
    assert_success
}

# 5.5.2 Ensure system accounts are secured (Automated)
@test "5.5.2 Ensure system accounts are secured (Automated)" {
    # it is also recommended that the shell field in the password file be set to the nologin shell.
    # this prevents the account from potentially being used to run any commands
    # the root, sync, shutdown, and halt users are exempted from requiring a non login shell
    run bash -c "awk -F: '\$1!~/(root|sync|shutdown|halt|^\+)/ && \$3<'\"\$(awk '/^\s*UID_MIN/{print \$2}' /etc/login.defs)\"' && \$7!~/((\/usr)?\/sbin\/nologin)/ && \$7!~/(\/bin)?\/false/ {print}' /etc/passwd 2>/dev/null"
    assert_output ""
    assert_success

    run bash -c "awk -F: '(\$1!~/(root|^\+)/ && \$3<'\"\$(awk '/^\s*UID_MIN/{print \$2}' /etc/login.defs)\"') {print \$1}' /etc/passwd 2>/dev/null | xargs -I '{}' passwd -S '{}' | awk '(\$2!~/LK?/) {print \$1}'"
    assert_output ""
    assert_success
}

# 5.5.3 Ensure default group for the root account is GID 0 (Automated)
@test "5.5.3 Ensure default group for the root account is GID 0 (Automated)" {
    # verify the result is 0
    run bash -c 'grep "^root:" /etc/passwd | cut -f4 -d:'
    assert_output 0
    assert_success
}

# 5.5.4 Ensure default user umask is 027 or more restrictive (Automated)
@test "5.5.4 Ensure default user umask is 027 or more restrictive (Automated)" {
    # verify that a default user umask is set enforcing a newly 
    # created directories's permissions to be 750 (drwxr-x---), 
    # and a newly created file's permissions be 640 (rw-r-----), or more restrictive
    run ensure_default_user_umask_is_027_or_more_restrictive
    assert_output --partial "Default user umask is set"
    assert_success

    # verify that no less restrictive system wide umask is set:
    run bash -c "grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bash.bashrc* 2>/dev/null | grep -q ' '"
    assert_success
}

# 5.5.5 Ensure default user shell timeout is 900 seconds or less (Automated)
@test "5.5.5 Ensure default user shell timeout is 900 seconds or less (Automated)" {
    run ensure_default_user_shell_timeout_is_900_seconds_or_less
    assert_output --partial "PASSED"
    assert_success
}