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

    # load the application helper
    # this helper is used to check the status for an application
    load '../../test/test_helper/bats-cis-application/load'
}

# Section: 5 Access, Authentication and Authorization
# ================================================
# test for 5.3 Configure privilege escalation
# ================================================
# 5.3 Configure privilege escalation
# 5.3.1 Ensure sudo is installed (Automated)
@test "5.3.1 Ensure sudo is installed (Automated)" {
    # set pkg name to check
    local pkg_sudo="sudo"
    local pkg_sudo_ldap="sudo-ldap"
    
    # check if sudo or sudo-ldap are installed
    # if at least one package is installed
    if (! is_app_installed $pkg_sudo) && (! is_app_installed $pkg_sudo_ldap); then
        assert_failure
    fi
}

# 5.3.2 Ensure sudo commands use pty (Automated)
@test "5.3.2 Ensure sudo commands use pty (Automated)" {
    # verify that sudo can only run other commands from a pseudo terminal
    run bash -c "grep -rPiq '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' /etc/sudoers* 2>/dev/null"
    assert_success
}

# 5.3.3 Ensure sudo log file exists (Automated)
@test "5.3.3 Ensure sudo log file exists (Automated)" {
    # verify that sudo has a custom log file configured
    run is_sudo_log_file_exists
    assert_success
}

# 5.3.4 Ensure users must provide password for privilege escalation (Automated)
@test "5.3.4 Ensure users must provide password for privilege escalation (Automated)" {
    # verify the operating system requires users to supply a password for privilege escalation
    run bash -c 'grep -rq "^[^#].*NOPASSWD" /etc/sudoers* 2>/dev/null'
    assert_success
}

# 5.3.5 Ensure re-authentication for privilege escalation is not disabled globally (Automated)
@test "5.3.5 Ensure re-authentication for privilege escalation is not disabled globally (Automated)" {
    # verify the operating system requires users to re-authenticate for privilege escalation
    run bash -c "grep -rqv '^[^#].*\!authenticate' /etc/sudoers* 2>/dev/null"
    assert_success
}

# 5.3.6 Ensure sudo authentication timeout is configured correctly (Automated)
@test "5.3.6 Ensure sudo authentication timeout is configured correctly (Automated)" {
    run bash -c "grep -roPq 'timestamp_timeout=\K[0-9]*' /etc/sudoers* 2>/dev/null"
    assert_success
}

# 5.3.7 Ensure access to the su command is restricted (Automated)
@test "5.3.7 Ensure access to the su command is restricted (Automated)" {
    # command will only allow users in a specific groups to execute su. This group should be empty to reinforce the use of sudo for privileged access.
    run bash -c "grep -Piq '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null"
    assert_success
}