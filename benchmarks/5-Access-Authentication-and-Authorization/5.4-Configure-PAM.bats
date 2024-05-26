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
    # load the application helper
    # this helper is used to check the status for an application
    load '../../test/test_helper/bats-cis-application/load'
}

# Section: 5 Access, Authentication and Authorization
# ================================================
# test for 5.4 Configure PAM
# ================================================
# 5.4 Configure PAM
# 5.4.1 Ensure password creation requirements are configured (Automated)
@test "5.4.1 Ensure password creation requirements are configured (Automated)" {
    # set pkg name to check
    local pkg=libpam-pwquality
    
    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # set password quality configuration
        local pw_qa_config="/etc/security/pwquality.conf"
        
        # check if exists file
        if [ -f $pw_qa_config ]; then
            skip "Verify password creation requirements ($pw_qa_config) conform to organization policy"
        else
            skip "$pw_qa_config is not exists"
        fi
    else
        skip "$pkg is not installed"
    fi     
}

# 5.4.2 Ensure lockout for failed password attempts is configured (Automated)
@test "5.4.2 Ensure lockout for failed password attempts is configured (Automated)" {
    # verify pam_faillock.so is configured
    run bash -c 'grep -q "^auth.*pam_faillock.so" /etc/pam.d/common-auth 2>/dev/null'
    assert_success

    # verify pam_faillock.so is configured
    run bash -c 'grep -q "^account.*pam_faillock.so" /etc/pam.d/common-account 2>/dev/null'
    assert_success

    # deny is not greater than 4
    run bash -c "awk '/^ *deny *=/' /etc/security/faillock.conf 2>/dev/null | awk -F '=' '{print $2}'"
    [[ "${output}" -gt 0 ]] && [[ "${output}" -lt 4 ]]
    assert_success

    # fail_interval is no greater than 900
    run bash -c "awk '/^ *fail_interval *=/' /etc/security/faillock.conf 2>/dev/null | awk -F '=' '{print $2}'"
    [[ "${output}" -gt 0 ]] && [[ "${output}" -lt 900 ]]
    assert_success

    # unlock_time is 0, or greater than or equal to 600
    run bash -c "awk '/^ *unlock_time *=/' /etc/security/faillock.conf 2>/dev/null | awk -F '=' '{print $2}'"
    [[ "${output}" -eq 0 ]] || [[ "${output}" -gt 600 ]]
    assert_success
}

# 5.4.3 Ensure password reuse is limited (Automated)
@test "5.4.3 Ensure password reuse is limited (Automated)" {
    # verify that option is 5 or more and follows your site policy
    run bash -c "grep -Pqs '^\h*password\h+([^#\n\r]+\h+)?pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/common-password 2>/dev/null"
    assert_success
}

# 5.4.4 Ensure password hashing algorithm is up to date with the latest standards (Automated)
@test "5.4.4 Ensure password hashing algorithm is up to date with the latest standards (Automated)" {
    # verify no hashing algorithm should be configured in /etc/pam.d/common-password
    run bash -c "grep -v '^#' /etc/pam.d/common-password 2>/dev/null | grep -Ev '(yescrypt|md5|bigcrypt|sha256|sha512|blowfish)'"
    assert_failure

    run bash -c "grep -iq '^\s*ENCRYPT_METHOD\s*yescrypt\s*$' /etc/login.defs"
    assert_success
}

# 5.4.5 Ensure all current passwords uses the configured hashing algorithm (Manual)
@test "5.4.5 Ensure all current passwords uses the configured hashing algorithm (Manual)" {
    # get a list of users that are not using the currently configured hashing algorithm
    run ensure_all_current_passwords_uses_the_configured_hashing_algorithm
    assert_success
}