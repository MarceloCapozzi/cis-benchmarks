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

# Section: Initial Setup
# ================================================
# test for 1.3 Filesystem Integrity Checking
# ================================================
# 1.3 Filesystem Integrity Checking
# 1.3.1 Ensure AIDE is installed (Automated)
@test "1.3.1 Ensure AIDE is installed (Automated)" {
    # check if aide is installed
    local pkg="aide"
    run is_app_installed $pkg
    assert_success

    # check if aide-common is installed
    local pkg="aide-common"
    run is_app_installed $pkg
    assert_success
}

# 1.3.2 Ensure filesystem integrity is regularly checked (Automated)
@test "1.3.2 Ensure filesystem integrity is regularly checked (Automated)" {
    # check a cron job scheduled to run the aide check
    run bash -c 'grep -Prs "^([^#\n\r]+\h+)?(\/usr\/s?bin\/|^\h*)aide(\.wrapper)?\h+(--check|([^#\n\r]+\h+)?\$AIDEARGS)\b" /etc/cron.* /etc/crontab /var/spool/cron/ 2>/dev/null'
    assert_success

    # check if aidacheck is enabled
    local pkg="aidecheck"
    run is_app_enabled $pkg
    assert_success

    # check if aidacheck.timer is enabled
    run bash -c "systemctl is-enabled $pkg.timer"
    assert_output "enabled"

    # check if aidacheck.timer is active
    run bash -c "systemctl status $pkg.timer | grep -q active"
    assert_success
}