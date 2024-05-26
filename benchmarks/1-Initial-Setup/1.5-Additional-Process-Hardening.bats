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

# Section: 1 Initial Setup
# ================================================
# test for 1.5 Additional Process Hardening
# ================================================
# 1.5 Additional Process Hardening
# 1.5.1 Ensure address space layout randomization (ASLR) is enabled (Automated)
@test "1.5.1 Ensure address space layout randomization (ASLR) is enabled (Automated)" {
    # set kernel parameter (kp) to check
    local kp_name="kernel.randomize_va_space"
    # set version (kp)
    local kp_version="2"
    # set string (kp+version)
    local kp="$kp_name=$kp_version"
    local is_configured="$(grep -q $kp /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null)"
    
    # check if exists kernel parameter
    run bash -c "sysctl $kp_name | grep -q $kp"
    assert_success
    
    # check if kernel parameter is configured
    if [ ! $is_configured ]; then
        skip "kernel parameter $kp_name is not detected in config files"
    fi
}

# 1.5.2 Ensure prelink is not installed (Automated)
@test "1.5.2 Ensure prelink is not installed (Automated)" {
    # check if prelink is not installed
    local pkg="prelink"
    run is_app_installed $pkg
    assert_failure
}

# 1.5.3 Ensure Automatic Error Reporting is not enabled (Automated)
@test "1.5.3 Ensure Automatic Error Reporting is not enabled (Automated)" {
    # check if apport is not enabled
    local pkg="apport"
    run is_app_enabled $pkg
    assert_failure

    # check if apport is not active
    run is_app_active $pkg
    assert_failure
}

# 1.5.4 Ensure core dumps are restricted (Automated)
@test "1.5.4 Ensure core dumps are restricted (Automated)" {
    # check core dumps status
    local coredumps='* hard core 0'
    run bash -c "grep -q $coredump /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null"
    assert_success

    # check core dumps using sysctl
    local suid_dumpable='fs.suid_dumpable = 0'
    run bash -c "sysctl $suid_dumpable 2>/dev/null | grep -q $suid_dumpable"
    assert_success

    # check core dumps in sysctl config files
    run bash -c "grep -q $suid_dumpable /etc/sysctl.conf /etc/sysctl.d/* 2>/dev/null"
    assert_success
}