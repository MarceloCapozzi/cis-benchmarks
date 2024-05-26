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

    # load the network helper
    # this helper is used to check the status for network
    load '../../test/test_helper/bats-cis-network/load'
}

# 3 Network Configuration
# ================================================
# test for 3.1 Disable unused network protocols and devices
# ================================================
# 3.1 Disable unused network protocols and devices
# 3.1.1 Ensure system is checked to determine if IPv6 is enabled (Manual)
@test "3.1.1 Ensure system is checked to determine if IPv6 is enabled (Manual)" {
    # check if IPv6 is enabled
    run is_ipv6_enabled
    assert_success
}

# 3.1.2 Ensure wireless interfaces are disabled (Automated)
@test "3.1.2 Ensure wireless interfaces are disabled (Automated)" {
    # check if wireless interfaces are disabled
    run is-network-wireless-disabled
    assert_success
}

# 3.1.3 Ensure DCCP is disabled (Automated)
@test "3.1.3 Ensure DCCP is disabled (Automated)" {
    # set module to check
    local module_name='dccp'

    # check if module is not exists
    run bash -c "modprobe -n -v $module_name"
    assert_output --partial "modprobe: FATAL: Module $module_name not found in directory"
    assert_failure

    # check if module is not loaded
    run bash -c "lsmod 2>/dev/null | grep -q $module_name"
    assert_failure

    # check if module is in the blacklist
    run bash -c "modprobe --showconfig | grep ^blacklist | grep -q $module_name"
    if [ $status -eq 0 ]; then
        skip "module: $module_name is deny listed"
    fi
}

# 3.1.4 Ensure SCTP is disabled (Automated)
@test "3.1.4 Ensure SCTP is disabled (Automated)" {
    # set module to check
    local module_name='sctp'

    # check if module is not exists
    run bash -c "modprobe -n -v $module_name"
    assert_output --partial "modprobe: FATAL: Module $module_name not found in directory"
    assert_failure

    # check if module is not loaded
    run bash -c "lsmod 2>/dev/null | grep -q $module_name"
    assert_failure

    # check if module is in the blacklist
    run bash -c "modprobe --showconfig | grep ^blacklist | grep -q $module_name"
    if [ $status -eq 0 ]; then
        skip "module: $module_name is deny listed"
    fi
}

# 3.1.5 Ensure RDS is disabled (Automated)
@test "3.1.5 Ensure RDS is disabled (Automated)" {
    # set module to check
    local module_name='rds'

    # check if module is not exists
    run bash -c "modprobe -n -v $module_name"
    assert_output --partial "modprobe: FATAL: Module $module_name not found in directory"
    assert_failure

    # check if module is not loaded
    run bash -c "lsmod 2>/dev/null | grep -q $module_name"
    assert_failure

    # check if module is in the blacklist
    run bash -c "modprobe --showconfig | grep ^blacklist | grep -q $module_name"
    if [ $status -eq 0 ]; then
        skip "module: $module_name is deny listed"
    fi
}

# 3.1.6 Ensure TIPC is disabled (Automated)
@test "3.1.6 Ensure TIPC is disabled (Automated)" {
    # set module to check
    local module_name='tipc'

    # check if module is not exists
    run bash -c "modprobe -n -v $module_name"
    assert_output --partial "modprobe: FATAL: Module $module_name not found in directory"
    assert_failure

    # check if module is not loaded
    run bash -c "lsmod 2>/dev/null | grep -q $module_name"
    assert_failure

    # check if module is in the blacklist
    run bash -c "modprobe --showconfig | grep ^blacklist | grep -q $module_name"
    if [ $status -eq 0 ]; then
        skip "module: $module_name is deny listed"
    fi
}