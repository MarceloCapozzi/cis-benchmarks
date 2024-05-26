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

# Section: 2 Services
# ================================================
# test for 2.3 Service Clients
# ================================================
# 2.3 Service Clients
# 2.3.1 Ensure NIS Client is not installed (Automated)
@test "2.3.1 Ensure NIS Client is not installed (Automated)" {
    # check if nis is not installed
    local pkg="nis"
    run is_app_installed $pkg
    assert_failure
}

# 2.3.2 Ensure rsh client is not installed (Automated)
@test "2.3.2 Ensure rsh client is not installed (Automated)" {
    # check if rsh-client is not installed
    local pkg="rsh-client"
    run is_app_installed $pkg
    assert_failure
}

# 2.3.3 Ensure talk client is not installed (Automated)
@test "2.3.3 Ensure talk client is not installed (Automated)" {
    # check if talk is not installed
    local pkg="talk"
    run is_app_installed $pkg
    assert_failure
}

# 2.3.4 Ensure telnet client is not installed (Automated)
@test "2.3.4 Ensure telnet client is not installed (Automated)" {
    # check if telnet is not installed
    local pkg="telnet"
    run is_app_installed $pkg
    assert_failure
}

# 2.3.5 Ensure LDAP client is not installed (Automated)
@test "2.3.5 Ensure LDAP client is not installed (Automated)" {
    # check if ldap-utils is not installed
    local pkg="ldap-utils"
    run is_app_installed $pkg
    assert_failure
}

# 2.3.6 Ensure RPC is not installed (Automated)
@test "2.3.6 Ensure RPC is not installed (Automated)" {
    # check if rpcbind is not installed
    local pkg="rpcbind"
    run is_app_installed $pkg
    assert_failure
}

# 2.4 Ensure nonessential services are removed or masked (Manual)
@test "2.4 Ensure nonessential services are removed or masked (Manual)" {
    # ensure that all services listed are required on the system. run 'ss -plntu'
    skip "this check must be done manually"
}