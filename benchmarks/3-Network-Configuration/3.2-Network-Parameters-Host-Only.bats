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
# test for 3.2 Network Parameters (Host Only)
# ================================================
# 3.2 Network Parameters (Host Only)
# 3.2.1 Ensure packet redirect sending is disabled (Automated)
@test "3.2.1 Ensure packet redirect sending is disabled (Automated)" {
    # checks applied on IPv4
    # check if packet redirect sending is disabled
    # IPv4 - conf.all.send_redirects
    run bash -c 'sysctl net.ipv4.conf.all.send_redirects 2>/dev/null | grep -q "net.ipv4.conf.all.send_redirects = 0"'
    assert_success

    # IPv4 - conf.default.send_redirects
    run bash -c 'sysctl net.ipv4.conf.default.send_redirects 2>/dev/null | grep -q "net.ipv4.conf.default.send_redirects = 0"'
    assert_success
    
    # IPv4 - conf.all.send_redirects
    run bash -c 'grep -qE "^net.ipv4.conf.all.send_redirects\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success

    # IPv4 - conf.default.send_redirects
    run bash -c 'grep -qE "^net.ipv4.conf.default.send_redirects\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success
}

# 3.2.2 Ensure IP forwarding is disabled (Automated)
@test "3.2.2 Ensure IP forwarding is disabled (Automated)" {
    # checks applied on IPv4
    # IPv4 - ip_forward
    run bash -c 'sysctl net.ipv4.ip_forward 2>/dev/null | grep -q "net.ipv4.ip_forward = 1"'
    assert_success
    
    # checks applied on IPv6
    # check IPv6 forwarding is disabled
    if [ is_ipv6_enabled == true ]; then
        # IPv6 - conf.all.forwarding
        run bash -c 'sysctl net.ipv6.conf.all.forwarding 2>/dev/null | grep -q "net.ipv6.conf.all.forwarding = 0"'
        assert_success
    fi
}