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
# test for 3.3 Network Parameters (Host and Router)
# ================================================
# 3.3 Network Parameters (Host and Router)
# 3.3.1 Ensure source routed packets are not accepted (Automated)
@test "3.3.1 Ensure source routed packets are not accepted (Automated)" {
    # checks applied on IPv4
    # IPv4 - conf.all.accept_source_route
    run bash -c 'sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | grep -q "net.ipv4.conf.all.accept_source_route = 0"'
    assert_success

    # IPv4 - conf.default.accept_source_route
    run bash -c 'sysctl net.ipv4.conf.default.accept_source_route 2>/dev/null | grep -q "net.ipv4.conf.default.accept_source_route = 0"'
    assert_success
    
    # IPv4 - conf.all.accept_source_route
    run bash -c 'grep -qE "^net.ipv4.conf.all.accept_source_route\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success

    # IPv4 - conf.default.accept_source_route
    run bash -c 'grep -qE "^net.ipv4.conf.default.accept_source_route\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success

    # checks applied on IPv6
    if [ is_ipv6_disabled == false ]; then
        # IPv6 - conf.all.accept_source_route
        run bash -c 'sysctl net.ipv6.conf.all.accept_source_route 2>/dev/null | grep -q "net.ipv6.conf.all.accept_source_route = 0"'
        assert_success

        # IPv6 - conf.default.accept_source_route
        run bash -c 'sysctl net.ipv6.conf.default.accept_source_route 2>/dev/null | grep -q "net.ipv6.conf.default.accept_source_route = 0"'
        assert_success

        # IPv6 - conf.all.accept_source_route
        run bash -c 'grep -qE "^net.ipv6.conf.all.accept_source_route\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
        assert_success

        # IPv6 - conf.default.accept_source_route
        run bash -c 'grep -qE "^net.ipv6.conf.default.accept_source_route\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
        assert_success
    fi
}

# 3.3.2 Ensure ICMP redirects are not accepted (Automated)
@test "3.3.2 Ensure ICMP redirects are not accepted (Automated)" {
    # checks applied on IPv4
    # IPv4 - conf.all.accept_redirects
    run bash -c 'sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q "net.ipv4.conf.all.accept_redirects = 0"'
    assert_success

    # IPv4 - conf.default.accept_redirects
    run bash -c 'sysctl net.ipv4.conf.default.accept_redirects 2>/dev/null | grep -q "net.ipv4.conf.default.accept_redirects = 0"'
    assert_success

    # IPv4 - conf.all.accept_redirects
    run bash -c 'grep -qE "^net.ipv4.conf.all.accept_redirects\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success

    # IPv4 - conf.default.accept_redirects
    run bash -c 'grep -qE "^net.ipv4.conf.default.accept_redirects\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success

    # checks applied on IPv6
    if [ is_ipv6_disabled == false ]; then
        # IPv6 - conf.all.accept_redirects
        run bash -c 'sysctl net.ipv6.conf.all.accept_redirects 2>/dev/null | grep -q "net.ipv6.conf.all.accept_redirects = 0"'
        assert_success

        # IPv6 - conf.default.accept_redirects
        run bash -c 'sysctl net.ipv6.conf.default.accept_redirects 2>/dev/null | grep -q "net.ipv6.conf.default.accept_redirects = 0"'
        assert_success

        # IPv6 - conf.all.accept_redirects
        run bash -c 'grep -qE "^net.ipv6.conf.all.accept_redirects\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.
        conf /etc/sysctl.conf 2>/dev/null'
        assert_success

        # IPv6 - conf.default.accept_redirects
        run bash -c 'grep -qE "^net.ipv6.conf.default.accept_redirects\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.
        conf /etc/sysctl.conf 2>/dev/null'
        assert_success
    fi
}

# 3.3.3 Ensure secure ICMP redirects are not accepted (Automated)
@test "3.3.3 Ensure secure ICMP redirects are not accepted (Automated)" {
    # checks applied on IPv4
    # IPv4 - conf.default.secure_redirects
    run bash -c 'sysctl net.ipv4.conf.default.secure_redirects 2>/dev/null | grep -q "net.ipv4.conf.default.secure_redirects = 0"'
    assert_success

    # IPv4 - conf.all.secure_redirects
    run bash -c 'sysctl net.ipv4.conf.all.secure_redirects = 0 2>/dev/null | grep -q "net.ipv4.conf.all.secure_redirects = 0"'
    assert_success

    # IPv4 - conf.default.secure_redirects
    run bash -c 'grep -qE "^net.ipv4.conf.default.secure_redirects\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success

    # IPv4 - conf.all.secure_redirects
    run bash -c 'grep -qE "^net.ipv4.conf.all.secure_redirects\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success
}

# 3.3.4 Ensure suspicious packets are logged (Automated)
@test "3.3.4 Ensure suspicious packets are logged (Automated)" {
    # checks applied on IPv4
    # IPv4 - conf.all.log_martians
    run bash -c 'sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q "net.ipv4.conf.all.log_martians = 0"'
    assert_success
    
    # IPv4 - conf.default.log_martians
    run bash -c 'sysctl net.ipv4.conf.default.log_martians 2>/dev/null | grep -q "net.ipv4.conf.default.log_martians = 0"'
    assert_success

    # IPv4 - conf.all.log_martians
    run bash -c 'grep -qE "^net.ipv4.conf.all.log_martians\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success

    # IPv4 - conf.default.log_martians
    run bash -c 'grep -qE "^net.ipv4.conf.default.log_martians\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success
}

# 3.3.5 Ensure broadcast ICMP requests are ignored (Automated)
@test "3.3.5 Ensure broadcast ICMP requests are ignored (Automated)" {
    # checks applied on IPv4
    # IPv4 - icmp_echo_ignore_broadcasts
    run bash -c 'sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null | grep -q "net.ipv4.icmp_echo_ignore_broadcasts = 1"'
    assert_success

    # IPv4 - icmp_echo_ignore_broadcasts
    run bash -c 'grep -qE "^net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success
}

# 3.3.6 Ensure bogus ICMP responses are ignored (Automated)
@test "3.3.6 Ensure bogus ICMP responses are ignored (Automated)" {
    # checks applied on IPv4
    # IPv4 - icmp_ignore_bogus_error_responses
    run bash -c 'sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null | grep -q "net.ipv4.icmp_ignore_bogus_error_responses = 1"'
    assert_success

    # IPv4 - icmp_ignore_bogus_error_responses
    run bash -c 'grep -qE "^net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*1" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success
}

# 3.3.7 Ensure Reverse Path Filtering is enabled (Automated)
@test "3.3.7 Ensure Reverse Path Filtering is enabled (Automated)" {
    # checks applied on IPv4
    # IPv4 - conf.all.rp_filter
    run bash -c 'sysctl net.ipv4.conf.all.rp_filter 2>/dev/null | grep -q "net.ipv4.conf.all.rp_filter = 1"'
    assert_success

    # IPv4 - conf.all.rp_filter
    run bash -c 'grep -qE "^net.ipv4.conf.all.rp_filter\s*=\s*1" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success

    # IPv4 - conf.default.rp_filter
    run bash -c 'sysctl net.ipv4.conf.default.rp_filter 2>/dev/null | grep -q "net.ipv4.conf.default.rp_filter = 1"'
    assert_success

    # IPv4 - conf.default.rp_filter
    run bash -c 'grep -qE "^net.ipv4.conf.default.rp_filter\s*=\s*1" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success
}

# 3.3.8 Ensure TCP SYN Cookies is enabled (Automated)
@test "3.3.8 Ensure TCP SYN Cookies is enabled (Automated)" {
    # checks applied on IPv4
    # IPv4 - tcp_syncookies
    run bash -c 'sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q "net.ipv4.tcp_syncookies = 1"'
    assert_success

    # IPv4 - tcp_syncookies
    run bash -c 'grep -qE "^net.ipv4.tcp_syncookies\s*=\s*1" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
    assert_success
}

# 3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)
@test "3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)" {
    # checks applied on IPv6
    if [ is_ipv6_enabled == true ]; then
        # IPv6 - conf.all.accept_ra
        run bash -c 'sysctl net.ipv6.conf.all.accept_ra 2>/dev/null | grep -q "net.ipv6.conf.all.accept_ra= 0"'
        assert_success

        # IPv6 - conf.default.accept_ra
        run bash -c 'sysctl net.ipv6.conf.default.accept_ra 2>/dev/null | grep -q "net.ipv6.conf.default.accept_ra= 0"'
        assert_success

        # IPv6 - conf.all.accept_ra
        run bash -c 'grep -qE "^net.ipv6.conf.all.accept_ra\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
        assert_success

        # IPv6 - conf.default.accept_ra
        run bash -c 'grep -qE "^net.ipv6.conf.default.accept_ra\s*=\s*0" /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null'
        assert_success
    else
        skip "IPv6 is disable"
    fi 
}