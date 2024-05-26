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
    # load the firewall helper
    # this helper is used to check the status for a firewall
    load '../../test/test_helper/bats-cis-firewall/load'
    # load the network helper
    # this helper is used to check the status for a network
    load '../../test/test_helper/bats-cis-network/load'
}

# 3 Network Configuration
# ================================================
# test for 3.5 Firewall Configuration
# ================================================
# 3.5 Firewall Configuration
# 3.5.1 Configure Uncomplicated Firewall
# 3.5.1.1 Ensure ufw is installed (Automated)
@test "3.5.1.1 Ensure ufw is installed (Automated)" {
    # check if ufw is installed
    local pkg="ufw"
    run is_app_installed $pkg
    assert_success
}

# 3.5.1.2 Ensure iptables-persistent is not installed with ufw (Automated)
@test "3.5.1.2 Ensure iptables-persistent is not installed with ufw (Automated)" {
    # check if iptables-persistent is not installed
    local pkg="iptables-persistent"
    run is_app_installed $pkg
    assert_failure
}

# 3.5.1.3 Ensure ufw service is enabled (Automated)
@test "3.5.1.3 Ensure ufw service is enabled (Automated)" {
    # check if ufw service is enabled
    local pkg="ufw"
    run is_app_enabled $pkg
    assert_success

    # check if ufw is active
    run is_app_active $pkg
    assert_success    
}

# 3.5.1.4 Ensure ufw loopback traffic is configured (Automated)
@test "3.5.1.4 Ensure ufw loopback traffic is configured (Automated)" {
    # check if ufw service is installed and active
    local pkg="ufw"
    
    # check if ufw is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        # check that all other interfaces to deny traffic to the loopback network
        run bash -c "ufw status verbose"
        [[ "${lines[2]}" == *"Anywhere on lo"*"ALLOW IN"*"Anywhere"* ]]
        [[ "${lines[3]}" == *"Anywhere"*"DENY IN"*"127.0.0.0/8"* ]]
        [[ "${lines[4]}" == *"Anywhere (v6) on lo"*"ALLOW IN"*"Anywhere (v6)"* ]]
        [[ "${lines[5]}" == *"Anywhere (v6)"*"DENY IN"*"::1"* ]]
        [[ "${lines[7]}" == *"Anywhere"*"ALLOW OUT"*"Anywhere on lo"* ]]
        [[ "${lines[8]}" == *"Anywhere (v6)"*"ALLOW OUT"*"Anywhere (v6) on lo"* ]]
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.1.5 Ensure ufw outbound connections are configured (Manual)
@test "3.5.1.5 Ensure ufw outbound connections are configured (Manual)" {
    # check if ufw service is installed and active
    local pkg="ufw"
    
    # check if ufw is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        skip "verify all rules for new outbound connections match site policy: ufw status numbered"
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.1.6 Ensure ufw firewall rules exist for all open ports (Automated)
@test "3.5.1.6 Ensure ufw firewall rules exist for all open ports (Automated)" {
    # check if ufw service is installed and active
    local pkg="ufw"
    
    # check if ufw is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        # check if exists a missing firewall rules
        run is-missing-firewall-rules
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.1.7 Ensure ufw default deny firewall policy (Automated)
@test "3.5.1.7 Ensure ufw default deny firewall policy (Automated)" {
    # check if ufw service is installed and active
    local pkg="ufw"
    
    # check if ufw is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then  
        # check ufw default status
        run bash -c "ufw status verbose | grep -i '^Default:'"
        assert_output --partial "deny (incoming)"
        assert_output --partial "deny (outgoing)"
        assert_output --partial "disabled (routed)"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.2 Configure nftables
# 3.5.2.1 Ensure nftables is installed (Automated)
@test "3.5.2.1 Ensure nftables is installed (Automated)" {
    # check if ufw is installed
    local pkg="nftables"
    run is_app_installed $pkg
    assert_success
}

# 3.5.2.2 Ensure ufw is uninstalled or disabled with nftables (Automated)
@test "3.5.2.2 Ensure ufw is uninstalled or disabled with nftables (Automated)" {
    # verify that ufw is either not installed or inactive
    # set pkg name to check
    local pkg="ufw"
    
    # check if ufw is uninstalled or disabled
    run is_app_installed $pkg
    [[ ${status} -eq 1 ]] || [[ $(is_app_masked $pkg) -eq 0 ]]
}

# 3.5.2.3 Ensure iptables are flushed with nftables (Manual)
@test "3.5.2.3 Ensure iptables are flushed with nftables (Manual)" {
    skip "nftables is a replacement for iptables, ip6tables, ebtables and arptables. Ensure no iptables rules exist. run iptables -L"
}

# 3.5.2.4 Ensure a nftables table exists (Automated)
@test "3.5.2.4 Ensure a nftables table exists (Automated)" {
    # check if nftables service is installed and active
    local pkg="nftables"
    
    # check if nftables is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        # check if nftwables table exists
        run bash -c "nft list tables"
        assert_output --partial "nft list tables"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.2.5 Ensure nftables base chains exist (Automated)
@test "3.5.2.5 Ensure nftables base chains exist (Automated)" {
    # check if nftables service is installed and active
    local pkg="nftables"
    
    # check if nftables is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        # verify that base chains exist for INPUT
        run bash -c "nft list ruleset | grep 'hook input'"
        assert_output --partial "type filter hook input priority 0;"
        assert_success

        # verify that base chains exist for FORWARD
        run bash -c "nft list ruleset | grep 'hook forward'"
        assert_output --partial "type filter hook input forward 0;"
        assert_success

        # verify that base chains exist for OUTPUT
        run bash -c "nft list ruleset | grep 'hook output'"
        assert_output --partial "type filter hook output priority 0;"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.2.6 Ensure nftables loopback traffic is configured (Automated)
@test "3.5.2.6 Ensure nftables loopback traffic is configured (Automated)" {
    # check if nftables service is installed and active
    local pkg="nftables"
    
    # check if nftables is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        # verify that the loopback interface is configured
        run bash -c "nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'"
        assert_output --partial 'iif "lo" accept'
        assert_success

        run bash -c "nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'"
        assert_output --partial "ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop"
        assert_success

        # checks applied on IPv6
        if [ is_ipv6_enabled == true ]; then
            # verify that the IPv6 loopback interface is configured
            run bash -c "nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'"
            assert_output --partial "ip6 saddr ::1 counter packets 0 bytes 0 drop"
            assert_success
        fi
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.2.7 Ensure nftables outbound and established connections are configured (Manual)
@test "3.5.2.7 Ensure nftables outbound and established connections are configured (Manual)" {
    # check if nftables service is installed and active
    local pkg="nftables"
    
    # check if nftables is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        # verify all rules for established incoming connections match site policy: site policy
        run bash -c "nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'"
        assert_output --partial "ip protocol tcp ct state established accept"
        assert_output --partial "ip protocol udp ct state established accept"
        assert_output --partial "ip protocol icmp ct state established accept"
        assert_success

        # verify all rules for new and established outbound connections match site policy
        run bash -c "nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'"
        assert_output --partial "ip protocol tcp ct state established,related,new accept"
        assert_output --partial "ip protocol udp ct state established,related,new accept"
        assert_output --partial "ip protocol icmp ct state established,related,new accept"
        assert_success
    else
        skip "$pkg is not installed"
    fi 
}

# 3.5.2.8 Ensure nftables default deny firewall policy (Automated)
@test "3.5.2.8 Ensure nftables default deny firewall policy (Automated)" {
    # check if nftables service is installed and active
    local pkg="nftables"
    
    # check if nftables is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        # verify that base chains contain a policy of DROP
        run bash -c "nft list ruleset | grep 'hook input'"
        assert_output --partial "type filter hook input priority 0; policy drop;"
        assert_success

        run bash -c "nft list ruleset | grep 'hook forward'"
        assert_output --partial "type filter hook forward priority 0; policy drop;"
        assert_success

        run bash -c "nft list ruleset | grep 'hook output'"
        assert_output --partial "type filter hook output priority 0; policy drop;"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.2.9 Ensure nftables service is enabled (Automated)
@test "3.5.2.9 Ensure nftables service is enabled (Automated)" {
    # check if nftables service is enabled
    local pkg="nftables"
    run is_app_enabled $pkg
    assert_success
}

# 3.5.2.10 Ensure nftables rules are permanent (Automated)
@test "3.5.2.10 Ensure nftables rules are permanent (Automated)" {
    # check if nftables service is installed and active
    local pkg="nftables"
    
    # check if nftables is installed and active
    if (is_app_installed $pkg) && (is_app_active $pkg); then
        skip "review nftables persistent configurarion in /etc/nftables.conf"   
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.3 Configure iptables
# 3.5.3.1 Configure iptables software
# 3.5.3.1.1 Ensure iptables packages are installed (Automated)
@test "3.5.3.1.1 Ensure iptables packages are installed (Automated)" {
    # check if iptables service is installed
    local pkg="iptables"
    run is_app_enabled $pkg
    assert_success

    # check if iptables-persistent service is installed
    local pkg="iptables-persistent"
    run is_app_enabled $pkg
    assert_success
}

# 3.5.3.1.2 Ensure nftables is not installed with iptables (Automated)
@test "3.5.3.1.2 Ensure nftables is not installed with iptables (Automated)" {
    # check if nftables is not installed
    local pkg="nftables"
    run is_app_installed $pkg
    assert_failure
}

# 3.5.3.1.3 Ensure ufw is uninstalled or disabled with iptables (Automated)
@test "3.5.3.1.3 Ensure ufw is uninstalled or disabled with iptables (Automated)" {
    # set pkg name to check
    local pkg="ufw"
    
    # check if ufw is uninstalled or disabled
    run is_app_installed $pkg
    [[ ${status} -eq 1 ]] || [[ $(is_app_masked $pkg) -eq 0 ]]
}

# 3.5.3.2 Configure IPv4 iptables
# 3.5.3.2.1 Ensure iptables default deny firewall policy (Automated)
@test "3.5.3.2.1 Ensure iptables default deny firewall policy (Automated)" {
    # check if iptables service is installed and active
    local pkg="iptables"
    
    # check if iptables is installed
    if (is_app_installed $pkg); then
        # verify iptables rules
        run bash -c "iptables -L"
        assert_output --partial "Chain INPUT (policy DROP)"
        assert_output --partial "Chain FORWARD (policy DROP)"
        assert_output --partial "Chain OUTPUT (policy DROP)"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.3.2.2 Ensure iptables loopback traffic is configured (Automated)
@test "3.5.3.2.2 Ensure iptables loopback traffic is configured (Automated)" {
    # check if iptables service is installed and active
    local pkg="iptables"
    
    # check if iptables is installed
    if (is_app_installed $pkg); then
        # check iptables loopback traffic config
        # check iptables chain INPUT
        run bash -c "iptables -L INPUT -v -n"
        assert_success
        [[ "$output" = *"ACCEPT"*"all"*"--"*"lo"*"*"*"0.0.0.0/0"*"0.0.0.0/0"* ]]
        [[ "$output" = *"DROP"*"all"*"--"*"*"*"*"*"127.0.0.0/8"*"0.0.0.0/0"* ]]

        # check iptables chain OUTPUT
        run bash -c "iptables -L OUTPUT -v -n"
        assert_success
        [[ "$output" = *"ACCEPT"*"all"*"--"*"*"*"lo"*"0.0.0.0/0"*"0.0.0.0/0"* ]]
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.3.2.3 Ensure iptables outbound and established connections are configured (Manual)
@test "3.5.3.2.3 Ensure iptables outbound and established connections are configured (Manual)" {
    skip "verify all rules for new outbound, and established connections match site policy. Run iptables -L -v -n"
}

# 3.5.3.2.4 Ensure iptables firewall rules exist for all open ports (Automated)
@test "3.5.3.2.4 Ensure iptables firewall rules exist for all open ports (Automated)" {
    # check if iptables service is installed
    local pkg="iptables"
    
    # check if iptables is installed
    if (is_app_installed $pkg); then
        skip "determine open ports. Run ss -4tuln. Determine firewall rules. Run iptables -L INPUT -v -n"
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.3.3 Configure IPv6 ip6tables
# 3.5.3.3.1 Ensure ip6tables default deny firewall policy (Automated)
@test "3.5.3.3.1 Ensure ip6tables default deny firewall policy (Automated)" {
    # check if ip6tables service is installed and active
    local pkg="ip6tables"
    
    # check if ip6tables is installed
    if (is_app_installed $pkg); then
        # verify iptables rules
        run bash -c "ip6tables -L"
        assert_output --partial "Chain INPUT (policy DROP)"
        assert_output --partial "Chain FORWARD (policy DROP)"
        assert_output --partial "Chain OUTPUT (policy DROP)"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 3.5.3.3.2 Ensure ip6tables loopback traffic is configured (Automated)
@test "3.5.3.3.2 Ensure ip6tables loopback traffic is configured (Automated)" {
    # check if ip6tables service is installed and active
    local pkg="ip6tables"
    
    # check if ip6tables is installed
    if (is_app_installed $pkg); then
        # check ip6tables loopback traffic config
        # check ip6tables chain INPUT
        run bash -c "ip6tables -L INPUT -v -n"
        assert_success
        [[ "$output" = *"ACCEPT"*"all"*"lo"*"*"*"::/0"*"::/0"* ]]
        [[ "$output" = *"DROP"*"all"*"*"*"*"*"::1"*"::/0"* ]]

        # check ip6tables chain OUTPUT
        run bash -c "ip6tables -L OUTPUT -v -n"
        assert_success
        [[ "$output" = *"ACCEPT"*"all"*"*"*"lo"*"::/0"*"::/0"* ]]
    else
        skip "$pkg is not installed"
    fi 
}

# 3.5.3.3.3 Ensure ip6tables outbound and established connections are configured (Manual)
@test "3.5.3.3.3 Ensure ip6tables outbound and established connections are configured (Manual)" {
    # check if ip6tables service is installed and active
    local pkg="ip6tables"
    
    # check if ip6tables is installed
    if (is_app_installed $pkg); then
        skip "verify all rules for new outbound, and established connections match site policy. Run ip6tables -L -v -n"
    else
        skip "$pkg is not installed"
    fi 
}

# 3.5.3.3.4 Ensure ip6tables firewall rules exist for all open ports (Automated)
@test "3.5.3.3.4 Ensure ip6tables firewall rules exist for all open ports (Automated)" {
    skip "Determine open ports. Run ss -6tuln. Determine firewall rules. Run ip6tables -L INPUT -v -n"   
}