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
# test for 2.2 Special Purpose Services
# ================================================
# 2.2 Special Purpose Services
# 2.2.1 Ensure X Window System is not installed (Automated)
@test "2.2.1 Ensure X Window System is not installed (Automated)" {
    # check if xserver-xorg is not installed
    local pkg="xserver-xorg*"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.2 Ensure Avahi Server is not installed (Automated)
@test "2.2.2 Ensure Avahi Server is not installed (Automated)" {
    # check if avahi-daemon is not installed
    local pkg="avahi-daemon"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.3 Ensure CUPS is not installed (Automated)
@test "2.2.3 Ensure CUPS is not installed (Automated)" {
    # check if cups is not installed
    local pkg="cups"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.4 Ensure DHCP Server is not installed (Automated)
@test "2.2.4 Ensure DHCP Server is not installed (Automated)" {
    # check if isc-dhcp-server is not installed
    local pkg="isc-dhcp-server"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.5 Ensure LDAP server is not installed (Automated)
@test "2.2.5 Ensure LDAP server is not installed (Automated)" {
    # check if slapd is not installed
    local pkg="slapd"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.6 Ensure NFS is not installed (Automated)
@test "2.2.6 Ensure NFS is not installed (Automated)" {
    # check if nfs-kernel-server is not installed
    local pkg="nfs-kernel-server"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.7 Ensure DNS Server is not installed (Automated)
@test "2.2.7 Ensure DNS Server is not installed (Automated)" {
    # check if bind9 is not installed
    local pkg="bind9"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.8 Ensure FTP Server is not installed (Automated)
@test "2.2.8 Ensure FTP Server is not installed (Automated)" {
    # check if vsftpd is not installed
    local pkg="vsftpd"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.9 Ensure HTTP server is not installed (Automated)
@test "2.2.9 Ensure HTTP server is not installed (Automated)" {
    # check if apache2 is not installed
    local pkg="apache2"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.10 Ensure IMAP and POP3 server are not installed (Automated)
@test "2.2.10 Ensure IMAP and POP3 server are not installed (Automated)" {
    # check if dovecot-imapd is not installed
    local pkg="dovecot-imapd"
    run is_app_installed $pkg
    assert_failure
    
    # check if dovecot-pop3d is not installed
    local pkg="dovecot-pop3d"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.11 Ensure Samba is not installed (Automated)
@test "2.2.11 Ensure Samba is not installed (Automated)" {
    # check if samba is not installed
    local pkg="samba"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.12 Ensure HTTP Proxy Server is not installed (Automated)
@test "2.2.12 Ensure HTTP Proxy Server is not installed (Automated)" {
    # check if squid is not installed
    local pkg="squid"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.13 Ensure SNMP Server is not installed (Automated)
@test "2.2.13 Ensure SNMP Server is not installed (Automated)" {
    # check if snmp is not installed
    local pkg="snmp"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.14 Ensure NIS Server is not installed (Automated)
@test "2.2.14 Ensure NIS Server is not installed (Automated)" {
    # check if nis is not installed
    local pkg="nis"
    run is_app_installed $pkg
    assert_failure
}

# 2.2.15 Ensure mail transfer agent is configured for local-only mode (Automated)
@test "2.2.15 Ensure mail transfer agent is configured for local-only mode (Automated)" {
    # check if MTA is not listening on any non-loopback address
    run bash -c "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'"
    assert_failure 1
    assert_output ""
}

# 2.2.16 Ensure rsync service is either not installed or masked (Automated)
@test "2.2.16 Ensure rsync service is either not installed or masked (Automated)" {
    # check if rsync is not installed
    local pkg="rsync"
    run is_app_installed $pkg
    assert_failure

    # check if rsync is not active
    run is_app_active $pkg
    assert_failure

    # check if rsync is masked
    run is_app_masked $pkg
    assert_success
}