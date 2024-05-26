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

# Section: 4 Logging and Auditing
# ================================================
# test for 4.2 Configure Logging
# ================================================
# 4.2.1 Configure journald
# 4.2.1.1 Ensure journald is configured to send logs to a remote log host
@test "4.2.1.1.1 Ensure systemd-journal-remote is installed (Automated)" {
    # check if systemd-journal-remote is installed
    local pkg="systemd-journal-remote"
    run is_app_installed $pkg
    assert_success
}

# 4.2.1.1.2 Ensure systemd-journal-remote is configured (Manual)
@test "4.2.1.1.2 Ensure systemd-journal-remote is configured (Manual)" {
    # set pkg name to check
    local pkg="systemd-journal-remote"
    
    # check if systemd-journal-remote is installed
    if (is_app_installed $pkg); then
        run bash -c 'grep -PE "^\s*URL=" /etc/systemd/journal-upload.conf'
        assert_output --regexp '^\s*URL='
        assert_success

        run bash -c 'grep -PE "^\s*ServerKeyFile=" /etc/systemd/journal-upload.conf'
        assert_output --regexp "^\s*ServerKeyFile="
        assert_success
        
        run bash -c 'grep -PE "^\s*ServerCertificateFile=" /etc/systemd/journal-upload.conf'
        assert_output --regexp "^\s*ServerCertificateFile="
        assert_success
        
        run bash -c 'grep -PE "^\s*TrustedCertificateFile=" /etc/systemd/journal-upload.conf'
        assert_output --regexp "^\s*TrustedCertificateFile="
        assert_success
    else
        skip "$pkg is not installed"
    fi    
}

# 4.2.1.1.3 Ensure systemd-journal-remote is enabled (Manual)
@test "4.2.1.1.3 Ensure systemd-journal-remote is enabled (Manual)" {
    # set pkg name to check
    local pkg="systemd-journal-remote" 
    
    # check if systemd-journal-remote is installed
    if (is_app_installed $pkg); then
        # set service name to check
        local service="systemd-journal-upload"

        # check if systemd-journal-remote is enabled
        run is_app_enabled $service
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 4.2.1.1.4 Ensure journald is not configured to recieve logs from a remote client (Automated)
@test "4.2.1.1.4 Ensure journald is not configured to recieve logs from a remote client (Automated)" {
    # set pkg name to check
    local pkg="systemd-journal-remote" 

    # check if systemd-journal-remote is installed
    if (is_app_installed $pkg); then
        # check if is not configured to receive logs from a remote client
        run bash -c "systemctl is-enabled $pkg.socket 2>/dev/null | grep -q disabled"
        assert_success
    else
        skip "$pkg is not installed"
    fi        
}

# 4.2.1.2 Ensure journald service is enabled (Automated)
@test "4.2.1.2 Ensure journald service is enabled (Automated)" {
    # set pkg name to check
    local pkg="systemd-journald" 
    
    # check if systemd-journal-remote is enabled
    run bash -c "systemctl is-enabled $pkg.service 2>/dev/null | grep -q static"
    assert_success
}

# 4.2.1.3 Ensure journald is configured to compress large log files (Automated)
@test "4.2.1.3 Ensure journald is configured to compress large log files (Automated)" {
    # set pkg name to check
    local pkg="systemd-journald" 

    # check if systemd-journald is installed
    if (is_app_installed $pkg); then
        # check if is configured to compress large log files
        run bash -c "grep -q '^\s*Compress=yes' /etc/systemd/journald.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 4.2.1.4 Ensure journald is configured to write logfiles to persistent disk (Automated)
@test "4.2.1.4 Ensure journald is configured to write logfiles to persistent disk (Automated)" {
    # set pkg name to check
    local pkg="systemd-journald" 

    # check if systemd-journald is installed
    if (is_app_installed $pkg); then
        # check if journald is configured to write logfiles to persistent disk
        run bash -c "grep -q '^\s*Storage=persistent' /etc/systemd/journald.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 4.2.1.5 Ensure journald is not configured to send logs to rsyslog (Manual)
@test "4.2.1.5 Ensure journald is not configured to send logs to rsyslog (Manual)" {
    # set pkg name to check
    local pkg="systemd-journald" 

    # check if systemd-journald is installed
    if (is_app_installed $pkg); then
        # check if journald is not configured to send logs to rsyslog
        run bash -c "grep -q ^\s*ForwardToSyslog /etc/systemd/journald.conf 2>/dev/null"
        assert_failure
    else
        skip "$pkg is not installed"
    fi
}

# 4.2.1.6 Ensure journald log rotation is configured per site policy (Manual)
@test "4.2.1.6 Ensure journald log rotation is configured per site policy (Manual)" {
    # review /etc/systemd/journald.conf and verify logs are rotated according to site policy
    skip "this check must be done manually"
}

# 4.2.1.7 Ensure journald default file permissions configured (Manual)
@test "4.2.1.7 Ensure journald default file permissions configured (Manual)" {
    # Ensure that log files have the correct permissions (0640) to ensure that sensitive data is archived and protected. More restrictive permissions such as 0600 is implicitly sufficient.
    skip "this check must be done manually"
}

# 4.2.2 Configure rsyslog
# 4.2.2.1 Ensure rsyslog is installed (Automated)
@test "4.2.2.1 Ensure rsyslog is installed (Automated)" {
    # set pkg name to check
    local pkg="rsyslog"

    # check if rsyslog is installed
    run is_app_installed $pkg
    assert_success
}

# 4.2.2.2 Ensure rsyslog service is enabled (Automated)
@test "4.2.2.2 Ensure rsyslog service is enabled (Automated)" {
    # set pkg name to check
    local pkg="rsyslog"

    # check if rsyslog is enabled
    run is_app_enabled $pkg
    assert_success
}

# 4.2.2.3 Ensure journald is configured to send logs to rsyslog (Manual)
@test "4.2.2.3 Ensure journald is configured to send logs to rsyslog (Manual)" {
    # set pkg name to check
    local pkg="systemd-journald" 

    # check if systemd-journald is installed
    if (is_app_installed $pkg); then
        run bash -c "grep -q '^\s*ForwardToSyslog=yes' /etc/systemd/journald.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 4.2.2.4 Ensure rsyslog default file permissions are configured (Automated)
@test "4.2.2.4 Ensure rsyslog default file permissions are configured (Automated)" {
    # set pkg name to check
    local pkg="systemd-journald" 

    # check if systemd-journald is installed
    if (is_app_installed $pkg); then
        run bash -c "grep -q '^\$FileCreateMode 0640'/etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 4.2.2.5 Ensure logging is configured (Manual)
@test "4.2.2.5 Ensure logging is configured (Manual)" {
    # review the contents of /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files to ensure appropriate logging is set
    skip "this check must be done manually"
}

# 4.2.2.6 Ensure rsyslog is configured to send logs to a remote log host (Manual)
@test "4.2.2.6 Ensure rsyslog is configured to send logs to a remote log host (Manual)" {
    # review the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files and verify that logs are sent to a central host
    skip "this check must be done manually"
}

# 4.2.2.7 Ensure rsyslog is not configured to receive logs from a remote client (Automated)
@test "4.2.2.7 Ensure rsyslog is not configured to receive logs from a remote client (Automated)" {
    # set pkg name to check
    local pkg="systemd-journald" 

    # check if systemd-journald is installed
    if (is_app_installed $pkg); then
        run bash -c "grep -q '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
        assert_success

        run bash -c "grep -q '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 4.2.3 Ensure all logfiles have appropriate permissions and ownership (Automated)
@test "4.2.3 Ensure all logfiles have appropriate permissions and ownership (Automated)" {
    skip "use 'get-permissions-and-ownership-to-logfiles' from ./helpers/logging to verify that files in /var/log/ have appropriate permissions"
}