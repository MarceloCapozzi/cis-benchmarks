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
# test for 1.8 GNOME Display Manager
# ================================================
# 1.8 GNOME Display Manager
# 1.8.1 Ensure GNOME Display Manager is removed (Automated)
@test "1.8.1 Ensure GNOME Display Manager is removed (Automated)" {
    # check if apport is not installed
    local pkg="gdm3"
    run is_app_installed $pkg
    assert_failure
}

# 1.8.2 Ensure GDM login banner is configured (Automated)
@test "1.8.2 Ensure GDM login banner is configured (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        # check configuration values -> dconf/db
        run bash -c 'grep -qrE "^banner-message-enable=true" /etc/dconf/db/*.d/* 2>/dev/null'
        assert_success

        # check configuration values -> dconf/db
        run bash -c 'grep -qrE "^banner-message-text=.*$" /etc/dconf/db/*.d/* 2>/dev/null'
        assert_success
        
        # check configuration values -> dconf/profile
        run bash -c 'grep -qrE "^system-db:.*$" /etc/dconf/profile/* 2>/dev/null'
        assert_success

        # check configuration values -> dconf/db
        run bash -c 'ls /etc/dconf/db/*.d 2>/dev/null | grep -qE "$pkg_gdm|$pkg_gdm3"'
        assert_success

        # check configuration values -> dconf/db
        run bash -c "grep -qrE '[org/gnome/login-screen]' /etc/dconf/db/*.d/* 2>/dev/null"
        assert_success
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi
}

# 1.8.3 Ensure GDM disable-user-list option is enabled (Automated)
@test "1.8.3 Ensure GDM disable-user-list option is enabled (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        # check configuration values -> dconf/db
        run bash -c 'grep -qrE '^\s*disable-user-list\s*=\s*true\b' /etc/dconf/db 2>/dev/null'
        assert_success

        # check configuration values -> dconf/profile
        run bash -c 'grep -qrE "^system-db:.*$" /etc/dconf/profile/* 2>/dev/null'
        assert_success

        # check configuration values -> dconf/profile
        run bash -c 'ls /etc/dconf/profile/* 2>/dev/null | grep -qE "gdm|gdm3"'
        assert_success

        # check configuration values -> dconf/db
        run bash -c "grep -qrE '[org/gnome/login-screen]' /etc/dconf/db/*.d/* 2>/dev/null"
        assert_success
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi
}

# 1.8.4 Ensure GDM screen locks when the user is idle (Automated)
@test "1.8.4 Ensure GDM screen locks when the user is idle (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        local dconf_profile="/etc/dconf/db/*/"
        local idle_delay_max=900 # set for max value for idle-delay in seconds
        local lock_delay_max=5 # set for max value for lock-delay in seconds
        local idle_delay=$(grep -qrE idle-delay=uint32 $dconf_profile 2>/dev/null | awk -F " " '{print $2}')
        local lock_delay=$(grep -qrE lock-delay=uint32 $dconf_profile 2>/dev/null | awk -F " " '{print $2}')

        # check idle-delay configuration (between[1-900] ; 0 = deshabilitado)
        if [ $idle_delay -lt 1 ] || [ $idle_delay -gt $idle_delay_max ]; then
            skip "review idle-delay configuration"
        fi

        # check lock-delay configuration (between[0-5])
        if [ $lock_delay -lt 0 ] || [ $lock_delay -gt $lock_delay_max ]; then
            skip "review lock-delay configuration"
        fi

        # check configuration values -> dconf/profile
        run bash -c 'grep -qE "^system-db:.*$" /etc/dconf/profile/* 2>/dev/null'
        assert_success

        # check configuration values -> dconf/profile
        run bash -c 'ls /etc/dconf/profile/* 2>/dev/null | grep -qE "gdm|gdm3"'
        assert_success
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi
}

# 1.8.5 Ensure GDM screen locks cannot be overridden (Automated)
@test "1.8.5 Ensure GDM screen locks cannot be overridden (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        # check idle-delay session configuration
        run bash -c 'grep -qrE "/org/gnome/desktop/session/idle-delay" /etc/dconf/db/* 2>/dev/null'
        assert_success

        # check lock-delay configuration
        run bash -c 'grep -qrE "/org/gnome/desktop/session/lock-delay" /etc/dconf/db/* 2>/dev/null'
        assert_success
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi
}

# 1.8.6 Ensure GDM automatic mounting of removable media is disabled (Automated)
@test "1.8.6 Ensure GDM automatic mounting of removable media is disabled (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        # check automount configuration - dconf/db
        run bash -c "grep -qrE '^automount=true|^automount-open=true' /etc/dconf/db/*.d 2>/dev/null"
        assert_failure

        # check configuration values -> dconf/profile
        run bash -c 'grep -qrE "^system-db:.*$" /etc/dconf/profile/* 2>/dev/null'
        assert_success
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi    
}

# 1.8.7 Ensure GDM disabling automatic mounting of removable media is not overridden (Automated)
@test "1.8.7 Ensure GDM disabling automatic mounting of removable media is not overridden (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        # check automount configuration -> dconf/db
        run bash -c 'grep -qrE "/org/gnome/desktop/media-handling/automount" /etc/dconf/db/* 2>/dev/null'
        assert_success

        # check automount-open configuration -> dconf/db
        run bash -c 'grep -qrE "/org/gnome/desktop/media-handling/automount-open" /etc/dconf/db/* 2>/dev/null'
        assert_success
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi
}

# 1.8.8 Ensure GDM autorun-never is enabled (Automated)
@test "1.8.8 Ensure GDM autorun-never is enabled (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        # check autorun-never configuration -> dconf/db
        run bash -c 'grep -qrE "autorun-never=true" /etc/dconf/db/*.d 2>/dev/null'
        assert_success
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi
}

# 1.8.9 Ensure GDM autorun-never is not overridden (Automated)
@test "1.8.9 Ensure GDM autorun-never is not overridden (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        # check autorun-never configuration
        run bash -c 'grep -qrE "/org/gnome/desktop/media-handling/autorun-never" /etc/dconf/db/* 2>/dev/null'
        assert_success
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi
}

# 1.8.10 Ensure XDCMP is not enabled (Automated)
@test "1.8.10 Ensure XDCMP is not enabled (Automated)" {
    # set pkg name to check
    local pkg_gdm="gdm" ; local pkg_gdm3="gdm3"
    # check if apps are installed
    if (is_app_installed $pkg_gdm) || (is_app_installed $pkg_gdm3); then
        # check if gdm is not enabled
        run bash -c "grep -rqEis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf 2>/dev/null"
        assert_failure
    else
        skip "$pkg_gdm or $pkg_gdm3 is not installed"
    fi
}

# 1.9 Ensure updates, patches, and additional security software are installed (Manual)
@test "1.9 Ensure updates, patches, and additional security software are installed (Manual)" {
    # Verify there are no updates or patches to install: 'apt-get -s upgrade'
    skip "this check must be done manually"
}