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
# test for 2.1 Configure Time Synchronization
# ================================================
# 2.1 Configure Time Synchronization
# 2.1.1 Ensure time Synchronization is in Use
# 2.1.1.1 Ensure a single time synchronization daemon is in use (Automated)
@test "2.1.1.1 Ensure a single time synchronization daemon is in use (Automated)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"

    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # if at least one package is installed
    if (is_app_installed $pkg_chorny) || (is_app_installed $pkg_ntp); then
        # check if systemd-timesyncd is enabled
        run is_app_enabled $systemd_timesyncd
        assert_success
    else
        skip "$pkg_chorny and $pkg_ntp are not installed"
    fi
}

# 2.1.2 Configure chrony
# 2.1.2.1 Ensure chrony is configured with authorized timeserver (Manual)
@test "2.1.2.1 Ensure chrony is configured with authorized timeserver (Manual)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # only chory should be installed
    if (is_app_installed $pkg_chorny) && (is_app_enabled $systemd_timesyncd); then
        # at least one pool line
        run bash -c "grep -E '^pool' /etc/$pkg_chorny/*.conf 2>/dev/null | wc -l"
        [ $output -gt 0 ]        

        # at least three server lines are returned
        run bash -c "grep -E '^server' /etc/$pkg_chorny/*.conf 2>/dev/null | wc -l"
        [ $output -ge 3 ]
    else
        skip "$pkg_chorny is not installed"
    fi
}

# 2.1.2.2 Ensure chrony is running as user _chrony (Automated)
@test "2.1.2.2 Ensure chrony is running as user _chrony (Automated)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # only chory should be installed
    if (is_app_installed $pkg_chorny) && (is_app_enabled $systemd_timesyncd); then
        # check service execution user
        run bash -c "ps -ef 2>/dev/null | grep -q [c]hronyd"
        assert_success
    else
        skip "$pkg_chorny is not installed"
    fi
}

# 2.1.2.3 Ensure chrony is enabled and running (Automated)
@test "2.1.2.3 Ensure chrony is enabled and running (Automated)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # only chory should be enabled and running
    if (is_app_installed $pkg_chorny) && (is_app_enabled $systemd_timesyncd); then
        # check if chrory is enabled
        run is_app_enabled $pkg_chorny
        assert_success

        # check if chory is active
        run is_app_active $pkg_chorny
        assert_success
    else
        skip "$pkg_chorny is not installed"
    fi
}

# 2.1.3 Configure systemd-timesyncd
# 2.1.3.1 Ensure systemd-timesyncd configured with authorized timeserver (Manual)
@test "2.1.3.1 Ensure systemd-timesyncd configured with authorized timeserver (Manual)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # check if systemd timesyncd is installed
    if (is_app_installed $systemd_timesyncd); then
        # check systemd timesynd configuration
        run bash -c "grep -qEr '^(NTP|FallbackNTP)' /etc/systemd/ 2>/dev/null"
        assert_success
    else
        skip "$systemd_timesyncd is not installed"
    fi
}

# 2.1.3.2 Ensure systemd-timesyncd is enabled and running (Automated)
@test "2.1.3.2 Ensure systemd-timesyncd is enabled and running (Automated)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # check if systemd timesyncd is installed
    if (is_app_installed $systemd_timesyncd); then
         # check if systemd timesyncd is enabled
        run is_app_enabled $systemd_timesyncd
        assert_success

        # check if systemd timesyncd is active
        run is_app_active $systemd_timesyncd
        assert_success
    else
        skip "$systemd_timesyncd is not installed"
    fi
}

# 2.1.4 Configure NTP
# 2.1.4.1 Ensure ntp access control is configured (Automated)
@test "2.1.4.1 Ensure ntp access control is configured (Automated)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    # set ntp configuration
    local ntp_config="/etc/ntp.conf"
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # check if ntp is installed
    if (is_app_installed $pkg_ntp); then
        # at least two definitions of type restrict
        local count_restrict=$(grep '^restrict' $ntp_config 2>/dev/null | wc -l)
        if [ $count_restrict -eq 2 ]; then
            # check ntp configuration
            run bash -c "grep '^restrict' $ntp_config 2>/dev/null"
            assert_success
            assert_output --partial "default"
            assert_output --partial "kod"
            assert_output --partial "nomodify"
            assert_output --partial "notrap"
            assert_output --partial "nopeer"
            assert_output --partial "noquery"
        else
            skip "review config. output should show 2 lines of restrict"
        fi

    else
        skip "$pkg_ntp is not installed"
    fi
}

# 2.1.4.2 Ensure ntp is configured with authorized timeserver (Manual)
@test "2.1.4.2 Ensure ntp is configured with authorized timeserver (Manual)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # only ntp should be installed
    if (is_app_installed $pkg_ntp) && (is_app_enabled $systemd_timesyncd); then
        # at least one pool line
        run bash -c "grep -E '^pool' /etc/${pkg_ntp}.conf 2>/dev/null | wc -l"
        [ $output -gt 0 ]        

        # at least three server lines are returned
        run bash -c "grep -E '^server' /etc/${pkg_ntp}.conf 2>/dev/null | wc -l"
        [ $output -ge 3 ]
    else
        skip "$pkg_ntp is not installed"
    fi
}

# 2.1.4.3 Ensure ntp is running as user ntp (Automated)
@test "2.1.4.3 Ensure ntp is running as user ntp (Automated)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # only ntp should be installed
    if (is_app_installed $pkg_ntp) && (is_app_enabled $systemd_timesyncd); then
        # check service execution user
        run bash -c "ps -ef 2>/dev/null | grep -q [n]tpd"
        assert_success
    else
        skip "$pkg_ntp is not installed"
    fi
}

# 2.1.4.4 Ensure ntp is enabled and running (Automated)
@test "2.1.4.4 Ensure ntp is enabled and running (Automated)" {
    # set pkg name to check
    local pkg_chorny="chrony" ; local pkg_ntp="ntp" ; local systemd_timesyncd="systemd-timesyncd"
    
    # only one time synchronization method should be in use on the system
    if (is_app_installed $pkg_chorny) && (is_app_installed $pkg_ntp); then
        skip "review configuration. Only one time synchronization method should be in use on the system."   
    fi

    # only ntp should be enabled and running
    if (is_app_installed $pkg_ntp) && (is_app_enabled $systemd_timesyncd); then
        # check if ntp is enabled
        run is_app_enabled $pkg_ntp
        assert_success

        # check if ntp is active
        run is_app_active $pkpkg_ntpg_chorny
        assert_success
    else
        skip "$pkg_ntp is not installed"
    fi
}