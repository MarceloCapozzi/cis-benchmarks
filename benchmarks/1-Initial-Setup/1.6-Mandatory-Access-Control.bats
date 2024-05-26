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
# test for 1.6 Mandatory Access Control
# ================================================
# 1.6 Mandatory Access Control
# 1.6.1 Configure AppArmor
# 1.6.1.1 Ensure AppArmor is installed (Automated)
@test "1.6.1.1 Ensure AppArmor is installed (Automated)" {
    # check if apparmor is installed
    local pkg="apparmor"
    run is_app_installed $pkg
    assert_success

    # check if apparmor-utils is installed
    local pkg="apparmor-utils"
    run is_app_installed $pkg
    assert_success
}

# 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration (Automated)
@test "1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration (Automated)" {
    # set pkg name to check
    local pkg="apparmor"
    # check if apparmor is configured in bootloader
    if (is_app_installed $pkg); then
        run bash -c "grep '^\s*linux' /boot/grub/grub.cfg 2>/dev/null | grep -q $pkg=1"
        assert_success

        run bash -c "grep '^\s*linux' /boot/grub/grub.cfg 2>/dev/null | grep -q security=$pkg"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Automated)
@test "1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Automated)" {
    # set pkg name to check
    local pkg="apparmor"
    # check if apparmor-utils is installed
    if (is_app_installed $pkg); then
        # check command output format
        # avoid blank or incorrect values
        local is_valid_apparmor_profile_output="$(apparmor_status 2>/dev/null | grep -q 'profiles are loaded' && apparmor_status 2>/dev/null | grep -q 'profiles are in complain mode' && apparmor_status 2>/dev/null | grep -q 'profiles are in enforce mode' && echo true || echo false)"
        if [ $is_valid_apparmor_profile_output != true ]; then
            skip "profile output is not valid"
        fi
        
        # check if profiles is loaded
        run bash -c "apparmor_status 2>/dev/null | grep -Eq '^0 profiles are loaded'"
        assert_failure

        # check if empty profile complain mode
        local is_empty_profiles_complain_mode=$(apparmor_status 2>/dev/null | grep -q "^0 profiles are in complain mode" && echo true || echo false)
        
        # check if empty profile enforce mode
        local is_empty_profiles_enforce_mode=$(apparmor_status 2>/dev/null | grep -q "^0 profiles are in enforce mode" && echo true || echo false)

        # avoid empty profiles (complain and enfoces cannot be unconfigured)
        if [ $is_empty_profiles_complain_mode == true ] && [ $is_empty_profiles_enforce_mode ]; then
            skip "review apparmor profile configuration (complain or enforce). Both cannot be unconfigured"
        fi

        # check command output format
        # avoid blank or incorrect values
        local is_valid_apparmor_process_output="$(apparmor_status 2>/dev/null | grep -q 'processes have profiles defined' && apparmor_status 2>/dev/null | grep -q 'processes are in enforce mode' && apparmor_status 2>/dev/null | grep -q 'processes are in complain mode' && apparmor_status 2>/dev/null | grep -q 'processes are unconfined but have a profile defined' && echo true || echo false)"
        if [ $is_valid_apparmor_process_output != true ]; then
            skip "processes output is not valid"
        fi
        
        # check if exists unconfined process in application
        run bash -c "apparmor_status 2>/dev/null | grep 'processes are unconfined but have a profile defined' | grep -vq 0"
        assert_failure
    else
        skip "$pkg is not installed"
    fi
}