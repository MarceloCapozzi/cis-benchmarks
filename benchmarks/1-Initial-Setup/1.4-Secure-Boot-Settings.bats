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
}

# Section: 1 Initial Setup
# ================================================
# test for 1.4 Secure Boot Settings
# ================================================
# 1.4 Secure Boot Settings
# 1.4.1 Ensure bootloader password is set (Automated)
@test "1.4.1 Ensure bootloader password is set (Automated)" {
    # set grub cfg path
    local grub="/boot/grub/grub.cfg"

    # check if exists file
    if [ -f $grub ]; then
        # check grub config
        run bash -c "grep -q '^set superusers' $grub 2>/dev/null"
        assert_success

        # check grub passowrd config
        run bash -c "grep -q '^password' $grub 2>/dev/null"
        assert_success
    else
        skip "$grub is not exists"
    fi
}

# 1.4.2 Ensure permissions on bootloader config are configured (Automated)
@test "1.4.2 Ensure permissions on bootloader config are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/boot/grub/grub.cfg"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0644"
    # check if exists file
    if [ -f $file ]; then
        # check uid values
        run bash -c "stat -c '%u' $file | grep -q $uid"
        assert_success

        # check user values
        run bash -c "stat -c '%U' $file | grep -q $user"
        assert_success

        # check gid values
        run bash -c "stat -c '%g' $file | grep -q $gid"
        assert_success

        # check user values
        run bash -c "stat -c '%G' $file | grep -q $group"
        assert_success

        # check permissions in octal format
        run bash -c "stat -c '%a' $file | sed -E 's/^([0-9]{3})$/0\1/g' | grep -q $permission_bits_in_octal" 
        assert_success
    else
        skip "$file is not exists"
    fi
}

# 1.4.3 Ensure authentication required for single user mode (Automated)
@test "1.4.3 Ensure authentication required for single user mode (Automated)" {
    # check if a user has a password
    run bash -c "grep -Eq '^root:\$[0-9]' /etc/shadow 2>/dev/null"
    assert_failure
}