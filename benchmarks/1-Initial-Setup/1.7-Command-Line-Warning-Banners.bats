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
# test for 1.7 Command Line Warning Banners
# ================================================
# 1.7 Command Line Warning Banners
# 1.7.1 Ensure message of the day is configured properly (Automated)
@test "1.7.1 Ensure message of the day is configured properly (Automated)" {
    # check if motd is configured (/etc/motd)
    run bash -c "grep -Eis \"(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/motd"
    assert_failure
}

# 1.7.2 Ensure local login warning banner is configured properly (Automated)
@test "1.7.2 Ensure local login warning banner is configured properly (Automated)" {
    # check if login banner is configured (/etc/issue)
    run bash -c "grep -E -i \"(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue"
    assert_failure
}

# 1.7.3 Ensure remote login warning banner is configured properly (Automated)
@test "1.7.3 Ensure remote login warning banner is configured properly (Automated)" {
    # check if remote login banner is configured (/etc/issue.net)
    run bash -c "grep -E -i \"(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue.net"
    assert_failure
}

# 1.7.4 Ensure permissions on /etc/motd are configured (Automated)
@test "1.7.4 Ensure permissions on /etc/motd are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/motd"
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

# 1.7.5 Ensure permissions on /etc/issue are configured (Automated)
@test "1.7.5 Ensure permissions on /etc/issue are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/issue"
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

# 1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)
@test "1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/issue.net"
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