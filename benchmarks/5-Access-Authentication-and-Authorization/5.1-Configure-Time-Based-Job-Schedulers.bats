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

# Section: 5 Access, Authentication and Authorization
# ================================================
# test for 5.1 Configure time-based job schedulers
# ================================================
# 5.1 Configure time-based job schedulers
@test "5.1 Configure time-based job schedulers" {
    skip "if cron and at are not installed, this section can be skipped"
}

# 5.1.1 Ensure cron daemon is enabled and running (Automated)
@test "5.1.1 Ensure cron daemon is enabled and running (Automated)" {
    # set pkg name to check
    local pkg="cron"

    # check if cron is installed
    if (is_app_installed $pkg); then
        # check if cron is enabled
        run is_app_enabled $pkg
        assert_success

        # check if cron is active
        run is_app_active $pkg
        assert_success
    else
        skip "$pkg is not installed"
    fi   
}

# 5.1.2 Ensure permissions on /etc/crontab are configured (Automated)
@test "5.1.2 Ensure permissions on /etc/crontab are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/crontab"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0600"
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

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Automated)
@test "5.1.3 Ensure permissions on /etc/cron.hourly are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/cron.hourly"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0700"
    # check if exists file
    if [ -d $file ]; then
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

# 5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated)
@test "5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/cron.daily"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0700"
    # check if exists file
    if [ -d $file ]; then
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

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Automated)
@test "5.1.5 Ensure permissions on /etc/cron.weekly are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/cron.weekly"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0700"
    # check if exists file
    if [ -d $file ]; then
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

# 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Automated)
@test "5.1.6 Ensure permissions on /etc/cron.monthly are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/cron.monthly"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0700"
    # check if exists file
    if [ -d $file ]; then
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

# 5.1.7 Ensure permissions on /etc/cron.d are configured (Automated)
@test "5.1.7 Ensure permissions on /etc/cron.d are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/cron.d"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0700"
    # check if exists file
    if [ -d $file ]; then
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

# 5.1.8 Ensure cron is restricted to authorized users (Automated)
@test "5.1.8 Ensure cron is restricted to authorized users (Automated)" {
    # check if no exists file
    [[ ! -f /etc/cron.deny ]]

    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/cron.allow"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0640"
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

# 5.1.9 Ensure at is restricted to authorized users (Automated)
@test "5.1.9 Ensure at is restricted to authorized users (Automated)" {
    # check if no exists file
    [[ ! -f /etc/at.deny ]]

    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/at.allow"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0640"
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