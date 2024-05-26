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

    # load the access helper
    # this helper is used to check the status for access
    load '../../test/test_helper/bats-cis-access/load'
}

# Section: 6 System Maintenance
# ================================================
# test for 6.1 System File Permissions
# ================================================
# 6.1 System File Permissions
# 6.1.1 Ensure permissions on /etc/passwd are configured (Automated)
@test "6.1.1 Ensure permissions on /etc/passwd are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/passwd"
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

# 6.1.2 Ensure permissions on /etc/passwd- are configured (Automated)
@test "6.1.2 Ensure permissions on /etc/passwd- are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/passwd-"
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

# 6.1.3 Ensure permissions on /etc/group are configured (Automated)
@test "6.1.3 Ensure permissions on /etc/group are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/group"
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

# 6.1.4 Ensure permissions on /etc/group- are configured (Automated)
@test "6.1.4 Ensure permissions on /etc/group- are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/group-"
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

# 6.1.5 Ensure permissions on /etc/shadow are configured (Automated)
@test "6.1.5 Ensure permissions on /etc/shadow are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/shadow"
    local user="root"
    local group="shadow"
    local uid="0"
    local gid="42"
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

# 6.1.6 Ensure permissions on /etc/shadow- are configured (Automated)
@test "6.1.6 Ensure permissions on /etc/shadow- are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/shadow-"
    local user="root"
    local group="shadow"
    local uid="0"
    local gid="42"
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

# 6.1.7 Ensure permissions on /etc/gshadow are configured (Automated)
@test "6.1.7 Ensure permissions on /etc/gshadow are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/gshadow"
    local user="root"
    local group="shadow"
    local uid="0"
    local gid="42"
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

# 6.1.8 Ensure permissions on /etc/gshadow- are configured (Automated)
@test "6.1.8 Ensure permissions on /etc/gshadow- are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/gshadow-"
    local user="root"
    local group="shadow"
    local uid="0"
    local gid="42"
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

# 6.1.9 Ensure no world writable files exist (Automated)
@test "6.1.9 Ensure no world writable files exist (Automated)" {
    # data in world-writable files can be modified and compromised by any user on the system.
    # world writable files may also indicate an incorrectly written script or program 
    # that could potentially be the cause of a larger compromise to the system's integrity
    run bash -c "df --local -P 2>/dev/null | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null"   
    assert_output ""
    assert_failure
}

# 6.1.10 Ensure no unowned files or directories exist (Automated)
@test "6.1.10 Ensure no unowned files or directories exist (Automated)" {
    # a new user who is assigned the deleted user's user ID or group ID may then end up 
    # "owning" these files, and thus have more access on the system than was intended
    run bash -c "df --local -P 2>/dev/null | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null"
    assert_output ""
    assert_failure
}

# 6.1.11 Ensure no ungrouped files or directories exist (Automated)
@test "6.1.11 Ensure no ungrouped files or directories exist (Automated)" {
    # A new user who is assigned the deleted user's user ID or group ID may then end up 
    # "owning" these files, and thus have more access on the system than was intended.
    run bash -c "df --local -P 2>/dev/null | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null"
    assert_output ""
    assert_failure
}

# 6.1.12 Audit SUID executables (Manual)
@test "6.1.12 Audit SUID executables (Manual)" {
    # it is important to identify and review such programs to ensure they are legitimate
    # review the files returned by the following execution: df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000"
    skip "this check must be done manually"
}

# 6.1.13 Audit SGID executables (Manual)
@test "6.1.13 Audit SGID executables (Manual)" {
    # check to see if system binaries have a different md5 checksum than what from the package.
    # this is an indication that the binary may have been replaced
    # review the files returned by the following execution: df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
    skip "this check must be done manually"
}