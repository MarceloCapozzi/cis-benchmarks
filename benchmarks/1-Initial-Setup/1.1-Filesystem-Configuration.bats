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
# tests for 1.1 Filesystem Configuration
# ================================================
# 1.1 Filesystem Configuration
# 1.1.1 Disable unused filesystems
# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)
@test "1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)" {
    # set module to check
    local module_name='cramfs'

    # check if module is not exists
    run bash -c "modprobe -n -v $module_name"
    assert_output --partial "modprobe: FATAL: Module $module_name not found in directory"
    assert_failure

    # check if module is not loaded
    run bash -c "lsmod 2>/dev/null | grep -q $module_name"
    assert_failure

    # check if module is in the blacklist
    run bash -c "modprobe --showconfig | grep ^blacklist | grep -q $module_name"
    if [ $status -eq 0 ]; then
        skip "module: $module_name is deny listed"
    fi
}

# 1.1.1.2 Ensure mounting of squashfs filesystems is disabled (Automated)
@test "1.1.1.2 Ensure mounting of squashfs filesystems is disabled (Automated)" {
    # set module to check
    local module_name='squashfs'

    # check if module is not exists
    run bash -c "modprobe -n -v $module_name"
    assert_output --partial "modprobe: FATAL: Module $module_name not found in directory"
    assert_failure

    # check if module is not loaded
    run bash -c "lsmod 2>/dev/null | grep -q $module_name"
    assert_failure

    # check if module is in the blacklist
    run bash -c "modprobe --showconfig | grep ^blacklist | grep -q $module_name"
    if [ $status -eq 0 ]; then
        skip "module: $module_name is deny listed"
    fi
}

# 1.1.1.3 Ensure mounting of udf filesystems is disabled (Automated)
@test "1.1.1.3 Ensure mounting of udf filesystems is disabled (Automated)" {
    # set module to check
    local module_name='udf'

    # check if module is not exists
    run bash -c "modprobe -n -v $module_name"
    assert_output --partial "modprobe: FATAL: Module $module_name not found in directory"
    assert_failure

    # check if module is not loaded
    run bash -c "lsmod 2>/dev/null | grep -q $module_name"
    assert_failure

    # check if module is in the blacklist
    run bash -c "modprobe --showconfig | grep ^blacklist | grep -q $module_name"
    if [ $status -eq 0 ]; then
        skip "module: $module_name is deny listed"
    fi
}

# 1.1.2 Configure /tmp
# 1.1.2.1 Ensure '/tmp' is a separate partition (Automated)
@test "1.1.2.1 Ensure '/tmp' is a separate partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name="/tmp"
        
        # check if partition is mounted
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${partition_name}"
        assert_success

        # check if partition is defined in /etc/fstab
        run bash -c "grep -q ^${partition_name} /etc/fstab"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.2.2 Ensure nodev option set on /tmp partition (Automated)
@test "1.1.2.2 Ensure nodev option set on /tmp partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/tmp'
        local mount_point_option='nodev'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.2.3 Ensure noexec option set on /tmp partition (Automated)
@test "1.1.2.3 Ensure noexec option set on /tmp partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/tmp'
        local mount_point_option='noexec'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.2.4 Ensure nosuid option set on /tmp partition (Automated)
@test "1.1.2.4 Ensure nosuid option set on /tmp partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/tmp'
        local mount_point_option='nosuid'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.3 Configure /var
# 1.1.3.1 Ensure separate partition exists for /var (Automated)
@test "1.1.3.1 Ensure separate partition exists for /var (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var'
        
        # check if partition is mounted
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${partition_name}"
        assert_success

        # check if partition is defined in /etc/fstab
        run bash -c "grep -q ^${partition_name} /etc/fstab"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.3.2 Ensure nodev option set on /var partition (Automated)
@test "1.1.3.2 Ensure nodev option set on /var partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var'
        local mount_point_option='nodev'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.3.3 Ensure nosuid option set on /var partition (Automated)
@test "1.1.3.3 Ensure nosuid option set on /var partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var'
        local mount_point_option='nosuid'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.4 Configure /var/tmp
# 1.1.4.1 Ensure separate partition exists for /var/tmp (Automated)
@test "1.1.4.1 Ensure separate partition exists for /var/tmp (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/tmp'
        
        # check if partition is mounted
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${partition_name}"
        assert_success

        # check if partition is defined in /etc/fstab
        run bash -c "grep -q ^${partition_name} /etc/fstab"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.4.2 Ensure noexec option set on /var/tmp partition (Automated)
@test "1.1.4.2 Ensure noexec option set on /var/tmp partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/tmp'
        local mount_point_option='noexec'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.4.3 Ensure nosuid option set on /var/tmp partition (Automated)
@test "1.1.4.3 Ensure nosuid option set on /var/tmp partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/tmp'
        local mount_point_option='nosuid'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.4.4 Ensure nodev option set on /var/tmp partition (Automated)
@test "1.1.4.4 Ensure nodev option set on /var/tmp partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/tmp'
        local mount_point_option='nodev'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.5 Configure /var/log
# 1.1.5.1 Ensure separate partition exists for /var/log (Automated)
@test "1.1.5.1 Ensure separate partition exists for /var/log (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/log'
        
        # check if partition is mounted
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${partition_name}"
        assert_success

        # check if partition is defined in /etc/fstab
        run bash -c "grep -q ^${partition_name} /etc/fstab"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.5.2 Ensure nodev option set on /var/log partition (Automated)
@test "1.1.5.2 Ensure nodev option set on /var/log partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/log'
        local mount_point_option='nodev'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.5.3 Ensure noexec option set on /var/log partition (Automated)
@test "1.1.5.3 Ensure noexec option set on /var/log partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/log'
        local mount_point_option='noexec'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.5.4 Ensure nosuid option set on /var/log partition (Automated)
@test "1.1.5.4 Ensure nosuid option set on /var/log partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/log'
        local mount_point_option='nosuid'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.6 Configure /var/log/audit
# 1.1.6.1 Ensure separate partition exists for /var/log/audit (Automated)
@test "1.1.6.1 Ensure separate partition exists for /var/log/audit (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/log/audit'
        
        # check if partition is mounted
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${partition_name}"
        assert_success

        # check if partition is defined in /etc/fstab
        run bash -c "grep -q ^${partition_name} /etc/fstab"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.6.2 Ensure noexec option set on /var/log/audit partition (Automated)
@test "1.1.6.2 Ensure noexec option set on /var/log/audit partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/log/audit'
        local mount_point_option='noexec'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.6.3 Ensure nodev option set on /var/log/audit partition (Automated)
@test "1.1.6.3 Ensure nodev option set on /var/log/audit partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/log/audit'
        local mount_point_option='nodev'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.6.4 Ensure nosuid option set on /var/log/audit partition (Automated)
@test "1.1.6.4 Ensure nosuid option set on /var/log/audit partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/var/log/audit'
        local mount_point_option='nosuid'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.7 Configure /home
# 1.1.7.1 Ensure separate partition exists for /home (Automated)
@test "1.1.7.1 Ensure separate partition exists for /home (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/home'
        
        # check if partition is mounted
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${partition_name}"
        assert_success

        # check if partition is defined in /etc/fstab
        run bash -c "grep -q ^${partition_name} /etc/fstab"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.7.2 Ensure nodev option set on /home partition (Automated)
@test "1.1.7.2 Ensure nodev option set on /home partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/home'
        local mount_point_option='nodev'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.7.3 Ensure nosuid option set on /home partition (Automated)
@test "1.1.7.3 Ensure nosuid option set on /home partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/home'
        local mount_point_option='nosuid'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.8 Configure /dev/shm
# 1.1.8.1 Ensure separate partition exists for /dev/shm (Automated)
@test "1.1.8.1 Ensure separate partition exists for /dev/shm (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/dev/shm'
        
        # check if partition is mounted
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${partition_name}"
        assert_success

        # check if partition is defined in /etc/fstab
        run bash -c "grep -q ^${partition_name} /etc/fstab"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.8.2 Ensure nodev option set on /dev/shm partition (Automated)
@test "1.1.8.2 Ensure nodev option set on /dev/shm partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/dev/shm'
        local mount_point_option='nodev'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.8.3 Ensure noexec option set on /dev/shm partition (Automated)
@test "1.1.8.3 Ensure noexec option set on /dev/shm partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/dev/shm'
        local mount_point_option='noexec'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.8.4 Ensure nosuid option set on /dev/shm partition (Automated)
@test "1.1.8.4 Ensure nosuid option set on /dev/shm partition (Automated)" {
    # set pkg name to check
    local pkg="findmnt2"

    # check if apps are installed
    if (is_app_installed $pkg); then
        # set partition to check
        local partition_name='/dev/shm'
        local mount_point_option='nosuid'
        
        # check mount point options
        run bash -c "findmnt2 -kn ${partition_name} | grep -q ${mount_point_option}"
        assert_success
    else
        skip "cannot perform check because $pkg is not installed"
    fi
}

# 1.1.9 Disable Automounting
# 1.1.9 Disable Automounting (Automated)
@test "1.1.9 Disable Automounting (Automated)" {
    # check if automounting is disabled
    run bash -c "systemctl is-enabled autofs | grep -q disabled"
    assert_success
}

# 1.1.10 Disable USB Storage (Automated)
@test "1.1.10 Disable USB Storage (Automated)" {
    # set module to check
    local module_name='usb-storage'

    # check if module is not exists
    run bash -c "modprobe -n -v $module_name"
    assert_output --partial "modprobe: FATAL: Module $module_name not found in directory"
    assert_failure

    # check if module is not loaded
    run bash -c "lsmod 2>/dev/null | grep -q $module_name"
    assert_failure

    # check if module is in the blacklist
    run bash -c "modprobe --showconfig | grep ^blacklist | grep -q $module_name"
    if [ $status -eq 0 ]; then
        skip "module: $module_name is deny listed"
    fi
}