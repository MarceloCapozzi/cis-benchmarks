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
    # load the audit helper
    # this helper is used to check the audit status
    load '../../test/test_helper/bats-cis-audit/load'
}

# Section: 4 Logging and Auditing
# ================================================
# test for 4.1 Configure System Accounting (auditd)
# ================================================
# 4.1 Configure System Accounting (auditd)
# 4.1.1 Ensure auditing is enabled
# 4.1.1.1 Ensure auditd is installed (Automated)
@test "4.1.1.1 Ensure auditd is installed (Automated)" {
    # set pkg name to check
    local pkg="auditd"

    # check if auditd is installed
    run is_app_installed $pkg
    assert_success

    # check if audispd-plugins is installed
    local pkg="audispd-plugins"
    run is_app_installed $pkg
    assert_success
}

# 4.1.1.2 Ensure auditd service is enabled and active (Automated)
@test "4.1.1.2 Ensure auditd service is enabled and active (Automated)" {
    # set pkg name to check
    local pkg="auditd"

    # check if auditd service is enabled
    run is_app_enabled $pkg
    assert_success

    # check if auditd is active
    run is_app_active $pkg
    assert_success      
}

# 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)
@test "4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then
        # verify grub.cfg audit configuration
        run bash -c "find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + 2>/dev/null | grep -v 'audit=1'"
        assert_success
    else
        skip "$pkg is not installed"
    fi  
}

# 4.1.1.4 Ensure audit_backlog_limit is sufficient (Automated)
@test "4.1.1.4 Ensure audit_backlog_limit is sufficient (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then
        # verify the audit_backlog_limit= parameter is set
        run bash -c "find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + 2>/dev/null | grep -Pv 'audit_backlog_limit=\d+\b'"
        assert_success
    else
        skip "$pkg is not installed"
    fi  
}

# 4.1.2 Configure Data Retention
# 4.1.2.1 Ensure audit log storage size is configured (Automated)
@test "4.1.2.1 Ensure audit log storage size is configured (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then
        run bash -c "grep -Poq -- '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf"
        assert_success
    else
        skip "$pkg is not installed"
    fi    
}

# 4.1.2.2 Ensure audit logs are not automatically deleted (Automated)
@test "4.1.2.2 Ensure audit logs are not automatically deleted (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then
        run bash -c "grep -q 'max_log_file_action = keep_logs' /etc/audit/auditd.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi    
}

# 4.1.2.3 Ensure system is disabled when audit logs are full (Automated)
@test "4.1.2.3 Ensure system is disabled when audit logs are full (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then
        # verify output matchesverify output matches
        run bash -c 'grep "space_left_action = email" /etc/audit/auditd.conf 2>/dev/null'
        assert_success

        # verify the output is either halt or single
        run bash -c "grep -Eq 'admin_space_left_action\s*=\s*(halt|single)'"
        assert_success
    else
        skip "$pkg is not installed"
    fi  
}

# 4.1.3 Configure auditd rules
# 4.1.3.1 Ensure changes to system administration scope (sudoers) is collected (Automated)
@test "4.1.3.1 Ensure changes to system administration scope (sudoers) is collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then
        # check on disk rules
        run ensure_changes_to_system_administration_scope_is_collected
        assert_output --partial "-w /etc/sudoers -p wa -k scope"
        assert_output --partial "-w /etc/sudoers.d -p wa -k scope"
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.2 Ensure actions as another user are always logged (Automated)
@test "4.1.3.2 Ensure actions as another user are always logged (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64)
                # check if actions as another user are logged
                run ensure_actions_as_another_user_are_always_logged
                assert_output --partial "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k"
                ;;
            i386)
                # check if actions as another user are logged
                run is_actions_as_another_user_are_always_logged
                assert_output --partial "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.3 Ensure events that modify the sudo log file are collected (Automated)
@test "4.1.3.3 Ensure events that modify the sudo log file are collected (Automated)" {
    # check if events that modify the sudo log file are collected
    run ensure_events_that_modify_the_sudo_log_file_are_collected
    assert_output --partial "-w /var/log/sudo.log -p wa -k sudo_log_file"
}

# 4.1.3.4 Ensure events that modify date and time information are collected (Automated)
@test "4.1.3.4 Ensure events that modify date and time information are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64)
                run ensure_events_that_modify_date_and_time_information_are_collected
                assert_output --partial "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change"
                assert_output --partial "-w /etc/localtime -p wa -k time-change"
                ;;
            i386)
                run ensure_events_that_modify_date_and_time_information_are_collected
                assert_output --partial "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change"
                assert_output --partial "-w /etc/localtime -p wa -k time-change"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.5 Ensure events that modify the system's network environment are collected (Automated)
@test "4.1.3.5 Ensure events that modify the system's network environment are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64)
                run ensure_events_that_modify_the_systems_network_environment_are_collected
                assert_output --partial "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"
                assert_output --partial "-w /etc/issue -p wa -k system-locale"
                assert_output --partial "-w /etc/issue.net -p wa -k system-locale"
                assert_output --partial "-w /etc/hosts -p wa -k system-locale"
                assert_output --partial "-w /etc/networks -p wa -k system-locale"
                assert_output --partial "-w /etc/network/ -p wa -k system-locale"
                ;;
            i386)
                run ensure_events_that_modify_the_systems_network_environment_are_collected
                assert_output --partial "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale"
                assert_output --partial "-w /etc/issue -p wa -k system-locale"
                assert_output --partial "-w /etc/issue.net -p wa -k system-locale"
                assert_output --partial "-w /etc/hosts -p wa -k system-locale"
                assert_output --partial "-w /etc/networks -p wa -k system-locale"
                assert_output --partial "-w /etc/network/ -p wa -k system-locale"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.6 Ensure use of privileged commands are collected (Automated)
@test "4.1.3.6 Ensure use of privileged commands are collected (Automated)" {
    run ensure_use_of_privileged_commands_are_collected
    assert_output --partial "OK"
}

# 4.1.3.7 Ensure unsuccessful file access attempts are collected (Automated)
@test "4.1.3.7 Ensure unsuccessful file access attempts are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64)
                run ensure_unsuccessful_file_access_attempts_are_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access"
                assert_output --partial "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access"
                ;;
            i386)
                run ensure_unsuccessful_file_access_attempts_are_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access"
                assert_output --partial "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.8 Ensure events that modify user/group information are collected (Automated)
@test "4.1.3.8 Ensure events that modify user/group information are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64|i386)
                run ensure_events_that_modify_user_group_information_are_collected
                assert_output --partial "-w /etc/group -p wa -k identity"
                assert_output --partial "-w /etc/passwd -p wa -k identity"
                assert_output --partial "-w /etc/gshadow -p wa -k identity"
                assert_output --partial "-w /etc/shadow -p wa -k identity"
                assert_output --partial "-w /etc/security/opasswd -p wa -k identity"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi                
}

# 4.1.3.9 Ensure discretionary access control permission modification events are collected (Automated)
@test "4.1.3.9 Ensure discretionary access control permission modification events are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64)
                run ensure_discretionary_access_control_permission_modification_events_are_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod"
                assert_output --partial "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod"
                assert_output --partial "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod"
                ;;
            i386)
                run ensure_discretionary_access_control_permission_modification_events_are_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod"
                assert_output --partial "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod"
                assert_output --partial "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.10 Ensure successful file system mounts are collected (Automated)
@test "4.1.3.10 Ensure successful file system mounts are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64)
                run ensure_successful_file_system_mounts_are_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b64 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts"
                ;;
            i386)
                run ensure_successful_file_system_mounts_are_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b32 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.11 Ensure session initiation information is collected (Automated)
@test "4.1.3.11 Ensure session initiation information is collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64|i386)
                run ensure_session_initiation_information_is_collected
                assert_output --partial "-w /var/run/utmp -p wa -k session"
                assert_output --partial "-w /var/log/wtmp -p wa -k session"
                assert_output --partial "-w /var/log/btmp -p wa -k session"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.12 Ensure login and logout events are collected (Automated)
@test "4.1.3.12 Ensure login and logout events are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64|i386)
                run ensure_login_and_logout_events_are_collected
                assert_output --partial "-w /var/log/lastlog -p wa -k logins"
                assert_output --partial "-w /var/run/faillock -p wa -k logins"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.13 Ensure file deletion events by users are collected (Automated)
@test "4.1.3.13 Ensure file deletion events by users are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64)
                run ensure_file_deletion_events_by_users_are_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=${UID_MIN} -F auid!=unset -k delete"
                ;;
            i386)
                run ensure_file_deletion_events_by_users_are_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=${UID_MIN} -F auid!=unset -k delete"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.14 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)
@test "4.1.3.14 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64|i386)
                run ensure_events_that_modify_the_systems_mandatory_access_controls_are_collected
                assert_output --partial "-w /etc/apparmor/ -p wa -k MAC-policy"
                assert_output --partial "-w /etc/apparmor.d/ -p wa -k MAC-policy"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded (Automated)
@test "4.1.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64|i386)
                run ensure_successful_and_unsuccessful_attempts_to_use_the_chcon_command_are_recorded ${UID_MIN}
                assert_output --partial "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded (Automated)
@test "4.1.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64|i386)
                run ensure_successful_and_unsuccessful_attempts_to_use_the_setfacl_command_are_recorded ${UID_MIN}
                assert_output --partial "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)
@test "4.1.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64|i386)
                run ensure_successful_and_unsuccessful_attempts_to_use_the_chacl_command_are_recorded ${UID_MIN}
                assert_output --partial "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k priv_cmd"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated)
@test "4.1.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64|i386)
                run ensure_successful_and_unsuccessful_attempts_to_use_the_usermod_command_are_recorded ${UID_MIN}
                assert_output --partial "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.19 Ensure kernel module loading unloading and modification is collected (Automated)
@test "4.1.3.19 Ensure kernel module loading unloading and modification is collected (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        local UID_MIN="$(get_UID_min)"
        local arch=$(dpkg --print-architecture 2>/dev/null)
        # eval architecture type
        case $arch in
            amd64)
                run ensure_kernel_module_loading_unloading_and_modification_is_collected ${UID_MIN}
                assert_output --partial "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules"
                assert_output --partial "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules"
                ;;
            *) 
                skip "arch ($arch) is not supported"
                ;;
        esac
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.3.20 Ensure the audit configuration is immutable (Automated)
@test "4.1.3.20 Ensure the audit configuration is immutable (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run bash -c "grep -Ph -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules 2>/dev/null | tail -1"
        assert_success
        assert_output --partial "-e 2"
    else
        skip "$pkg is not installed"
    fi    
}

# 4.1.3.21 Ensure the running and on disk configuration is the same (Manual)
@test "4.1.3.21 Ensure the running and on disk configuration is the same (Manual)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run bash -c "augenrules --check"
        assert_success
        assert_output --partial "/usr/sbin/augenrules: No change"
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4 Configure auditd file access
# 4.1.4.1 Ensure audit log files are mode 0640 or less permissive (Automated)
@test "4.1.4.1 Ensure audit log files are mode 0640 or less permissive (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_audit_log_files_are_mode_0640_or_less_permissive
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.2 Ensure only authorized users own audit log files (Automated)
@test "4.1.4.2 Ensure only authorized users own audit log files (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_only_authorized_users_own_audit_log_files
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files (Automated)
@test "4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then
        # verify log_group parameter is set to either adm or root
        run bash -c "grep -Piw -- '^\h*log_group\h*=\h*(adm|root)\b' /etc/audit/auditd.conf 2>/dev/null"
        assert_success
        [[ "$output" = *"log_group = adm"* ]] || [[ "$output" = *"log_group = root"* ]]

        # determine if the audit log files are owned by the "root" or "adm" group
        run ensure_only_authorized_groups_are_assigned_ownership_of_audit_log_files
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.4 Ensure the audit log directory is 0750 or more restrictive (Automated)
@test "4.1.4.4 Ensure the audit log directory is 0750 or more restrictive (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_the_audit_log_directory_is_0750_or_more_restrictive
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.5 Ensure audit configuration files are 640 or more restrictive (Automated)
@test "4.1.4.5 Ensure audit configuration files are 640 or more restrictive (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_audit_configuration_files_are_640_or_more_restrictive
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.6 Ensure audit configuration files are owned by root (Automated)
@test "4.1.4.6 Ensure audit configuration files are owned by root (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_audit_configuration_files_are_owned_by_root
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.7 Ensure audit configuration files belong to group root (Automated)
@test "4.1.4.7 Ensure audit configuration files belong to group root (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_audit_configuration_files_belong_to_group_root
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.8 Ensure audit tools are 755 or more restrictive (Automated)
@test "4.1.4.8 Ensure audit tools are 755 or more restrictive (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_audit_tools_are_755_or_more_restrictive
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.9 Ensure audit tools are owned by root (Automated)
@test "4.1.4.9 Ensure audit tools are owned by root (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_audit_tools_are_owned_by_root
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.10 Ensure audit tools belong to group root (Automated)
@test "4.1.4.10 Ensure audit tools belong to group root (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run ensure_audit_tools_belong_to_group_root
        assert_success
        assert_output ""
    else
        skip "$pkg is not installed"
    fi
}

# 4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools (Automated)
@test "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools (Automated)" {
    # set pkg name to check
    local pkg="auditd"
    
    # check if auditd is installed
    if (is_app_installed $pkg); then  
        run bash -c "grep -Ps -- '(\/sbin\/(audit|au)\H*\b)' /etc/aide/aide.conf.d/*.conf /etc/aide/aide.conf 2>/dev/null"
        assert_success
        assert_output --partial "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512"
        assert_output --partial "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512"
        assert_output --partial "/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512"
        assert_output --partial "/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512"
        assert_output --partial "/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512"
        assert_output --partial "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512"
    else
        skip "$pkg is not installed"
    fi    
}