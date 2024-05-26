#!/bin/bash

# ================================================
# This script is a collection of functions to audit a Debian 11 system
# based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
# ================================================
# 4.1.3.1 Ensure changes to system administration scope (sudoers) is collected
function ensure_changes_to_system_administration_scope_is_collected(){
    awk '/^ *-w/ && /\/etc\/sudoers/ && / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
}

# 4.1.3.2 Ensure actions as another user are always logged
function ensure_actions_as_another_user_are_always_logged(){
    awk '/^ *-a *always,exit/ && / -F *arch=b[2346]{2}/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && (/ -C *euid!=uid/||/ -C *uid!=euid/) && / -S *execve/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
}

# 4.1.3.3 Ensure events that modify the sudo log file are collected
function ensure_events_that_modify_the_sudo_log_file_are_collected(){
    SUDO_LOG_FILE_ESCAPED=$(grep -r logfile /etc/sudoers* 2>/dev/null | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g')
    [ -n "${SUDO_LOG_FILE_ESCAPED}" ] && awk "/^ *-w/ && /"${SUDO_LOG_FILE_ESCAPED}"/  / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"
}

# 4.1.3.4 Ensure events that modify date and time information are collected
function ensure_events_that_modify_date_and_time_information_are_collected(){
    awk '/^ *-a *always,exit/ && / -F *arch=b[2346]{2}/ && / -S/ && (/adjtimex/||/settimeofday/||/clock_settime/ ) && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
    awk '/^ *-w/ && /\/etc\/localtime/ && / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
}

# 4.1.3.5 Ensure events that modify the system's network environment are collected
function ensure_events_that_modify_the_systems_network_environment_are_collected(){
    awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ && (/sethostname/||/setdomainname/) && (/ key= *[!-~]* *$/|| / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
    awk '/^ *-w/ &&(/\/etc\/issue/||/\/etc\/issue.net/||/\/etc\/hosts/||/\/etc\/network/) && / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
}

# 4.1.3.6 Ensure use of privileged commands are collected
function ensure_use_of_privileged_commands_are_collected(){
    for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) 2>/dev/null | grep -Pv "noexec|nosuid" | awk '{print $1}') ; do
        for PRIVILEGED in $(find "${PARTITION}" -xdev -perm /6000 -type f); do
            grep -qr "${PRIVILEGED}" /etc/audit/rules.d 2>/dev/null && printf "OK: '${PRIVILEGED}' found in auditing rules.\n" || printf "Warning: '${PRIVILEGED}' not found in on disk configuration.\n"
        done
    done
}

function get_UID_min(){
    echo "$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"
}

# 4.1.3.7 Ensure unsuccessful file access attempts are collected
function ensure_unsuccessful_file_access_attempts_are_collected(){
    UID_MIN=$1
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && / -F *arch=b[2346]{2}/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -F *auid>=${UID_MIN}/ && (/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) && / -S/ && /creat/ && /open/ && /truncate/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.3.8 Ensure events that modify user/group information are collected
function ensure_events_that_modify_user_group_information_are_collected(){
    awk '/^ *-w/ && (/\/etc\/group/ ||/\/etc\/passwd/||/\/etc\/gshadow/||/\/etc\/shadow/||/\/etc\/security\/opasswd/) && / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
}

# 4.1.3.9 Ensure discretionary access control permission modification events are collected
function ensure_discretionary_access_control_permission_modification_events_are_collected(){
    UID_MIN=$1
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && / -F *arch=b[2346]{2}/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -S/ && / -F *auid>=${UID_MIN}/ && (/chmod/||/fchmod/||/fchmodat/||/chown/||/fchown/||/fchownat/||/lchown/||/setxattr/||/lsetxattr/||/fsetxattr/||/removexattr/||/lremovexattr/||/fremovexattr/) && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.3.10 Ensure successful file system mounts are collected
function ensure_successful_file_system_mounts_are_collected(){
    UID_MIN=$1
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && / -F *arch=b[2346]{2}/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -F *auid>=${UID_MIN}/ && / -S/ && /mount/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.3.11 Ensure session initiation information is collected
function ensure_session_initiation_information_is_collected(){
    awk '/^ *-w/ && (/\/var\/run\/utmp/||/\/var\/log\/wtmp/||/\/var\/log\/btmp/) && / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
}

# 4.1.3.12 Ensure login and logout events are collected
function ensure_login_and_logout_events_are_collected(){
    awk '/^ *-w/ && (/\/var\/log\/lastlog/||/\/var\/run\/faillock/) && / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
}

# 4.1.3.13 Ensure file deletion events by users are collected
function ensure_file_deletion_events_by_users_are_collected(){
    UID_MIN=$1
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && / -F *arch=b[2346]{2}/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -F *auid>=${UID_MIN}/ && / -S/ && (/unlink/||/rename/||/unlinkat/||/renameat/) && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.3.14 Ensure events that modify the system's Mandatory Access Controls are collected
function ensure_events_that_modify_the_systems_mandatory_access_controls_are_collected(){
    awk '/^ *-w/ && (/\/etc\/apparmor/||/\/etc\/apparmor.d/) && / +-p *wa/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
}

# 4.1.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded
function ensure_successful_and_unsuccessful_attempts_to_use_the_chcon_command_are_recorded(){
    UID_MIN=$1
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -F *auid>=${UID_MIN}/ && / -F *perm=x/ && / -F *path=\/usr\/bin\/chcon/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded
function ensure_successful_and_unsuccessful_attempts_to_use_the_setfacl_command_are_recorded(){
    UID_MIN=$1
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -F *auid>=${UID_MIN}/ && / -F *perm=x/ && / -F *path=\/usr\/bin\/setfacl/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded
function ensure_successful_and_unsuccessful_attempts_to_use_the_chacl_command_are_recorded(){
    UID_MIN=$1
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -F *auid>=${UID_MIN}/ && / -F *perm=x/ && / -F *path=\/usr\/bin\/chacl/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded
function ensure_successful_and_unsuccessful_attempts_to_use_the_usermod_command_are_recorded(){
    UID_MIN=$1
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -F *auid>=${UID_MIN}/ && / -F *perm=x/ && / -F *path=\/usr\/sbin\/usermod/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.3.19 Ensure kernel module loading unloading and modification is collected
function ensure_kernel_module_loading_unloading_and_modification_is_collected(){
    UID_MIN=$1
    awk '/^ *-a *always,exit/ && / -F *arch=b[2346]{2}/ && (/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) && / -S/ && (/init_module/ || /finit_module/ || /delete_module/ || /create_module/ || /query_module/) && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ && (/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) && / -F *auid>=${UID_MIN}/ && / -F *perm=x/ && / -F *path=\/usr\/bin\/kmod/ && (/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules 2>/dev/null || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

# 4.1.4.1 Ensure audit log files are mode 0640 or less permissive
function ensure_audit_log_files_are_mode_0640_or_less_permissive(){
    [ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f \( ! -perm 600 -a ! -perm 0400 -a ! -perm 0200 -a ! -perm 0000 -a ! -perm 0640 -a ! -perm 0440 -a ! -perm 0040 \) -exec stat -Lc "%n %#a" {} +
}

# 4.1.4.2 Ensure only authorized users own audit log files
function ensure_only_authorized_users_own_audit_log_files(){
    [ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec stat -Lc "%n %U" {} +
}

# 4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files
function ensure_only_authorized_groups_are_assigned_ownership_of_audit_log_files(){
    stat -c "%n %G" "$(dirname $(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf 2>/dev/null | xargs) 2>/dev/null )"/* | grep -Pv '^\h*\H+\h+(adm|root)\b'
}

# 4.1.4.4 Ensure the audit log directory is 0750 or more restrictive
function ensure_the_audit_log_directory_is_0750_or_more_restrictive(){
    stat -Lc "%n %a" "$(dirname $( awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf 2>/dev/null ) 2>/dev/null)" 2>/dev/null | grep -Pv -- '^\h*\H+\h+([0,5,7][0,5]0)'
}

# 4.1.4.5 Ensure audit configuration files are 640 or more restrictive
function ensure_audit_configuration_files_are_640_or_more_restrictive(){
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec stat -Lc "%n %a" {} + 2>/dev/null | grep -Pv -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$'
}

# 4.1.4.6 Ensure audit configuration files are owned by root
function ensure_audit_configuration_files_are_owned_by_root(){
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root 2>/dev/null
}

# 4.1.4.7 Ensure audit configuration files belong to group root
function ensure_audit_configuration_files_belong_to_group_root(){
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root 2>/dev/null
}

# 4.1.4.8 Ensure audit tools are 755 or more restrictive
function ensure_audit_tools_are_755_or_more_restrictive(){
    stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$'
}

# 4.1.4.9 Ensure audit tools are owned by root
function ensure_audit_tools_are_owned_by_root(){
    stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -Pv -- '^\h*\H+\h+root\h*$'
}

# 4.1.4.10 Ensure audit tools belong to group root
function ensure_audit_tools_belong_to_group_root(){
    stat -c "%n %a %U %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$'
}
