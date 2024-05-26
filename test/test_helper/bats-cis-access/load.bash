#!/bin/bash

# ================================================
# This script is a collection of functions to audit a Debian 11 system
# based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
# ================================================
# 5.2.2 Ensure permissions on SSH private host key files are configured (Automated)
function verify-ssh-keys-mode(){
    l_output=""
    l_skgn="ssh_keys" # Group designated to own openSSH keys
    l_skgid="$(awk -F: '($1 == "'"$l_skgn"'"){print $3}' /etc/group)"
    awk '{print}' <<< "$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -L -c "%n %#a %U %G %g" {} +)" | (while read -r l_file l_mode l_owner l_group l_gid ; do
        [ -n "$l_skgid" ] && l_cga="$l_skgn" || l_cga="root"
        [ "$l_gid" = "$l_skgid" ] && l_pmask="0137" || l_pmask="0177"
        l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
        [ $(( $l_mode $l_pmask )) -gt 0 ] && l_output="$l_output\n - File: \"$l_file\" is mode \"$l_mode\" should be mode: \"$l_maxperm\" or more restrictive"
        [ "$l_owner" != "root" ] && l_output="$l_output\n - File: \"$l_file\" is owned by: \"$l_owner\" should be owned by \"root\""
        if [ "$l_group" != "root" ] && [ "$l_gid" != "$l_skgid" ]; then
            l_output="$l_output\n - File: \"$l_file\" is owned by group \"$l_group\" should belong to group \"$l_cga\""
        fi
        done
    if [ -z "$l_output" ]; then
        echo -e "\n- Audit Result:\n *** PASS ***\n"
    else
        echo -e "\n- Audit Result:\n *** FAIL ***$l_output\n"
        exit 1
    fi
    )
}

# 5.4.5 Ensure all current passwords uses the configured hashing algorithm
function ensure_all_current_passwords_uses_the_configured_hashing_algorithm(){
    is_user_with_potencial_problems=0 # true
    declare -A HASH_MAP=( ["y"]="yescrypt" ["1"]="md5" ["2"]="blowfish" ["5"]="SHA256" ["6"]="SHA512" ["g"]="gost-yescrypt" ) 
    CONFIGURED_HASH=$(sed -n "s/^\s*ENCRYPT_METHOD\s*\(.*\)\s*$/\1/p" /etc/login.defs)
    for MY_USER in $(sed -n "s/^\(.*\):\\$.*/\1/p" /etc/shadow)
    do
        CURRENT_HASH=$(sed -n "s/${MY_USER}:\\$\(.\).*/\1/p" /etc/shadow)
        if [[ "${HASH_MAP["${CURRENT_HASH}"]^^}" != "${CONFIGURED_HASH^^}" ]]; then 
            echo "The password for '${MY_USER}' is using '${HASH_MAP["${CURRENT_HASH}"]}' instead of the configured '${CONFIGURED_HASH}'."
            is_user_with_potencial_problems=1 # false // user match with a potential problem algorithm 
        fi
    done
    # 0 = true // 1 = false
    return "$is_user_with_potencial_problems"
}

# 5.5.1.1 Ensure minimum days between password changes is configured
function is_valid_password_min_days_policy(){
    is=1 # false
    pass_min_days="$(grep '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk -F ' ' '{print $2}')"
    if [ $pass_min_days -gt 1 ]; then
        is=0 # true
    fi
    # 0 = true // 1 = false
    return $is
}

# 5.5.1.1 Ensure minimum days between password changes is configured
function ensure_minimum_days_between_password_changes_is_configured(){
    is_user_with_potencial_problems=1
    awk -F : '(/^[^:]+:[^!*]/ && $4 < 1){print $1 " " $4}' /etc/shadow 2>/dev/null | grep -q " "
    if [ $? -ne 0 ]; then
        is_user_with_potencial_problems=0
    fi
    # 0 = true // 1 = false
    return $is_user_with_potencial_problems
}

# 5.5.1.2 Ensure password expiration is 365 days or less
function is_valid_expiration_password_policy(){
    is=1 # false
    pass_max_days="$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk -F ' ' '{print $2}')"
    if [ $pass_max_days -gt 0 ] && [ $pass_max_days -lt 365 ]; then
        is=0 # true
    fi
    # 0 = true // 1 = false
    return $is
}

# 5.5.1.2 Ensure password expiration is 365 days or less
function ensure_password_expiration_is_365_days_or_less(){
    is_user_with_potencial_problems=1
    awk -F: '(/^[^:]+:[^!*]/ && ($5>365 || $5~/([0-1]|-1|\s*)/)){print $1 " " $5}' /etc/shadow 2>/dev/null | grep -q " "
    if [ $? -ne 0 ]; then
        is_user_with_potencial_problems=0
    fi
    # 0 = true // 1 = false
    return $is_user_with_potencial_problems
}

# 5.5.1.3 Ensure password expiration warning days is 7 or more
function is_valid_expiration_password_warning_policy(){
    is=1 # false
    pass_warn_age="$(grep '^PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk -F ' ' '{print $2}')"
    if [ $pass_warn_age -gt 7 ]; then
        is=0 # true
    fi
    # 0 = true // 1 = false
    return $is
}

# 5.5.1.3 Ensure password expiration warning days is 7 or more
function ensure_password_expiration_warning_days_is_7_or_more(){
    is_user_with_potencial_problems=1 # false
    awk -F: '(/^[^:]+:[^!*]/ && $6<7){print $1 " " $6}' /etc/shadow 2>/dev/null | grep -q " "
    if [ $? -ne 0 ]; then
        is_user_with_potencial_problems=0 # true
    fi
    # 0 = true // 1 = false
    return $is_user_with_potencial_problems
}

# 5.5.1.4 Ensure inactive password lock is 30 days or less
function is_valid_password_inactive_days_policy(){
    is=1 # false
    inactive_days="$(useradd -D 2>/dev/null | grep INACTIVE | awk -F '=' '{print $2}')"
    if [ $inactive_days -gt 0 ] && [ $inactive_days -lt 30 ]; then
        is=0 # true
    fi
    # 0 = true // 1 = false
    return $is
}

# 5.5.1.4 Ensure inactive password lock is 30 days or less
function ensure_inactive_password_lock_is_30_days_or_less(){
    is_user_with_potencial_problems=1 # false
    awk -F: '(/^[^:]+:[^!*]/ && ($7~/(\\s*$|-1)/ || $7>30)){print $1 " " $7}' /etc/shadow 2>/dev/null | grep -q " "
    if [ $? -ne 0 ]; then
        is_user_with_potencial_problems=0 # true
    fi
    # 0 = true // 1 = false
    return $is_user_with_potencial_problems
}

# 5.5.1.5 Ensure all users last password change date is in the past
function ensure_all_users_last_password_change_date_is_in_the_past(){
    awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow 2>/dev/null | while read -r usr; do
    change=$(date -d "$(chage --list $usr 2>/dev/null | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s);
    if [[ "$change" -gt "$(date +%s)" ]]; then
        echo "User: \"$usr\" last password change was \"$(chage --list $usr 2>/dev/null | grep '^Last password change' | cut -d: -f2)\""; 
    fi
    done
}

# 5.5.4 Ensure default user umask is 027 or more restrictive
function ensure_default_user_umask_is_027_or_more_restrictive(){
    passing=""
    grep -Eiq '^\s*UMASK\s+(0[0-7][2-7]7|[0-7][2-7]7)\b' /etc/login.defs && grep -Eqi '^\s*USERGROUPS_ENAB\s*"?no"?\b' /etc/login.defs && grep -Eq '^\s*session\s+(optional|requisite|required)\s+pam_umask\.so\b' /etc/pam.d/common-session && passing=true
    grep -REiq '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/profile* /etc/bash.bashrc* && passing=true
    [ "$passing" = true ] && echo "Default user umask is set"
}

# 5.5.5 Ensure default user shell timeout is 900 seconds or less
function ensure_default_user_shell_timeout_is_900_seconds_or_less(){
    output1="" output2=""
    [ -f /etc/bash.bashrc ] && BRC="/etc/bash.bashrc"
    for f in "$BRC" /etc/profile /etc/profile.d/*.sh ; do
        grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' "$f" && grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && grep -Pq '^\s*([^#]+;\s*)?export\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && output1="$f"
    done
    grep -Pq '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC" && output2=$(grep -Ps '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh $BRC)
    if [ -n "$output1" ] && [ -z "$output2" ]; then
        echo -e "\nPASSED\n\nTMOUT is configured in: \"$output1\"\n"
    else
        [ -z "$output1" ] && echo -e "\nFAILED\n\nTMOUT is not configured\n"
        [ -n "$output2" ] && echo -e "\nFAILED\n\nTMOUT is incorrectly configured in: \"$output2\"\n"
    fi
}