#!/bin/bash

# ================================================
# This script is a collection of functions to audit a Debian 11 system
# based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
# ================================================
# 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group
function ensure_all_groups_in_passwdfile_exist_in_groupfile(){
    for i in $(cut -s -d: -f4 /etc/passwd 2>/dev/null | sort -u ); do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
        fi
    done
}

# 6.2.5 Ensure no duplicate UIDs exist
function ensure_no_duplicate_UIDs_exist(){
    cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
        [ -z "$x" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
            echo "Duplicate UID ($2): $users"
        fi
    done
}

# 6.2.6 Ensure no duplicate GIDs exist
function ensure_no_duplicate_GIDs_exist(){
    cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
        echo "Duplicate GID ($x) in /etc/group"
    done
}

# 6.2.7 Ensure no duplicate user names exist
function ensure_no_duplicate_user_names_exist(){
    cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r x; do
        echo "Duplicate login name $x in /etc/passwd"
    done
}

# 6.2.8 Ensure no duplicate group names exist
function ensure_no_duplicate_group_names_exist(){
    cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do
        echo "Duplicate group name $x in /etc/group"
    done
}

# 6.2.9 Ensure root PATH Integrity
function ensure_root_path_integrity(){
    RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
    echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory (::)"
    echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
    for x in $(echo "$RPCV" | tr ":" " "); do
        if [ -d "$x" ]; then
            ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"} $3 != "root" {print $9, "is not owned by root"} substr($1,6,1) != "-" {print $9, "is group writable"} substr($1,9,1) != "-" {print $9, "is world writable"}'
        else
            echo "$x is not a directory"
        fi
    done
}

# 6.2.11 Ensure local interactive user home directories exist
function ensure_local_interactive_user_home_directories_exist(){
    output=""
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        [ ! -d "$home" ] && output="$output\n - User \"$user\" home directory \"$home\" doesn't exist"
    done
    if [ -z "$output" ]; then
        echo -e "\n-PASSED: - All local interactive users have a home directory\n"
    else
        echo -e "\n- FAILED:\n$output\n"
    fi
    )
}

# 6.2.12 Ensure local interactive users own their home directories
function ensure_local_interactive_users_own_their_home_directories(){
    output=""
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        owner="$(stat -L -c "%U" "$home")"
        [ "$owner" != "$user" ] && output="$output\n - User \"$user\" home directory \"$home\" is owned by user \"$owner\""
    done
    if [ -z "$output" ]; then
        echo -e "\n-PASSED: - All local interactive users have a home directory\n"
    else
        echo -e "\n- FAILED:\n$output\n"
    fi
    )

}

# 6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive
function ensure_local_interactive_user_home_directories_are_mode_750_or_more_restrictive(){
    output=""
    perm_mask='0027'
    maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        if [ -d "$home" ]; then
            mode=$( stat -L -c '%#a' "$home" )
            [ $(( $mode & $perm_mask )) -gt 0 ] && output="$output\n- User $user home directory: \"$home\" is too permissive: \"$mode\" (should be: \"$maxperm\" or more restrictive)"
        fi
    done
    if [ -n "$output" ]; then
        echo -e "\n- FAILED:$output"
    else
        echo -e "\n- PASSED:\n- All user home directories are mode: \"$maxperm\" or more restrictive"
    fi
    )
 }

#6.2.14 Ensure no local interactive user has .netrc files
function ensure_no_local_interactive_user_has_netrc_files(){
    output="" output2=""
    perm_mask='0177'
    maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        if [ -f "$home/.netrc" ]; then
            mode="$( stat -L -c '%#a' "$home/.netrc" )"
            if [ $(( $mode & $perm_mask )) -gt 0 ]; then
                output="$output\n - User \"$user\" file: \"$home/.netrc\" is too permissive: \"$mode\" (should be: \"$maxperm\" or more restrictive)"
            else
                output2="$output2\n - User \"$user\" file: \"$home/.netrc\" exists and has file mode: \"$mode\" (should be: \"$maxperm\" or more restrictive)"
            fi
        fi
    done
    if [ -z "$output" ]; then
        if [ -z "$output2" ]; then
            echo -e "\n-PASSED: - No local interactive users have \".netrc\" files in their home directory\n"
        else
            echo -e "\n- WARNING:\n$output2\n"
        fi
    else
        echo -e "\n- FAILED:\n$output\n"
        [ -n "$output2" ] && echo -e "\n- WARNING:\n$output2\n"
    fi
    )
}

# 6.2.15 Ensure no local interactive user has .forward files
function ensure_no_local_interactive_user_has_forward_files(){
    output=""
    fname=".forward"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        [ -f "$home/$fname" ] && output="$output\n - User \"$user\" file: \"$home/$fname\" exists"
    done
    if [ -z "$output" ]; then
        echo -e "\n-PASSED: - No local interactive users have \"$fname\" files in their home directory\n"
    else
        echo -e "\n- FAILED:\n$output\n"
    fi
    )
}

# 6.2.16 Ensure no local interactive user has .rhosts files
function ensure_no_local_interactive_user_has_rhosts_files(){
    output=""
    fname=".rhosts"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        [ -f "$home/$fname" ] && output="$output\n - User \"$user\" file: \"$home/$fname\" exists"
    done
    if [ -z "$output" ]; then
        echo -e "\n-PASSED: - No local interactive users have \"$fname\" files in their home directory\n"
    else
        echo -e "\n- FAILED:\n$output\n"
    fi
    )
}

# 6.2.17 Ensure local interactive user dot files are not group or world writable
function ensure_local_interactive_user_dot_files_are_not_group_or_world_writable(){
    output=""
    perm_mask='0022'
    maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do
        for dfile in $(find "$home" -type f -name '.*'); do
            mode=$( stat -L -c '%#a' "$dfile" )
            [ $(( $mode & $perm_mask )) -gt 0 ] && output="$output\n- User $user file: \"$dfile\" is too permissive: \"$mode\" (should be: \"$maxperm\" or more restrictive)"
        done
    done
    if [ -n "$output" ]; then
        echo -e "\n- FAILED:$output"
    else
        echo -e "\n- PASSED:\n- All user home dot files are mode: \"$maxperm\" or more restrictive"
    fi
    )
}