#!/bin/bash

# ================================================
# This script is a collection of functions to audit a Debian 11 system
# based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
# ================================================
# 4.2.3 Ensure all logfiles have appropriate permissions and ownership
function get-permissions-and-ownership-to-logfiles(){
    echo -e "\n- Start check - logfiles have appropriate permissions and ownership"
    output=""
    find /var/log -type f | (while read -r fname; do
        bname="$(basename $fname 2>/dev/null)"
        case $bname in
            lastlog | lastlog.* | wtmp | wtmp.* | btmp | btmp.*)
                if ! stat -Lc "%a" "$fname" 2>/dev/null | grep -Pq --'^\h*[0,2,4,6][0,2,4,6][0,4]\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")"
                fi
                if ! stat -Lc "%U %G" "$fname" 2>/dev/null | grep -Pq --'^\h*root\h+(utmp|root)\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")"
                fi
            ;;
            secure | auth.log)
                if ! stat -Lc "%a" "$fname" 2>/dev/null | grep -Pq --'^\h*[0,2,4,6][0,4]0\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")"
                fi
                if ! stat -Lc "%U %G" "$fname" 2>/dev/null | grep -Pq --'^\h*(syslog|root)\h+(adm|root)\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")"
                fi
            ;;
            SSSD | sssd)
                if ! stat -Lc "%a" "$fname" 2>/dev/null | grep -Pq --'^\h*[0,2,4,6][0,2,4,6]0\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")"
                fi
                if ! stat -Lc "%U %G" "$fname" 2>/dev/null | grep -Piq --'^\h*(SSSD|root)\h+(SSSD|root)\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")"
                fi
            ;;
            gdm | gdm3)
                if ! stat -Lc "%a" "$fname" 2>/dev/null | grep -Pq --'^\h*[0,2,4,6][0,2,4,6]0\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")"
                fi
                if ! stat -Lc "%U %G" "$fname" 2>/dev/null | grep -Pq --'^\h*(root)\h+(gdm3?|root)\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")"
                fi
            ;;
            *.journal)
                if ! stat -Lc "%a" "$fname" 2>/dev/null | grep -Pq --'^\h*[0,2,4,6][0,4]0\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")"
                fi
                if ! stat -Lc "%U %G" "$fname" 2>/dev/null | grep -Pq --'^\h*(root)\h+(systemd-journal|root)\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc"%U:%G" "$fname")"
                fi
            ;;
            *)
                if ! stat -Lc "%a" "$fname" 2>/dev/null | grep -Pq --'^\h*[0,2,4,6][0,4]0\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")"
                fi
                if ! stat -Lc "%U %G" "$fname" 2>/dev/null | grep -Pq --'^\h*(syslog|root)\h+(adm|root)\h*$' 2>/dev/null; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")"
                fi
            ;;
        esac
    done
    
    # If all files passed, then we pass
    if [ -z "$output" ]; then
        echo -e "\n- PASS\n- All files in \"/var/log/\" have appropriate permissions and ownership\n"
    else
        # print the reason why we are failing
        echo -e "\n- FAIL:\n$output"
    fi
    # End check
    echo -e "- End check - logfiles have appropriate permissions and ownership\n"
    )
}