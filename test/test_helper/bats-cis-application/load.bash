#!/bin/bash

# ================================================
# This script is a collection of functions to audit a Debian 11 system
# based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
# ================================================
# function is_app_installed is used to check if a package is installed
function is_app_installed(){
    pkg=$1 ; is=1 # false
    if [ ! -z $pkg ]; then
        is_installed=$(dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' $pkg 2>/dev/null | grep -Eq "$pkg\s*install\s*ok\s*installed\s*installed" && echo true || echo false)
        if [ $is_installed == "true" ] ; then
            is=0 # true
        fi
    fi
    # 0 = true // 1 = false
    return $is
}

# function is_app_not_installed is used to check if a package is not installed
function is_app_not_installed(){
    pkg=$1 ; is=1 # false
    if [ $(is_app_installed $pkg) ]; then
        is=0 # true
    fi
    # 0 = true // 1 = false
    return $is
}

# function is_app_enabled is used to check if a service is enabled
function is_app_enabled(){
    pkg=$1 ; is=1 # false
    if [ ! -z $pkg ]; then
        is_enabled=$(systemctl is-enabled $pkg.service 2>/dev/null | grep -q "enabled" && echo true || echo false)
        if [ $is_enabled == "true" ] ; then
            is=0 # true
        fi
    fi
    # 0 = true // 1 = false
    return $is
}

# function is_app_active is used to check if a service is active
function is_app_active(){
    pkg=$1 ; is=1 # false
    if [ ! -z $pkg ]; then
        is_active=$(systemctl is-active $pkg 2>/dev/null | grep -qE "^active" && echo true || echo false)
        if [ $is_active == "true" ]; then
            is=0 # true
        fi
    fi
    # 0 = true // 1 = false
    return $is
}

# function is_app_masked is used to check if a service is masked
function is_app_masked(){
    pkg=$1 ; is=1 # false
    if [ ! -z $pkg ]; then
        is_active=$(systemctl is-enabled $pkg 2>/dev/null | grep -qE "masked|disabled" && echo true || echo false)
        if [ $is_active == "true" ]; then
            is=0 # true
        fi
    fi
    # 0 = true // 1 = false
    return $is
}