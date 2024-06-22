#!/bin/bash

# ================================================
# This script is a collection of functions to audit a Debian 11 system
# based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
# ================================================
# function is_ipv6_disabled is used to check if IPv6 is disabled
function is_ipv6_disabled(){
    ipv6_disable="ipv6.disable=1"
    grub_cdmline_linux="GRUB_CMDLINE_LINUX"
    grub_cfg_files="/boot/grub/menu.lst /boot/grub/grub.cfg /etc/default/grub /etc/grub.d/* /boot/grub2/grub.cfg"
    is_grub_ipv6_disable=$(grep -Rq ^$grub_cdmline_linux $grub_cfg_files 2>/dev/null | grep $ipv6_disable ; echo $?)
    is_sysctl_net_ipv6_conf_all_disable=$(sysctl net.ipv6.conf.all.disable_ipv6 | grep 'net.ipv6.conf.all.disable_ipv6 = 1' 1>/dev/null 2>/dev/null ; echo $?)
    is_sysctl_net_ipv6_default_disable=$(sysctl net.ipv6.conf.default.disable_ipv6 | grep 'net.ipv6.conf.default.disable_ipv6 = 1' 1>/dev/null 2>/dev/null ; echo $?)
    is_sysctl_net_ipv6_conf_lo_disable=$(sysctl net.ipv6.conf.lo.disable_ipv6 | grep 'net.ipv6.conf.lo.disable_ipv6 = 1' 1>/dev/null 2>/dev/null ; echo $?)
    is_disable=1
    if [ $is_grub_ipv6_disable ] || ( [ $is_sysctl_net_ipv6_conf_all_disable ] && [ $is_sysctl_net_ipv6_default_disable ] && [ $is_sysctl_net_ipv6_conf_lo_disable ]); then
        is_disable=0
    fi
    # Return 0 if IPv6 is disabled, 1 if it is enabled
    return $is_disable
}

# function is_ipv6_enabled is used to check if IPv6 is enabled
function is_ipv6_enabled(){
    is_enable=0
    if [ $(is_ipv6_disabled) ]; then
        is_enable=1
    fi
    # Return 0 if IPv6 is enabled, 1 if it is disabled
    return $is_enable
}

# function is-network-wireless-disabled is used to check if the wireless network is disabled
function is-network-wireless-disabled() {
    is=1 # Wireless is enabled
    if command -v nmcli >/dev/null 2>&1 ; then
        if nmcli radio all | grep -Eq '\s*\S+\s+disabled\s+\S+\s+disabled\b'; then
            echo "Wireless is not enabled"
        else 
            nmcli radio all
        fi
    elif [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
        t=0
        mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
        for dm in $mname; do
            if grep -Eq "^\s*install\s+$dm\s+/bin/(true|false)" /etc/modprobe.d/*.conf; then
                /bin/true
            else
                t=1
            fi
        done
        [ "$t" -eq 0 ] && is=0 # "Wireless is disabled"
    else
        is=0 # "Wireless is disabled"
    fi
}