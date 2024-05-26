#!/bin/bash

# ================================================
# This script is a collection of functions to audit a Debian 11 system
# based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
# ================================================
# 3.5.1.6 Ensure ufw firewall rules exist for all open ports
function is-missing-firewall-rules(){
    is=1 # false
    ufw_out="$(ufw status verbose)"
    ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/::1/) {split($5, a, ":"); print a[2]}' | sort | uniq -u | while read -r lpn ;
    do
        ! grep -Pq "^\h*$lpn\b" <<< "$ufw_out" && is=0 ; echo "- Port: \"$lpn\" is missing a firewall rule"
    done
    # 0 = true // 1 = false
    return $is
}