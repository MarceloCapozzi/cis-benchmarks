#!/bin/bash
# expand aliases
shopt -s expand_aliases
#
# This script is used to monitoring the base of operating system for vulnerabilities
# Based on the CIS Debian Linux 11 Benchmark v1.0.0 (09-22-2022)
# CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
# CIS Learn: https://learn.cisecurity.org/benchmarks
# bats-core docs: https://bats-core.readthedocs.io/en/stable/tutorial.html
# Author: Marcelo Capozzi (https://github.com/MarceloCapozzi)
# Date: 2024-05-25
#
# install bats
# new alias for bats
alias bats='./test/bats/bin/bats'
# set the permissions
chmod +x test/bats/bin/bats
chmod +x test/bats/libexec/bats-core/bats*
chmod +x test/test_helper/bats-*/*.bash

# Section: 1-Initial-Setup
bats benchmarks/1-Initial-Setup/1.1-Filesystem-Configuration.bats
bats benchmarks/1-Initial-Setup/1.2-Configure-Software-Updates.bats
bats benchmarks/1-Initial-Setup/1.3-Filesystem-Integrity-Checking.bats
bats benchmarks/1-Initial-Setup/1.4-Secure-Boot-Settings.bats
bats benchmarks/1-Initial-Setup/1.5-Additional-Process-Hardening.bats
bats benchmarks/1-Initial-Setup/1.6-Mandatory-Access-Control.bats
bats benchmarks/1-Initial-Setup/1.7-Command-Line-Warning-Banners.bats
bats benchmarks/1-Initial-Setup/1.8-GNOME-Display-Manager.bats

# Section: 2-Services
bats benchmarks/2-Services/2.1-Configure-Time-Synchronization.bats
bats benchmarks/2-Services/2.2-Special-Purpose-Services.bats
bats benchmarks/2-Services/2.3-Service-Clients.bats

# Section: 3-Network-Configuration
bats benchmarks/3-Network-Configuration/3.1-Disable-unused-network-protocols-and-devices.bats
bats benchmarks/3-Network-Configuration/3.2-Network-Parameters-Host-Only.bats
bats benchmarks/3-Network-Configuration/3.3-Network-Parameters-Host-and-Router.bats
bats benchmarks/3-Network-Configuration/3.5-Firewall-Configuration.bats

# Section: 4-Logging-and-Auditing
bats benchmarks/4-Logging-and-Auditing/4.1-Configure-System-Accounting-auditd.bats
bats benchmarks/4-Logging-and-Auditing/4.2-Configure-Logging.bats

# Section: 5-Access-Authentication-and-Authorization
bats benchmarks/5-Access-Authentication-and-Authorization/5.1-Configure-time-based-job-schedulers.bats
bats benchmarks/5-Access-Authentication-and-Authorization/5.2-Configure-SSH-Server.bats
bats benchmarks/5-Access-Authentication-and-Authorization/5.3-Configure-privilege-escalation.bats
bats benchmarks/5-Access-Authentication-and-Authorization/5.4-Configure-PAM.bats
bats benchmarks/5-Access-Authentication-and-Authorization/5.5-User-Accounts-and-Environment.bats

# Section: 6-System-Maintenance
bats benchmarks/6-System-Maintenance/6.1-System-File-Permissions.bats
bats benchmarks/6-System-Maintenance/6.2-Local-User-and-Group-Settings.bats