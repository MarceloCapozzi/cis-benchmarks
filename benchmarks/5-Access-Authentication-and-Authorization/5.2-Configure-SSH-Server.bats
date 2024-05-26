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

    # load the helpers
    # this helper is used to check the status for access
    load '../../test/test_helper/bats-cis-access/load'
    # load the application helper
    # this helper is used to check the status for an application
    load '../../test/test_helper/bats-cis-application/load'
}

# Section: 5 Access, Authentication and Authorization
# ================================================
# 5.2 Configure SSH server
# ================================================
# 5.2 Configure SSH server
# The recommendations in this section only apply if the SSH daemon is installed 
# on the system, if remote access is not required the SSH daemon can be 
# removed and this section skipped.
# 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)
@test "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)" {
    # set permissions values
    # user: root | uid: 0
    # group: root | gid: 0
    # permissions: 0400 = 400
    local file="/etc/ssh/sshd_config"
    local user="root"
    local group="root"
    local uid="0"
    local gid="0"
    local permission_bits_in_octal="0600"
    # check if exists file
    if [ -f $file ]; then
        # check uid values
        run bash -c "stat -c '%u' $file | grep -q $uid"
        assert_success

        # check user values
        run bash -c "stat -c '%U' $file | grep -q $user"
        assert_success

        # check gid values
        run bash -c "stat -c '%g' $file | grep -q $gid"
        assert_success

        # check user values
        run bash -c "stat -c '%G' $file | grep -q $group"
        assert_success

        # check permissions in octal format
        run bash -c "stat -c '%a' $file | sed -E 's/^([0-9]{3})$/0\1/g' | grep -q $permission_bits_in_octal" 
        assert_success
    else
        skip "$file is not exists"
    fi    
}

# 5.2.2 Ensure permissions on SSH private host key files are configured (Automated)
@test "5.2.2 Ensure permissions on SSH private host key files are configured (Automated)" {
    skip "use 'verify-ssh-keys-mode' from ./helpers/access to verify SSH private host key files are mode 0600 or more restrictive, owned be the root user, and owned be the group root or group designated to own openSSH private keys"
}

# 5.2.3 Ensure permissions on SSH public host key files are configured (Automated)
@test "5.2.3 Ensure permissions on SSH public host key files are configured (Automated)" {
    skip "verify Access does not grant write or execute permissions to group or other for all returned files. Run 'find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;'"
}

# 5.2.4 Ensure SSH access is limited (Automated)
@test "5.2.4 Ensure SSH access is limited (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH access is limited using policy access
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'"
        assert_success

        # check if return AllowUsers, AllowGroups, DenyUsers, DenyGroups
        [[ "${output}" = *"AllowUsers"* ]] || [[ "${output}" = *"AllowGroups"* ]] || [[ "${output}" = *"DenyUsers"* ]] || [[ "${output}" == *"DenyGroups"* ]]
    else
        skip "$pkg is not installed"
    fi         
}

# 5.2.5 Ensure SSH LogLevel is appropriate (Automated)
@test "5.2.5 Ensure SSH LogLevel is appropriate (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH LogLevel is appropiate (VERBOSE or INFO)
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq loglevel"
        assert_success

        # check if SSH LogLevel is appropiate (VERBOSE or INFO)
        [[ "${output}" = *"loglevel VERBOSE"* ]] || [[ "${output}" = *"loglevel INFO"* ]]

        # check if loglevel is configured (VERBOSE or INFO)
        run bash -c "grep -i 'loglevel' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -Eviq '(VERBOSE|INFO)'"
        assert_success
    else
        skip "$pkg is not installed"
    fi   
}

# 5.2.6 Ensure SSH PAM is enabled (Automated)
@test "5.2.6 Ensure SSH PAM is enabled (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH PAM is enabled
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'usepam yes'"
        assert_success

        # check if SSH PAM is enabled from sshd_config
        run bash -c "grep -Eiq '^\s*UsePAM\s+no' /etc/ssh/sshd_config"
        assert_failure
    else
        skip "$pkg is not installed"
    fi
}

# 5.2.7 Ensure SSH root login is disabled (Automated)
@test "5.2.7 Ensure SSH root login is disabled (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH root login is disabled
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'permitrootlogin no'"
        assert_success

        # check if check if SSH root login is disabled from sshd_config
        run bash -c "grep -Eiq '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi        
}

# 5.2.8 Ensure SSH HostbasedAuthentication is disabled (Automated)
@test "5.2.8 Ensure SSH HostbasedAuthentication is disabled (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH HostbasedAuthentication is disabled
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'hostbasedauthentication no'"
        assert_success

        # check if SSH HostbasedAuthentication is disabled from sshd_config
        run bash -c "grep -Eiq '^\s*HostbasedAuthentication\s+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_failure
    else
        skip "$pkg is not installed"
    fi
}

# 5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Automated)
@test "5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH PermitEmptyPasswords is disabled
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'permitemptypasswords no'"
        assert_success

        # check if SSH PermitEmptyPasswords is disabled from sshd_config
        run bash -c "grep -Eiq '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_failure
    else
        skip "$pkg is not installed"
    fi
}

# 5.2.10 Ensure SSH PermitUserEnvironment is disabled (Automated)
@test "5.2.10 Ensure SSH PermitUserEnvironment is disabled (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH PermitEmptyPasswords is disabled
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'permituserenvironment no'"
        assert_success

        # check if SSH PermitEmptyPasswords is disabled from sshd_config
        run bash -c "grep -Eiq '^\s*PermitUserEnvironment\s+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_failure
    else
        skip "$pkg is not installed"
    fi
}

# 5.2.11 Ensure SSH IgnoreRhosts is enabled (Automated)
@test "5.2.11 Ensure SSH IgnoreRhosts is enabled (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH IgnoreRhosts is enabled
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'ignorerhosts yes'"
        assert_success

        # check if SSH IgnoreRhosts is enabled from sshd_config
        run bash -c "grep -Eiq '^\s*ignorerhosts\s+no\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_failure
    else
        skip "$pkg is not installed"
    fi    
}

# 5.2.12 Ensure SSH X11 forwarding is disabled (Automated)
@test "5.2.12 Ensure SSH X11 forwarding is disabled (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH X11 forwarding is disabled
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'x11forwarding no'"
        assert_success

        # check if SSH X11 forwarding is disabled from sshd_config
        run bash -c "grep -Eiq '^\s*x11forwarding\s+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_failure
    else
        skip "$pkg is not installed"
    fi      
}

# 5.2.13 Ensure only strong Ciphers are used (Automated)
@test "5.2.13 Ensure only strong Ciphers are used (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check that only strong Ciphers are used
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -i ciphers"
        assert_success
        # verify that output does not contain any of the following weak ciphers
        [[ "${output}" != *"3des-cbc"* ]]
        [[ "${output}" != *"aes128-cbc"* ]]
        [[ "${output}" != *"aes192-cbc"* ]]
        [[ "${output}" != *"aes256-cbc"* ]]
    else
        skip "$pkg is not installed"
    fi        
}

# 5.2.14 Ensure only strong MAC algorithms are used (Automated)
@test "5.2.14 Ensure only strong MAC algorithms are used (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check that only strong MAC algorithms are used
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -i MACs"
        assert_success
        # verify that output does not contain any of the listed weak MAC algorithms
        [[ "${output}" != *"hmac-md5"* ]]
        [[ "${output}" != *"hmac-md5-96"* ]]
        [[ "${output}" != *"hmac-ripemd160"* ]]
        [[ "${output}" != *"hmac-sha1"* ]]
        [[ "${output}" != *"hmac-sha1-96"* ]]
        [[ "${output}" != *"umac-64@openssh.com"* ]]
        [[ "${output}" != *"umac-128@openssh.com"* ]]
        [[ "${output}" != *"hmac-md5-etm@openssh.com"* ]]
        [[ "${output}" != *"hmac-md5-96-etm@openssh.com"* ]]
        [[ "${output}" != *"hmac-ripemd160-etm@openssh.com"* ]]
        [[ "${output}" != *"hmac-sha1-etm@openssh.com"* ]]
        [[ "${output}" != *"hmac-sha1-96-etm@openssh.com"* ]]
        [[ "${output}" != *"umac-64-etm@openssh.com"* ]]
        [[ "${output}" != *"umac-128-etm@openssh.com"* ]]
    else
        skip "$pkg is not installed"
    fi 
}

# 5.2.15 Ensure only strong Key Exchange algorithms are used (Automated)
@test "5.2.15 Ensure only strong Key Exchange algorithms are used (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check that only strong Key Exchange algorithms are used
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep kexalgorithms"
        assert_success
        # verify that output does not contain any of the listed weak Key Exchange algorithms
        [[ "${output}" != *"diffie-hellman-group1-sha1"* ]]
        [[ "${output}" != *"diffie-hellman-group14-sha1"* ]]
        [[ "${output}" != *"diffie-hellman-group-exchange-sha1"* ]]
    else
        skip "$pkg is not installed"
    fi 
}

# 5.2.16 Ensure SSH AllowTcpForwarding is disabled (Automated)
@test "5.2.16 Ensure SSH AllowTcpForwarding is disabled (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH AllowTcpForwarding is disabled
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'allowtcpforwarding no'"
        assert_success

        # check if SSH AllowTcpForwarding is disabled  from sshd_config
        run bash -c "grep -Eiq '^\s*AllowTcpForwarding\s+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_failure
    else
        skip "$pkg is not installed"
    fi
}

# 5.2.17 Ensure SSH warning banner is configured (Automated)
@test "5.2.17 Ensure SSH warning banner is configured (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH warning banner is configured
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -iq 'banner /etc/issue.net'"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 5.2.18 Ensure SSH MaxAuthTries is set to 4 or less (Automated)
@test "5.2.18 Ensure SSH MaxAuthTries is set to 4 or less (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH warning banner is configured
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -Eiq '^\s*maxauthtries\s+([0-4])$'"
        assert_success

        # check if SSH warning banner is configured from sshd_config
        run bash -c "grep -Eiq '^\s*maxauthtries\s+([0-4])$' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 5.2.19 Ensure SSH MaxStartups is configured (Automated)
@test "5.2.19 Ensure SSH MaxStartups is configured (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH warning banner is configured
        # verify that output MaxStatups is 10:30:60 or more restrictive
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -i maxstartups | grep -Eiq '^\s*maxstartups\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))'"
        assert_success

        # check if SSH MaxStartups is configured from sshd_config
        # verify that output MaxStatups is 10:30:60 or more restrictive
        run bash -c "grep -Eivq '^\s*maxstartups\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}

# 5.2.20 Ensure SSH MaxSessions is set to 10 or less (Automated)
@test "5.2.20 Ensure SSH MaxSessions is set to 10 or less (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH MaxSessions is set to 10 or less
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -Eivq '^\s*MaxSessions\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)'"
        assert_success

        # check if SSH MaxSessions is set to 10 or less from sshd_config
        run bash -c "grep -Eivq '^\s*MaxSessions\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi  
}

# 5.2.21 Ensure SSH LoginGraceTime is set to one minute or less (Automated)
@test "5.2.21 Ensure SSH LoginGraceTime is set to one minute or less (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH LoginGraceTime is set to one minute or less
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -Eivq '^\s*LoginGraceTime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+|[^1]m)'"
        assert_success

        # check if SSH LoginGraceTime is set to one minute or less from sshd_config
        run bash -c "grep -Eivq '^\s*LoginGraceTime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+|[^1]m)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi  
}

# 5.2.22 Ensure SSH Idle Timeout Interval is configured (Automated)
@test "5.2.22 Ensure SSH Idle Timeout Interval is configured (Automated)" {
    # set pkg name to check
    local pkg="openssh-server"

    # check if openssh-server is installed
    if (is_app_installed $pkg); then
        # check if SSH LoginGraceTime is set to one minute or less
        run bash -c "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts 2>/dev/null | awk '{print $1}') | grep -Eiq '^\s*ClientAliveCountMax\s+(0|[4-9]|[1-9][0-9]+)\b'"
        assert_success

        # check if SSH LoginGraceTime is set to one minute or less from sshd_config
        run bash -c "grep -Eiq '^\s*ClientAliveCountMax\s+(0|[4-9]|[1-9][0-9]+)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        assert_success
    else
        skip "$pkg is not installed"
    fi
}