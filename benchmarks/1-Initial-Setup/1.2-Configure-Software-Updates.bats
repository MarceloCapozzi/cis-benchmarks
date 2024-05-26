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
}

# Section: 1 Initial Setup
# ================================================
# test for 1.2 Configure Software Updates
# ================================================
# 1.2 Configure Software Updates
# 1.2.1 Ensure package manager repositories are configured (Manual)
@test "1.2.1 Ensure package manager repositories are configured (Manual)" {
    # check package policy status
    # run: "apt-cache policy"
    skip "verify if package repositories policy are configured correctly"
}

# 1.2.2 Ensure GPG keys are configured (Manual)
@test "1.2.2 Ensure GPG keys are configured (Manual)" {
    # check if gpg keys are configured
    # run: "apt-key list"
    skip "verify if GPG keys are configured correctly for your package manager"
}