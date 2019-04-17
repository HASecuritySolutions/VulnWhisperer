#!/usr/bin/env bash

NORMAL=$(tput sgr0)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)

function red() {
    echo -e "$RED$*$NORMAL"
}

function green() {
    echo -e "$GREEN$*$NORMAL"
}

function yellow() {
    echo -e "$YELLOW$*$NORMAL"
}

return_code=0

TEST_PATH=${TEST_PATH:-"tests/data"}

yellow "\n*********************************************"
yellow "* Test successful scan download and parsing *"
yellow "*********************************************"
rm -rf /opt/VulnWhisperer/*
if vuln_whisperer -F -c configs/test.ini --mock --mock_dir "${TEST_PATH}"; then
    green "\n✅ Passed: Test successful scan download and parsing"
else
    red "\n❌ Failed: Test successful scan download and parsing"
    ((return_code = return_code + 1))
fi

yellow "\n*********************************************"
yellow "*    Test run with no scans to import       *"
yellow "*********************************************"
if vuln_whisperer -F -c configs/test.ini --mock --mock_dir "${TEST_PATH}"; then
    green "\n✅ Passed: Test run with no scans to import"
else
    red "\n❌ Failed: Test run with no scans to import"
    ((return_code = return_code + 1))
fi

yellow "\n*********************************************"
yellow "*           Test one failed scan            *"
yellow "*********************************************"
rm -rf /opt/VulnWhisperer/*
yellow "Removing ${TEST_PATH}/nessus/GET_scans_exports_164_download"
mv "${TEST_PATH}/nessus/GET_scans_exports_164_download"{,.bak}
if vuln_whisperer -F -c configs/test.ini --mock --mock_dir "${TEST_PATH}"; [[ $? -eq 1 ]]; then
    green "\n✅ Passed: Test one failed scan"
else
    red "\n❌ Failed: Test one failed scan"
    ((return_code = return_code + 1))
fi

yellow "\n*********************************************"
yellow "*           Test two failed scans           *"
yellow "*********************************************"
rm -rf /opt/VulnWhisperer/*
yellow "Removing ${TEST_PATH}/qualys_vuln/scan_1553941061.87241"
mv "${TEST_PATH}/qualys_vuln/scan_1553941061.87241"{,.bak}
if vuln_whisperer -F -c configs/test.ini --mock --mock_dir "${TEST_PATH}"; [[ $? -eq 2 ]]; then
    green "\n✅ Passed: Test two failed scans"
else
    red "\n❌ Failed: Test two failed scans"
    ((return_code = return_code + 1))
fi

yellow "\n*********************************************"
yellow "*   Test only nessus with one failed scan   *"
yellow "*********************************************"
rm -rf /opt/VulnWhisperer/*
if vuln_whisperer -F -c configs/test.ini -s nessus --mock --mock_dir "${TEST_PATH}"; [[ $? -eq 1 ]]; then
    green "\n✅ Passed: Test only nessus with one failed scan"
else
    red "\n❌ Failed: Test only nessus with one failed scan"
    ((return_code = return_code + 1))
fi

yellow "*********************************************"
yellow "* Test only Qualys VM with one failed scan  *"
yellow "*********************************************"
rm -rf /opt/VulnWhisperer/*
if vuln_whisperer -F -c configs/test.ini -s qualys_vuln --mock --mock_dir "${TEST_PATH}"; [[ $? -eq 1 ]]; then
    green "\n✅ Passed: Test only Qualys VM with one failed scan"
else
    red "\n❌ Failed: Test only Qualys VM with one failed scan"
    ((return_code = return_code + 1))
fi

# Restore the removed files
mv "${TEST_PATH}/qualys_vuln/scan_1553941061.87241.bak" "${TEST_PATH}/qualys_vuln/scan_1553941061.87241"
mv "${TEST_PATH}/nessus/GET_scans_exports_164_download.bak" "${TEST_PATH}/nessus/GET_scans_exports_164_download"

exit $return_code
