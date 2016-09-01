#!/bin/bash

command_exists () {
    type "$1" &> /dev/null ;
}

if gem list | grep 'ssh_scan'
then
  echo "Running integration tests via ssh_scan RubyGem"
  SSH_SCAN_BINARY="ssh_scan"
else
  echo "Running integration tests via ssh_scan source"
  SSH_SCAN_BINARY="ruby -I lib bin/ssh_scan"
fi

# Change permissions so the shell script will run
chmod 755 ./spec/ssh_scan/integration.sh

# Integration Test #1 (Basic)
$SSH_SCAN_BINARY -t ssh.mozilla.com > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #1: Pass"
else
  echo "Integration Test #1: Fail"
  exit 1
fi

# Integration Test #2 (Basic + Port)
$SSH_SCAN_BINARY -t ssh.mozilla.com -p 22 > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #2: Pass"
else
  echo "Integration Test #2: Fail"
  exit 1
fi

# Integration Test #3 (Basic + File Output)
$SSH_SCAN_BINARY -t github.com -p 22 -o output.json
if [ $? -eq 0 ]
then
  echo "Integration Test #3: Pass"
else
  echo "Integration Test #3: Fail"
  exit 1
fi

# Integration Test #4 (Basic + File Input)
echo "ssh.mozilla.com" >> input.txt
echo "github.com" >> input.txt
$SSH_SCAN_BINARY -t github.com -p 22 -f input.txt > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #4: Pass"
else
  echo "Integration Test #4: Fail"
  exit 1
fi

# Integration Test #5 (File Input + File Output)
$SSH_SCAN_BINARY -t github.com -p 22 -o output.json
$SSH_SCAN_BINARY -O output.json -o rescan_output.json
if [ $? -eq 0 ]
then
  echo "Integration Test #5: Pass"
else
  echo "Integration Test #5: Fail"
  exit 1
fi

# Integration Test #6 (Help Output)
$SSH_SCAN_BINARY -h > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #6: Pass"
else
  echo "Integration Test #6: Fail"
  exit 1
fi
