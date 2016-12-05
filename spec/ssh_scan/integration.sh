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
  echo "Integration Test #1: Pass (Basic)"
else
  echo "Integration Test #1: Fail (Basic)"
  exit 1
fi

# Integration Test #2 (Basic + Port)
$SSH_SCAN_BINARY -t ssh.mozilla.com -p 22 > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #2: Pass (Basic + Port)"
else
  echo "Integration Test #2: Fail (Basic + Port)"
  exit 1
fi

# Integration Test #3 (Basic + File Output)
$SSH_SCAN_BINARY -t github.com -p 22 -o output.json
if [ $? -eq 0 ]
then
  echo "Integration Test #3: Pass (Basic + File Output)"
else
  echo "Integration Test #3: Fail (Basic + File Output)"
  exit 1
fi

# Integration Test #4 (Basic + File Input)
echo "ssh.mozilla.com" >> input.txt
echo "github.com" >> input.txt
$SSH_SCAN_BINARY -t github.com -p 22 -f input.txt > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #4: Pass (Basic + File Input)"
else
  echo "Integration Test #4: Fail (Basic + File Input)"
  exit 1
fi

# Integration Test #5 (File Input + File Output Rescan)
$SSH_SCAN_BINARY -t github.com -p 22 -o output.json
$SSH_SCAN_BINARY -O output.json -o rescan_output.json
if [ $? -eq 0 ]
then
  echo "Integration Test #5: Pass (File Input + File Output Rescan)"
else
  echo "Integration Test #5: Fail (File Input + File Output Rescan)"
  exit 1
fi

# Integration Test #6 (Help Output)
$SSH_SCAN_BINARY -h > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #6: Pass (Help Output)"
else
  echo "Integration Test #6: Fail (Help Output)"
  exit 1
fi

# Integration Test #7 (verbose scan)
$SSH_SCAN_BINARY -t ssh.mozilla.com -V DEBUG
if [ $? -eq 0 ]
then
  echo "Integration Test #7: Pass (verbose scan)"
else
  echo "Integration Test #7: Fail (verbose scan)"
  exit 1
fi
