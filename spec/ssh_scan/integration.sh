#!/bin/bash

# Change permissions so the shell script will run
chmod 755 ./spec/ssh_scan/integration.sh

# Integration Test #1 (Basic)
./bin/ssh_scan -t ssh.mozilla.com > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #1: Pass"
else
  echo "Integration Test #1: Fail"
  exit 1
fi

# Integration Test #2 (Basic + Port)
./bin/ssh_scan -t ssh.mozilla.com -p 22 > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #2: Pass"
else
  echo "Integration Test #2: Fail"
  exit 1
fi

# Integration Test #3 (Basic + File Output)
./bin/ssh_scan -t github.com -p 22 -o output.json
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
./bin/ssh_scan -t github.com -p 22 -f input.txt > /dev/null
if [ $? -eq 0 ]
then
  echo "Integration Test #4: Pass"
else
  echo "Integration Test #4: Fail"
  exit 1
fi

# Integration Test #5 (File Input + File Output)
./bin/ssh_scan -t github.com -p 22 -o output.json
./bin/ssh_scan -O output.json -o rescan_output.json
if [ $? -eq 0 ]
then
  echo "Integration Test #5: Pass"
else
  echo "Integration Test #5: Fail"
  exit 1
fi
