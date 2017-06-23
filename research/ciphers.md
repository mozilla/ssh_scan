# SSH Encryption Ciphers

A place where we document reasons why we recommend and don't recommend certain ciphers...

|Cipher|Acceptable?|Reasons|
|chacha20-poly1305@openssh.com|Yes|---|
|aes256-gcm@openssh.com|Yes|---|
|aes128-gcm@openssh.com|Yes|---|
|aes256-ctr|Yes|---|
|aes192-ctr|Yes|---|
|aes128-ctr|Yes|---|
|3des-cbc|No|---|
|blowfish-cbc|No|---|
|cast128-cbc|No|---|
|arcfour|No|---|
|arcfour128|No|---|
|arcfour256|No|---|
|aes128-cbc|No|---|
|aes192-cbc|No|---|
|aes256-cbc|No|---|