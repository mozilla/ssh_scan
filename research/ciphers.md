# SSH Encryption Ciphers

A place where we document reasons why we recommend and don't recommend certain ciphers...

|Cipher|Acceptable?|Rationale|
|---|---|---|
|chacha20-poly1305@openssh.com|Yes||
|aes256-gcm@openssh.com|Yes||
|aes128-gcm@openssh.com|Yes||
|aes256-ctr|Yes||
|aes192-ctr|Yes||
|aes128-ctr|Yes||
|arcfour256|No|RC4 has known weaknesses|
|arcfour128|No|RC4 has known weaknesses|
|arcfour|No|RC4 has known weaknesses|
|aes256-cbc|No|CBC has known weaknesses|
|aes128-cbc|No|CBC has known weaknesses|
|aes192-cbc|No|CBC has known weaknesses|
|cast128-cbc|No|CBC has known weaknesses|
|blowfish-cbc|No|Blowfish has known weaknesses|
|3des-cbc|No|3DES has known weaknesses|
