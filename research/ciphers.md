# SSH Encryption Ciphers

A place where we document reasons why we recommend and don't recommend certain ciphers...

|Cipher|Acceptable?|Reasons|
|---|---|---|
|chacha20-poly1305@openssh.com|Yes||
|aes256-gcm@openssh.com|Yes||
|aes128-gcm@openssh.com|Yes||
|aes256-ctr|Yes||
|aes192-ctr|Yes||
|aes128-ctr|Yes||
|arcfour256|No||
|arcfour128|No||
|arcfour|No||
|aes256-cbc|No||
|aes128-cbc|No||
|aes192-cbc|No||
|cast128-cbc|No||
|blowfish-cbc|No||
|3des-cbc|No||
