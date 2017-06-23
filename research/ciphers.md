# SSH Encryption Ciphers

A place where we document reasons why we recommend and don't recommend certain ciphers...

|Cipher|Acceptable?|Reasons|
|---|---|---|
|chacha20-poly1305@openssh.com|👍||
|aes256-gcm@openssh.com|👍||
|aes128-gcm@openssh.com|👍||
|aes256-ctr|👍||
|aes192-ctr|👍||
|aes128-ctr|👍||
|arcfour256|👎||
|arcfour128|👎||
|arcfour|👎||
|aes256-cbc|👎||
|aes128-cbc|👎||
|aes192-cbc|👎||
|cast128-cbc|👎||
|blowfish-cbc|👎||
|3des-cbc|👎||
