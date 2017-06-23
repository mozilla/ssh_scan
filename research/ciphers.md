# SSH Encryption Ciphers

A place where we document reasons why we recommend and don't recommend certain ciphers in ssh_scan...

|Cipher|Acceptable?|Rationale||
|---|---|---|---|
|chacha20-poly1305@openssh.com|✅|||
|aes256-gcm@openssh.com|✅|||
|aes128-gcm@openssh.com|✅|||
|aes256-ctr|✅|||
|aes192-ctr|✅|||
|aes128-ctr|✅|||
|arcfour256|🚫|RC4 has [known weaknesses](https://en.wikipedia.org/wiki/RC4#Security)||
|arcfour128|🚫|RC4 has [known weaknesses](https://en.wikipedia.org/wiki/RC4#Security)||
|arcfour|🚫|RC4 has [known weaknesses](https://en.wikipedia.org/wiki/RC4#Security)||
|aes256-cbc|🚫|CBC has known weaknesses||
|aes128-cbc|🚫|CBC has known weaknesses||
|aes192-cbc|🚫|CBC has known weaknesses||
|cast128-cbc|🚫|CBC has known weaknesses||
|blowfish-cbc|🚫|Blowfish has known weaknesses||
|3des-cbc|🚫|3DES has known weaknesses||