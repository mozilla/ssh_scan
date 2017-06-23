# SSH Encryption Ciphers

A place where we document reasons why we recommend and don't recommend certain ciphers...

## Recommend These Ciphers*

- chacha20-poly1305@openssh.com (Reason: ???)
- aes256-gcm@openssh.com (Reason: ???)
- aes128-gcm@openssh.com (Reason: ???)
- aes256-ctr (Reason: ???)
- aes192-ctr (Reason: ???)
- aes128-ctr (Reason: ???)
 
## Don't Recommend These Ciphers*

- 3des-cbc (Reason: ???)
- blowfish-cbc (Reason: ???)
- cast128-cbc (Reason: ???)
- arcfour (Reason: ???)
- arcfour128 (Reason: ???)
- arcfour256 (Reason: ???)
- aes128-cbc (Reason: ???)
- aes192-cbc (Reason: ???)
- aes256-cbc (Reason: ???)