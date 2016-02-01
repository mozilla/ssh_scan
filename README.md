# ssh_scan
A prototype/PoC for an SSH scanner

Example run:

    $ ruby -I ./ ssh_scan.rb 192.168.1.1
    {
      "ip": "192.168.1.1",
      "port": 22,
      "server_banner": "SSH-2.0-OpenSSH_5.3",
      "key_algorithms": [
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1"
      ],
      "server_host_key_algorithms": [
        "ssh-rsa",
        "ssh-dss"
      ],
      "encryption_algorithms_client_to_server": [
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "arcfour256",
        "arcfour128",
        "aes128-cbc",
        "3des-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "arcfour",
        "rijndael-cbc@lysator.liu.se"
      ],
      "encryption_algorithms_server_to_client": [
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "arcfour256",
        "arcfour128",
        "aes128-cbc",
        "3des-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "arcfour",
        "rijndael-cbc@lysator.liu.se"
      ],
      "mac_algorithms_client_to_server": [
        "hmac-md5",
        "hmac-sha1",
        "umac-64@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-ripemd160",
        "hmac-ripemd160@openssh.com",
        "hmac-sha1-96",
        "hmac-md5-96"
      ],
      "mac_algorithms_server_to_client": [
        "hmac-md5",
        "hmac-sha1",
        "umac-64@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-ripemd160",
        "hmac-ripemd160@openssh.com",
        "hmac-sha1-96",
        "hmac-md5-96"
      ],
      "compression_algorithms_client_to_server": [
        "none",
        "zlib@openssh.com"
      ],
      "compression_algorithms_server_to_client": [
        "none",
        "zlib@openssh.com"
      ],
      "languages_client_to_server": [

      ],
      "languages_server_to_client": [

      ],
      "compliance": {
        "policy": "SSH::IntermediatePolicy",
        "compliant": false,
        "recommendations": [
          "Remove these Key Exchange Algos: diffie-hellman-group-exchange-sha1, diffie-hellman-group14-sha1, diffie-hellman-group1-sha1",
          "Remove these MAC Algos: hmac-md5, hmac-sha1, umac-64@openssh.com, hmac-ripemd160, hmac-ripemd160@openssh.com, hmac-sha1-96, hmac-md5-96",
          "Remove these Encryption Ciphers: arcfour256, arcfour128, aes128-cbc, 3des-cbc, blowfish-cbc, cast128-cbc, aes192-cbc, aes256-cbc, arcfour, rijndael-cbc@lysator.liu.se"
        ]
      }
    }
