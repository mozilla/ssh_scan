# ssh_scan

[![Build Status](https://secure.travis-ci.org/mozilla/ssh_scan.png)](http://travis-ci.org/mozilla/ssh_scan)
[![Code Climate](https://codeclimate.com/github/mozilla/ssh_scan.png)](https://codeclimate.com/github/mozilla/ssh_scan)
[![Gem Version](https://badge.fury.io/rb/ssh_scan.svg)](https://badge.fury.io/rb/ssh_scan)

A SSH configuration and policy scanner

## Key Benefits

- **Minimal Dependancies** - Uses native Ruby and BinData to do it's work, no heavy dependancies.
- **Not Just a Script** - Implementation is portable for use in another project or for automation of tasks.
- **Simple** - Just point ssh_scan at an SSH service and get a JSON report of what is supports and it's policy status
- **Configurable** - Make your own custom policies that fit your unique policy requirements.

## Setup

To install as a gem, type

```bash
gem install ssh_scan
ssh_scan
```

To install from source, type

```bash
git clone https://github.com/mozilla/ssh_scan.git
cd ssh_scan
gem install bindata
./bin/ssh_scan
```

## Example Command-Line Usage

Run `ssh_scan -h` to get this

    ssh_scan v0.0.8 (https://github.com/mozilla/ssh_scan)

    Usage: ssh_scan [options]
        -t, --target [IP/Hostname]       IP/Hostname (IPv4/IPv6/FQDNs)
        -p, --port [PORT]                Port (Default: 22)
        -P, --policy [FILE]              Policy file (Default: Mozilla Modern)
        -u, --unit-test [FILE]           Throw appropriate exit codes based on compliance status
        -v, --version                    Display just version info
        -h, --help                       Show this message

    Examples:

      ssh_scan -t 192.168.1.1
      ssh_scan -t server.example.com
      ssh_scan -t ::1
      ssh_scan -t 192.168.1.1 -p 22222
      ssh_scan -t 192.168.1.1 -P custom_policy.yml
      ssh_scan -t 192.168.1.1 --unit-test -P custom_policy.yml

See here for [example video](https://asciinema.org/a/7pliiw5zqhj7eqvz7q437u6vx)

See here for [example output](https://github.com/mozilla/ssh_scan/blob/master/examples/192.168.1.1.json)

See here for [example policies](https://github.com/mozilla/ssh_scan/blob/master/policies)

## Rubies Supported

This project is integrated with [travis-ci](http://about.travis-ci.org/) and is regularly tested to work with the following rubies:

* [2.1.3](https://github.com/ruby/ruby/tree/ruby_2_1)
* [2.1.0](https://github.com/ruby/ruby/tree/ruby_2_1)
* [2.0.0](https://github.com/ruby/ruby/tree/ruby_2_0_0)
* [1.9.3](https://github.com/ruby/ruby/tree/ruby_1_9_3)
* [ruby-head](https://github.com/ruby/ruby)
* [jruby-head](http://jruby.org/)
* [jruby-19mode](http://jruby.org/)

To checkout the current build status for these rubies, click [here](https://travis-ci.org/#!/mozilla/ssh_scan).

## Contributing

If you are interested in contributing to this project, please see [CONTRIBUTING.md](https://github.com/mozilla/ssh_scan/blob/master/CONTRIBUTING.md)

## Credits

**Sources of Inspiration for ssh_scan**

- [**Mozilla OpenSSH Security Guide**](https://wiki.mozilla.org/Security/Guidelines/OpenSSH) - For providing a sane baseline policy recommendation for SSH configuration parameters (eg. Ciphers, Macs, and KexAlgos).
