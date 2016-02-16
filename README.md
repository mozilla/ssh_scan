# ssh_scan

[![Build Status](https://secure.travis-ci.org/claudijd/ssh_scan.png)](http://travis-ci.org/claudijd/ssh_scan)
[![Code Climate](https://codeclimate.com/github/claudijd/ssh_scan.png)](https://codeclimate.com/github/claudijd/ssh_scan)

A Ruby-based SSH configuration and policy scanner

## Key Benefits

- **Minimal Dependancies** - Uses native Ruby and BinData to do it's work, no heavy dependancies.
- **Not Just a Script** - Implementation is portable for use in another project or for automation of tasks.
- **Simple** - It is a small project so the interfaces are simple and easy to use.

## Setup

To install, type

```bash
gem install ssh_scan
```

## Example Command-Line Usage

Run `ssh_scan -h` to get this

    Usage: ssh_scan [ip] [port]
        -h, --help                       Show this message

    Example: ssh_scan 192.168.1.1
    Example: ssh_scan 192.168.1.1 22

## Rubies Supported

This project is integrated with [travis-ci](http://about.travis-ci.org/) and is regularly tested to work with the following rubies:

* [2.1.3](https://github.com/ruby/ruby/tree/ruby_2_1)
* [2.1.0](https://github.com/ruby/ruby/tree/ruby_2_1)
* [2.0.0](https://github.com/ruby/ruby/tree/ruby_2_0_0)
* [1.9.3](https://github.com/ruby/ruby/tree/ruby_1_9_3)
* [ruby-head](https://github.com/ruby/ruby)
* [jruby-head](http://jruby.org/)
* [jruby-19mode](http://jruby.org/)

To checkout the current build status for these rubies, click [here](https://travis-ci.org/#!/claudijd/ssh_scan).

## Contributing

If you are interested in contributing to this project, please see [CONTRIBUTING.md](https://github.com/claudijd/ssh_scan/blob/master/CONTRIBUTING.md)

## Credits

**Sources of Inspiration for ssh_scan**

- [**Mozilla OpenSSH Security Guide**](https://wiki.mozilla.org/Security/Guidelines/OpenSSH) - For providing a sane baseline policy recommendation for SSH configuration parameters (eg. Ciphers, Macs, and KexAlgos).
