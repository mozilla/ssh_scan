require 'rubygems'
require 'rake'
require 'rubygems/package_task'
require 'rspec'
require 'rspec/core'
require 'rspec/core/rake_task'
require 'bundler/setup'
require 'ssh_scan/version'

$:.unshift File.join(File.dirname(__FILE__), "lib")

require 'ssh_scan'

task :default => :spec

desc "Run all specs in spec directory"
RSpec::Core::RakeTask.new(:spec)

PACKAGE_NAME = "ssh_scan"
VERSION = SSHScan::VERSION