#!/usr/bin/env ruby

require 'pp'
require 'net/http'

urls = [
  "https://launchpad.net/ubuntu/+source/openssh/+changelog",
  "https://launchpad.net/ubuntu/+source/openssh/+changelog\
?batch=75&memo=75&start=75",
  "https://launchpad.net/ubuntu/+source/openssh/+changelog\
?batch=75&memo=150&start=150"
]

lines = []
urls.each do |url|
  lines += Net::HTTP.get(URI(url)).lines
end

codenames = {
  "4.10" => "warty",
  "5.04" => "hoary",
  "5.10" => "breezy",
  "6.04" => "dapper",
  "6.10" => "edgy",
  "7.04" => "feisty",
  "7.10" => "gutsy",
  "8.04" => "hardy",
  "8.10" => "intrepid",
  "9.04" => "jaunty",
  "9.10" => "karmic",
  "10.04" => "lucid",
  "10.10" => "maverick",
  "11.04" => "natty",
  "11.10" => "oneiric",
  "12.04" => "precise",
  "12.10" => "quantal",
  "13.04" => "raring",
  "13.10" => "saucy",
  "14.04" => "trusty",
  "14.10" => "utopic",
  "15.04" => "vivid",
  "15.10" => "wily",
  "16.04" => "xenial",
  "16.10" => "yakkety"
}

versions = {}
codenames.keys.each do |key|
  versions[key] = []
end

lines.each do |line|
  next if !line.include?("openssh (")
  fingerprint = line.strip.scan(/\(([^\)]+)\)/)
  versions.keys.each do |key|
    matches = 0
    if line.include?(codenames[key])
      fingerprint.each do |val|
        versions[key] << val.first.split(":")[1..-1].join(":")
      end
      matches += 1
    end
  end
end

pp versions
