#!/usr/bin/env ruby

require 'open3'

VALID_KEY_IDS = {
  "4BCDD990313DFA87" => "claudijd",
  "4B22F448CA24E57B" => "jinankjain",
  "3F5C4C1BB282EF34" => "agaurav77",
}

REGEX = / using [A-Z]+ key( ID)? (0x)?(?<keyid>[A-F0-9]*)/

stdin, stdout, stderr, wait_thr = Open3.popen3("git log --no-merges --format='%H:%GG' master")
first_line = stdout.gets.strip
first_line.gsub! "'", ""
parts = first_line.split(":")
keyid = nil
sha = parts[0]
if parts[1] == 'gpg'
  next_line = stdout.gets.strip
  next_line.gsub! "'", ""
  m = REGEX.match(next_line)
  if m
    keyid = m['keyid']
    if !VALID_KEY_IDS.keys.include?(keyid)
      puts "Latest commit #{sha} is signed by an invalid key #{keyid}"
      exit 1
    else
      puts "#{sha} is signed by #{keyid}(#{VALID_KEY_IDS[keyid]})"
      exit 0
    end
  end
  if keyid.nil?
    raise "Latest commit #{sha} is not signed!\nCommits must be gpg signed: `git commit -S[<keyid>]`"
  end
end
