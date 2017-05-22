$: << "lib"
require 'ssh_scan/version'
require 'date'

Gem::Specification.new do |s|
  s.name = 'ssh_scan'
  s.version = SSHScan::VERSION
  s.authors = ["Jonathan Claudius", "Jinank Jain", "Harsh Vardhan", "Rishabh Saxena", "Ashish Gaurav"]
  s.date = Date.today.to_s
  s.email = 'jclaudius@mozilla.com'
  s.platform = Gem::Platform::RUBY
  s.files = Dir.glob("lib/**/*") +
            Dir.glob("bin/**/*") +
            Dir.glob("config/**/*") +
            Dir.glob("data/**/*") +
            Dir.glob("policies/**/*") +
            [".gitignore",
             ".rspec",
             ".travis.yml",
             "CONTRIBUTING.md",
             "Gemfile",
             "Rakefile",
             "README.md",
             "ssh_scan.gemspec"]
  s.license       = "ruby"
  s.require_paths = ["lib"]
  s.executables   = s.files.grep(%r{^bin/[^\/]+$}) { |f| File.basename(f) }
  s.summary = 'Ruby-based SSH Scanner'
  s.description = 'A Ruby-based SSH scanner for configuration and policy scanning'
  s.homepage = 'http://rubygems.org/gems/ssh_scan'
  s.metadata["yard.run"] = "yri" # use "yard" to build full HTML docs

  s.add_dependency('bindata', '~> 2.0')
  s.add_dependency('netaddr')
  s.add_dependency('net-ssh')
  s.add_dependency('sshkey')
  s.add_development_dependency('pry')
  s.add_development_dependency('rspec', '~> 3.0')
  s.add_development_dependency('rspec-its', '~> 1.2')
  s.add_development_dependency('rake', '~> 10.3')
  s.add_development_dependency('rubocop')
end
