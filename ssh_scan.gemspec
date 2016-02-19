$: << "lib"
require 'ssh_scan/version'

Gem::Specification.new do |s|
  s.name = 'ssh_scan'
  s.version = SSHScan::VERSION
  s.authors = ["Jonathan Claudius"]
  s.date = Date.today.to_s
  s.email = 'claudijd@yahoo.com'
  s.platform = Gem::Platform::RUBY
  s.files = Dir.glob("lib/**/*") +
            Dir.glob("bin/**/*") +
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

  s.add_dependency('bindata', '~> 2.0')
  s.add_development_dependency('pry')
  s.add_development_dependency('rspec', '~> 3.0')
  s.add_development_dependency('rspec-its', '~> 1.2')
  s.add_development_dependency('rake', '~> 10.3')
end
