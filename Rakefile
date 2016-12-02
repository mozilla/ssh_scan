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
TRAVELING_RUBY_VERSION = "20150210-2.1.5"
SQLITE3_VERSION = "1.3.9"  # Must match Gemfile

desc "Package your app"
task :package => [
  'package:linux:x86',
  'package:linux:x86_64',
  'package:osx',
  'package:win32'
]

namespace :package do
  namespace :linux do
    desc "Package your app for Linux x86"
    task :x86 => [:bundle_install,
      "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-linux-x86.tar.gz",
      "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-linux-x86-sqlite3\
-#{SQLITE3_VERSION}.tar.gz"
    ] do
      create_package("linux-x86")
    end

    desc "Package your app for Linux x86_64"
    task :x86_64 => [:bundle_install,
      "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-linux-x86_64.tar.gz",
      "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-linux-x86_64-sqlite3\
-#{SQLITE3_VERSION}.tar.gz"
    ] do
      create_package("linux-x86_64")
    end
  end

  desc "Package your app for OS X"
  task :osx => [:bundle_install,
    "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-osx.tar.gz",
    "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-osx-sqlite3\
-#{SQLITE3_VERSION}.tar.gz"
  ] do
    create_package("osx")
  end

  desc "Package your app for Windows x86"
  task :win32 => [:bundle_install, "packaging/traveling-ruby\
-#{TRAVELING_RUBY_VERSION}-win32.tar.gz"] do
    create_package("win32", :windows)
  end

  desc "Install gems to local directory"
  task :bundle_install do
    if RUBY_VERSION !~ /^2\.3\./
      abort "You can only 'bundle install' using Ruby 2.3, because \
that's what Traveling Ruby uses."
    end
    sh "rm -rf packaging/tmp"
    sh "mkdir packaging/tmp"
    sh "mkdir packaging/tmp/lib"
    sh "mkdir packaging/tmp/bin"
    sh "cp -R lib/* packaging/tmp/lib"
    sh "cp -R bin/* packaging/tmp/bin"
    sh "cp Gemfile Gemfile.lock #{PACKAGE_NAME}.gemspec packaging/tmp/"
    Bundler.with_clean_env do
      sh "cd packaging/tmp && env BUNDLE_IGNORE_CONFIG=1 bundle install \
--path ../vendor --without development"
    end
    sh "rm -rf packaging/tmp"
    sh "rm -f packaging/vendor/*/*/cache/*"
    sh "rm -rf packaging/vendor/ruby/*/extensions"
    sh "find packaging/vendor/ruby/*/gems -name '*.so' | xargs rm -f"
    sh "find packaging/vendor/ruby/*/gems -name '*.bundle' | xargs rm -f"
    sh "find packaging/vendor/ruby/*/gems -name '*.o' | xargs rm -f"
  end
end

file "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-linux-x86.tar.gz" do
  download_runtime("linux-x86")
end

file "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-linux-x86_64.tar.gz" do
  download_runtime("linux-x86_64")
end

file "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-osx.tar.gz" do
  download_runtime("osx")
end

file "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-win32.tar.gz" do
  download_runtime("win32")
end

file "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-linux-x86-sqlite3\
-#{SQLITE3_VERSION}.tar.gz" do
  download_native_extension("linux-x86", "sqlite3-#{SQLITE3_VERSION}")
end

file "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-linux-x86_64-sqlite3\
-#{SQLITE3_VERSION}.tar.gz" do
  download_native_extension("linux-x86_64", "sqlite3-#{SQLITE3_VERSION}")
end

file "packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-osx-sqlite3\
-#{SQLITE3_VERSION}.tar.gz" do
  download_native_extension("osx", "sqlite3-#{SQLITE3_VERSION}")
end

def create_package(target, os_type = :unix)
  package_dir = "#{PACKAGE_NAME}-#{VERSION}-#{target}"
  sh "rm -rf #{package_dir}"
  sh "mkdir #{package_dir}"
  sh "mkdir -p #{package_dir}/lib/app"
  sh "cp bin/#{PACKAGE_NAME} #{package_dir}/lib/app/"
  sh "mkdir #{package_dir}/lib/ruby"
  sh "tar -xzf packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-#{target}\
.tar.gz -C #{package_dir}/lib/ruby"
  if os_type == :unix
    sh "cp packaging/wrapper.sh #{package_dir}/#{PACKAGE_NAME}"
  else
    sh "cp packaging/wrapper.bat #{package_dir}/#{PACKAGE_NAME}.bat"
  end

  sh "cp -R lib/* #{package_dir}/lib/"
  sh "cp -pR packaging/vendor #{package_dir}/lib/"
  sh "cp Gemfile Gemfile.lock #{PACKAGE_NAME}.gemspec #{package_dir}/lib/vendor/"
  sh "mkdir #{package_dir}/lib/vendor/.bundle"
  sh "cp packaging/bundler-config #{package_dir}/lib/vendor/.bundle/config"
  if os_type == :unix
    sh "tar -xzf packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-#{target}-\
sqlite3-#{SQLITE3_VERSION}.tar.gz " +
      "-C #{package_dir}/lib/vendor/ruby"
  else
    sh "tar -xzf packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}-#{target}\
.tar.gz " + "-C #{package_dir}/lib/vendor/ruby"
  end
  if !ENV['DIR_ONLY']
    if os_type == :unix
      sh "tar -czf #{package_dir}.tar.gz #{package_dir}"
    else
      sh "zip -9r #{package_dir}.zip #{package_dir}"
    end

    sh "rm -rf #{package_dir}"
  end
end

def download_runtime(target)
  sh "cd packaging && curl -L -O --fail " +
    "https://d6r77u77i8pq3.cloudfront.net/releases/traveling-ruby-\
#{TRAVELING_RUBY_VERSION}-#{target}.tar.gz"
end

def download_native_extension(target, gem_name_and_version)
  sh "curl -L --fail -o packaging/traveling-ruby-#{TRAVELING_RUBY_VERSION}\
-#{target}-#{gem_name_and_version}.tar.gz " +
    "https://d6r77u77i8pq3.cloudfront.net/releases/traveling-ruby-gems-\
#{TRAVELING_RUBY_VERSION}-#{target}/#{gem_name_and_version}.tar.gz"
end
