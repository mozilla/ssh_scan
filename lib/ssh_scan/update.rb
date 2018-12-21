require 'ssh_scan/os'
require 'ssh_scan/ssh_lib'
require 'ssh_scan/version'
require 'net/http'

module SSHScan
  class Update
    def initialize
      @errors = []
    end

    def next_patch_version(version = SSHScan::VERSION)
      major, minor, patch = version.split(".")
      patch_num = patch.to_i
      patch_num += 1

      return [major, minor, patch_num.to_s].join(".")
    end

    def next_minor_version(version = SSHScan::VERSION)
      major, minor, patch = version.split(".")
      minor_num = minor.to_i
      minor_num += 1

      return [major, minor_num.to_s, "0"].join(".")
    end

    def next_major_version(version = SSHScan::VERSION)
      major, minor, patch = version.split(".")
      major_num = major.to_i
      major_num += 1

      return [major_num.to_s, "0", "0"].join(".")
    end

    def gem_exists?(version = SSHScan::VERSION)
      uri = URI("https://rubygems.org/gems/ssh_scan/versions/#{version}")

      begin
        res = Net::HTTP.get_response(uri)
      rescue Exception => e
        @errors << e.message
        return false
      end

      if res.code != "200"
        return false
      else
        return true
      end
    end

    def errors
      @errors.uniq
    end

    def newer_gem_available?(version = SSHScan::VERSION)
      if gem_exists?(next_patch_version(version))
        return true
      end

      if gem_exists?(next_minor_version(version))
        return true
      end

      if gem_exists?(next_major_version(version))
        return true
      end

      return false
    end
  end
end
