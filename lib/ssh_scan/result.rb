require 'json'
require 'ssh_scan/banner'
require 'ipaddr'
require 'string_ext'
require 'set'

module SSHScan
  class Result
    def initialize()
      @version = SSHScan::VERSION
      @fingerprints = nil
      @duplicate_host_key_ips = Set.new()
      @compliance = {}
    end

    def version
      @version
    end

    def ip
      @ip
    end

    def ip=(ip)
      unless ip.is_a?(String) && ip.ip_addr?
        raise ArgumentError, "Invalid attempt to set IP to a non-IP address value"
      end

      @ip = ip
    end

    def port
      @port
    end

    def port=(port)
      unless port.is_a?(Integer) && port > 0 && port <= 65535
        raise ArgumentError, "Invalid attempt to set port to a non-port value"
      end

      @port = port
    end

    def banner()
      @banner || SSHScan::Banner.new("")
    end

    def hostname=(hostname)
      @hostname = hostname
    end

    def hostname()
      @hostname || ""
    end

    def banner=(banner)
      unless banner.is_a?(SSHScan::Banner)
        raise ArgumentError, "Invalid attempt to set banner with a non-banner object"
      end

      @banner = banner
    end

    def ssh_version
      self.banner.ssh_version
    end

    def os_guess_common
      self.banner.os_guess.common
    end

    def os_guess_cpe
      self.banner.os_guess.cpe
    end

    def ssh_lib_guess_common
      self.banner.ssh_lib_guess.common
    end

    def ssh_lib_guess_cpe
      self.banner.ssh_lib_guess.cpe
    end

    def cookie
      @cookie || ""
    end

    def key_algorithms
      @hex_result_hash ? @hex_result_hash[:key_algorithms] : []
    end

    def server_host_key_algorithms
      @hex_result_hash ? @hex_result_hash[:server_host_key_algorithms] : []
    end

    def encryption_algorithms_client_to_server
      @hex_result_hash ? @hex_result_hash[:encryption_algorithms_client_to_server] : []
    end

    def encryption_algorithms_server_to_client
      @hex_result_hash ? @hex_result_hash[:encryption_algorithms_server_to_client] : []
    end

    def mac_algorithms_client_to_server
      @hex_result_hash ? @hex_result_hash[:mac_algorithms_client_to_server] : []
    end

    def mac_algorithms_server_to_client
      @hex_result_hash ? @hex_result_hash[:mac_algorithms_server_to_client] : []
    end

    def compression_algorithms_client_to_server
      @hex_result_hash ? @hex_result_hash[:compression_algorithms_client_to_server] : []
    end

    def compression_algorithms_server_to_client
      @hex_result_hash ? @hex_result_hash[:compression_algorithms_server_to_client] : []
    end

    def languages_client_to_server
      @hex_result_hash ? @hex_result_hash[:languages_client_to_server] : []
    end

    def languages_server_to_client
      @hex_result_hash ? @hex_result_hash[:languages_server_to_client] : []
    end

    def set_kex_result(kex_result)
      @hex_result_hash = kex_result.to_hash
    end

    def set_start_time
      @start_time = Time.now
    end

    def start_time
      @start_time
    end

    def set_end_time
      @end_time = Time.now
    end

    def scan_duration
      if start_time.nil?
        raise "Cannot calculate scan duration without start_time set"
      end

      if end_time.nil?
        raise "Cannot calculate scan duration without end_time set"
      end

      end_time - start_time
    end

    def end_time
      @end_time
    end

    def auth_methods=(auth_methods)
      @auth_methods = auth_methods
    end

    def fingerprints=(fingerprints)
      @fingerprints = fingerprints
    end

    def fingerprints
      @fingerprints
    end

    def duplicate_host_key_ips=(duplicate_host_key_ips)
      @duplicate_host_key_ips = duplicate_host_key_ips
    end

    def duplicate_host_key_ips
      @duplicate_host_key_ips.to_a
    end

    def auth_methods()
      @auth_methods || []
    end

    def set_compliance=(compliance)
      @compliance = compliance
    end

    def compliance_policy
      @compliance[:policy]
    end

    def compliant?
      @compliance[:compliant]
    end

    def compliance_references
      @compliance[:references]
    end

    def compliance_recommendations
      @compliance[:recommendations]
    end

    def set_client_attributes(client)
      self.ip = client.ip
      self.port = client.port || 22
      self.banner = client.banner || SSHScan::Banner.new("")
    end

    def error=(error)
      @error = error.to_s
    end

    def unset_error
      @error = nil
    end

    def error?
      !@error.nil?
    end

    def error
      @error
    end

    def grade=(grade)
      @compliance[:grade] = grade
    end

    def grade
      @compliance[:grade] 
    end

    def to_hash
      hashed_object = {
      	"ssh_scan_version" => self.version,
      	"ip" => self.ip,
        "hostname" => self.hostname,
      	"port" => self.port,
      	"server_banner" => self.banner.to_s,
      	"ssh_version" => self.ssh_version,
      	"os" => self.os_guess_common,
      	"os_cpe" => self.os_guess_cpe,
      	"ssh_lib" => self.ssh_lib_guess_common,
      	"ssh_lib_cpe" => self.ssh_lib_guess_cpe,
      	"key_algorithms" => self.key_algorithms,
      	"encryption_algorithms_client_to_server" => self.encryption_algorithms_client_to_server,
      	"encryption_algorithms_server_to_client" => self.encryption_algorithms_server_to_client,
      	"mac_algorithms_client_to_server" => self.mac_algorithms_client_to_server,
      	"mac_algorithms_server_to_client" => self.mac_algorithms_server_to_client,
      	"compression_algorithms_client_to_server" => self.compression_algorithms_client_to_server,
      	"compression_algorithms_server_to_client" => self.compression_algorithms_server_to_client,
      	"languages_client_to_server" => self.languages_client_to_server,
      	"languages_server_to_client" => self.languages_server_to_client,
      	"auth_methods" => self.auth_methods,
        "fingerprints" => self.fingerprints,
        "duplicate_host_key_ips" => self.duplicate_host_key_ips,
      	"compliance" => @compliance,
        "start_time" => self.start_time,
        "end_time" => self.end_time,
        "scan_duration_seconds" => self.scan_duration,
      }

      if self.error?
        hashed_object["error"] = self.error
      end

      hashed_object
    end

    def to_json
      self.to_hash.to_json
    end
  end
end