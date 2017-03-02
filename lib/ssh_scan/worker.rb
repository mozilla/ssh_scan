require 'ssh_scan/scan_engine'
require 'openssl'
require 'net/https'

module SSHScan
  class Worker
    def initialize(opts = {})
      @server = opts["server"] || "127.0.0.1"
      @scheme = opts["scheme"] || "http"
      @verify = opts["verify"] || "false"
      @port = opts["port"] || 8000
      @logger = setup_logger(opts["logger"])
      @poll_interval = 5 # seconds
      @worker_id = SecureRandom.uuid
      @verify_ssl = false
      @auth_token = opts["auth_token"] || nil
    end

    def setup_logger(logger)
      case logger
      when Logger
        return logger
      when String
        return Logger.new(logger)
      end

      return Logger.new(STDOUT)
    end

    def self.from_config_file(file_string)
      opts = YAML.load_file(file_string)
      SSHScan::Worker.new(opts)
    end

    def run!
      loop do
        begin
          response = retrieve_work
          if response["work"]
            job = response["work"]
            results = perform_work(job)
            post_results(results, job)
          else
            @logger.info("No jobs available (waiting 5 seconds)")
            sleep 5
            next
          end
        rescue Errno::ECONNREFUSED
          @logger.error("Cannot reach API endpoint, waiting 5 seconds")
          sleep 5
        rescue RuntimeError => e
          @logger.error(e.inspect)
        end
      end
    end

    def retrieve_work
      (Net::HTTP::SSL_IVNAMES << :@ssl_options).uniq!
      (Net::HTTP::SSL_ATTRIBUTES << :options).uniq!

      Net::HTTP.class_eval do
        attr_accessor :ssl_options
      end

      uri = URI(
        "#{@scheme}://#{@server}:#{@port}/api/v#{SSHScan::API_VERSION}/\
work?worker_id=#{@worker_id}"
      )
      http = Net::HTTP.new(uri.host, uri.port)

      if @scheme == "https"
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @verify == false
        options_mask =
          OpenSSL::SSL::OP_NO_SSLv2 +
          OpenSSL::SSL::OP_NO_SSLv3 +
          OpenSSL::SSL::OP_NO_COMPRESSION
        http.ssl_options = options_mask
      end

      request = Net::HTTP::Get.new(uri.path)
      request.add_field("SSH_SCAN_AUTH_TOKEN", @auth_token) unless @auth_token.nil?
      response = http.request(request)
      JSON.parse(response.body)
    end

    def perform_work(job)
      @logger.info("Started job: #{job["uuid"]}")
      scan_engine = SSHScan::ScanEngine.new
      results = scan_engine.scan(job)
      @logger.info("Completed job: #{job["uuid"]}")
      return results
    end

    def post_results(results, job)
      uri = URI(
        "#{@scheme}://#{@server}:#{@port}/api/v#{SSHScan::API_VERSION}/\
work/results/#{@worker_id}/#{job["uuid"]}"
      )
      http = Net::HTTP.new(uri.host, uri.port)

      if @scheme == "https"
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @verify == false
        options_mask =
          OpenSSL::SSL::OP_NO_SSLv2 +
          OpenSSL::SSL::OP_NO_SSLv3 +
          OpenSSL::SSL::OP_NO_COMPRESSION
        http.ssl_options = options_mask
      end

      request = Net::HTTP::Post.new(uri.path)
      request.add_field("SSH_SCAN_AUTH_TOKEN", @auth_token) unless @auth_token.nil?
      request.body = results.to_json
      http.request(request)
      @logger.info("Posted job: #{job["uuid"]}")
    end
  end
end
