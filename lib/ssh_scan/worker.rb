require 'ssh_scan/scan_engine'
require 'openssl'
require 'net/https'

module SSHScan
  class Worker
    def initialize(opts = {})
      @server = opts[:server] || "127.0.0.1"
      @port = opts[:port] || 8000
      @logger = opts[:logger] || Logger.new(STDOUT)
      @poll_interval = 5 # seconds
      @worker_id = SecureRandom.uuid
      @verify_ssl = false
    end

    def run!
      loop do
        begin
          response = get_work
          if response["work"]
            job = response["work"]
            results = perform_work(job)
            post_results(results, job)
          else
            sleep 0.5
            next
          end
        rescue Errno::ECONNREFUSED
          @logger.error("Cannot reach API endpoint, waiting 5 seconds")
          sleep 5
        end
      end
    end

    def get_work
      (Net::HTTP::SSL_IVNAMES << :@ssl_options).uniq!
      (Net::HTTP::SSL_ATTRIBUTES << :options).uniq!

      Net::HTTP.class_eval do
        attr_accessor :ssl_options
      end

      uri = URI("https://#{@server}:#{@port}/api/v0.0.1/work?worker_id=#{@worker_id}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE # unless @verify_ssl == true
      options_mask = OpenSSL::SSL::OP_NO_SSLv2 + OpenSSL::SSL::OP_NO_SSLv3 + OpenSSL::SSL::OP_NO_COMPRESSION
      http.ssl_options = options_mask
      request = Net::HTTP::Get.new(uri.path)
      response = http.request(request)
      JSON.parse(response.body)
    end

    def perform_work(job)
      @logger.info("Worker #{@worker_id} started job")
      scan_engine = SSHScan::ScanEngine.new()
      options = {
        :sockets => job[:sockets],
        :logger => @logger,
        :fingerprint_database => "./fingerprints.db"
      }
      results = scan_engine.scan(job)
      @logger.info("Worker #{@worker_id} finished job")
      return results
    end

    def post_results(results, job)
      uri = URI("https://#{@server}:#{@port}/api/v0.0.1/work/results/#{@worker_id}/#{job["uuid"]}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE # unless @verify_ssl == true
      options_mask = OpenSSL::SSL::OP_NO_SSLv2 + OpenSSL::SSL::OP_NO_SSLv3 + OpenSSL::SSL::OP_NO_COMPRESSION
      http.ssl_options = options_mask
      request = Net::HTTP::Post.new(uri.path)
      request.body = results.to_json
      response = http.request(request)
      @logger.info("Worker #{@worker_id} posted results for job")
    end
  end
end
