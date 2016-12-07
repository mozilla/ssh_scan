require 'sinatra/base'
require 'sinatra/namespace'
require 'ssh_scan/version'
require 'ssh_scan/policy'
require 'ssh_scan/job_queue'
require 'ssh_scan/worker'
require 'json'
require 'haml'
require 'secure_headers'
require 'thin'
require 'securerandom'
require 'ssh_scan/authenticator'

module SSHScan
  class API < Sinatra::Base
    # Configure all the secure headers we want to use
    use SecureHeaders::Middleware
    SecureHeaders::Configuration.default do |config|
      config.cookies = {
        secure: true, # mark all cookies as "Secure"
        httponly: true, # mark all cookies as "HttpOnly"
      }
      config.hsts = "max-age=31536000; includeSubdomains; preload"
      config.x_frame_options = "DENY"
      config.x_content_type_options = "nosniff"
      config.x_xss_protection = "1; mode=block"
      config.x_download_options = "noopen"
      config.x_permitted_cross_domain_policies = "none"
      config.referrer_policy = "no-referrer"
      config.csp = {
        default_src: ["'none'"],
        frame_ancestors: ["'none'"],
        upgrade_insecure_requests: true, # see https://www.w3.org/TR/upgrade-insecure-requests/
      }
    end

    register Sinatra::Namespace

    before do
      headers "Server" => "ssh_scan_api"
      headers "Cache-control" => "no-store"
      headers "Pragma" => "no-cache"
    end

    # Custom 404 handling
    not_found do
      content_type "text/plain"
      "Invalid request, see API documentation here: \
https://github.com/mozilla/ssh_scan/wiki/ssh_scan-Web-API\n"
    end

    get '/' do
      content_type "text/plain"
      "See API documentation here: \
https://github.com/mozilla/ssh_scan/wiki/ssh_scan-Web-API\n"
    end

    get '/robots.txt' do
      content_type "text/plain"
      "User-agent: *\nDisallow: /\n"
    end

    get '/contribute.json' do
      content_type :json
      SSHScan::Constants::CONTRIBUTE_JSON.to_json
    end

    namespace "/api/v#{SSHScan::API_VERSION}" do
      before do
        content_type :json
        if settings.authentication == true
          token = request.env['HTTP_SSH_SCAN_AUTH_TOKEN']
          unless token && settings.authenticator.valid_token?(token)
            halt '{"error" : "authentication failure"}'
          end
        end
      end

      post '/scan' do
        options = {
          :sockets => [],
          :policy => File.expand_path(
            "../../../policies/mozilla_modern.yml", __FILE__
          ),
          :timeout => 2,
          :verbosity => nil,
          :fingerprint_database => "fingerprints.db",
        }
        options[:sockets] <<
          "#{params[:target]}:#{params[:port] ? params[:port] : "22"}"
        options[:policy_file] = SSHScan::Policy.from_file(options[:policy])
        options[:uuid] = SecureRandom.uuid
        settings.job_queue.add(options)
        {
          uuid: options[:uuid]
        }.to_json
      end

      get '/scan/results' do
        # TODO: get a given scan result, by UUID and return it as JSON
        '{"I am not finished yet"}'
      end

      get '/work' do
        worker_id = params[:worker_id]
        logger.warn("Worker #{worker_id} polls for Job")
        job = settings.job_queue.next
        if job.nil?
          logger.warn("Worker #{worker_id} didn't get any work")
          {"work" => false}.to_json
        else
          logger.warn("Worker #{worker_id} got job #{job[:uuid]}")
          {"work" => job}.to_json
        end
      end

      post '/work/results/:worker_id/:uuid' do
        worker_id = params['worker_id']
        uuid = params['uuid']

        if worker_id.empty? || uuid.empty?
          return {"accepted" => "false"}.to_json
        end

        # TODO: add work results to datastore, whatever that ends up being

        return {"accepted" => "true"}.to_json
      end

      get '/__version__' do
        {
          :ssh_scan_version => SSHScan::VERSION,
          :api_version => SSHScan::API_VERSION,
        }.to_json
      end

      get '/__lbheartbeat__' do
        {
          :status  => "OK",
          :message => "Keep sending requests. I am still alive."
        }.to_json
      end
    end

    def self.run!(options = {}, &block)
      set options

      configure do
        set :bind, options["bind"] || '127.0.0.1'
        set :server, "thin"
        set :logger, Logger.new(STDOUT)
        set :job_queue, JobQueue.new()
        set :results, {}
        set :authentication, options["authentication"]
        set :authenticator, SSHScan::Authenticator.from_config_file(
          options["config_file"]
        )
      end

      super do |server|
        server.ssl = true
        ssl_opts = {
        :verify_peer => false,
        :ssl_version => :TLSv1_2,
        :ssl_ciphers => "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
          ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
          ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:\
          ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
        }
        ssl_opts[:cert_chain_file] = options["crt"] if options["crt"]
        ssl_opts[:private_key_file] = options["key"] if options["key"]
        server.ssl_options = ssl_opts
      end
    end
  end
end
