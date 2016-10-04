require 'sinatra/base'
require 'sinatra/namespace'
require 'ssh_scan/version'
require 'ssh_scan/policy'
require 'ssh_scan/scan_engine'
require 'json'
require 'haml'
require 'secure_headers'

module SSHScan
  class API < Sinatra::Base
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
      config.referrer_policy = "origin-when-cross-origin"
      config.csp = {
        default_src: %w(https: 'self'),
        base_uri: %w('self'),
        block_all_mixed_content: true, # see http://www.w3.org/TR/mixed-content/
        child_src: %w('none'), # if child-src isn't supported, the value for frame-src will be set.
        connect_src: %w('none'),
        font_src: %w('none'),
        form_action: %w('none'),
        frame_ancestors: %w('none'),
        img_src: %w('none'),
        media_src: %w('none'),
        object_src: %w('none'),
        plugin_types: %w('none'),
        script_src: %w('none'),
        style_src: %w('none'),
        upgrade_insecure_requests: true, # see https://www.w3.org/TR/upgrade-insecure-requests/
        #report_uri: %w(https://report-uri.io/example-csp)
      }
    end

    class NullLogger < Logger
      def initialize(*args)
      end

      def add(*args, &block)
      end
    end

    register Sinatra::Namespace

    before do
      headers "Server" => "ssh_scan_api"
    end

    # Custom 404 handling
    not_found do
      'Invalid request, see API documentation here: https://github.com/mozilla/ssh_scan/wiki/ssh_scan-Web-API'
    end

    namespace "/api/v#{SSHScan::API_VERSION}" do
      before do
        content_type :json
      end

      post '/scan' do
        options = {
          :sockets => [],
          :policy => File.expand_path("../../../policies/mozilla_modern.yml", __FILE__),
          :timeout => 2,
          :verbosity => nil,
          :logger => NullLogger.new,
          :fingerprint_database => "fingerprints.db",
        }
        options[:sockets] << "#{params[:target]}:#{params[:port] ? params[:port] : "22"}"
        options[:policy_file] = SSHScan::Policy.from_file(options[:policy])
        scan_engine = SSHScan::ScanEngine.new()
        scan_engine.scan(options).to_json
      end

      get '/__version__' do
        {
          :ssh_scan_version => SSHScan::VERSION,
          :api_version => SSHScan::API_VERSION,
        }.to_json
      end
    end
  end
end
