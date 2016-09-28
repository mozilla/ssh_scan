require 'sinatra/base'
require 'sinatra/namespace'
require 'ssh_scan/version'
require 'ssh_scan/policy'
require 'ssh_scan/scan_engine'
require 'json'

module SSHScan
  class API < Sinatra::Base
    class NullLogger < Logger
      def initialize(*args)
      end

      def add(*args, &block)
      end
    end

    register Sinatra::Namespace

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
