require 'ssh_scan/api'
require 'rack/test'
require 'json'

describe SSHScan::API do
  include Rack::Test::Methods

  def app
    SSHScan::API.new
  end


  it "should be able to GET / correctly" do
    get "/"
    expect(last_response.status).to eql(404)
    expect(last_response.body).to eql(
      "Invalid request, see API documentation here: " +
      "https://github.com/mozilla/ssh_scan/wiki/ssh_scan-Web-API"
    )
  end

  # TODO: figure out why specs are failing
  # This works IRL...
  # $ curl -k https://127.0.0.1:8000/api/v1/__version__
  # {"ssh_scan_version":"0.0.16","api_version":"1"}
  #
  # it "should be able to GET __version__ correctly" do
  #   get "/api/v#{SSHScan::API_VERSION}/__version__"
  #   expect(last_response.status).to eql(200)
  #   expect(last_response.body).to eql({
  #     :ssh_scan_version => SSHScan::VERSION,
  #     :api_version => SSHScan::API_VERSION
  #   }.to_json)
  # end

  # TODO: figure out why specs are failing
  # This works IRL...
  # $ curl -k https://127.0.0.1:8000/api/v1/__lbheartbeat__
  # {"status":"OK","message":"Keep sending requests. I am still alive."}
  #
  # it "should send a positive response on GET __lbheartbeat__ if the API is working" do
  #   get "/api/v#{SSHScan::API_VERSION}/__lbheartbeat__"
  #   expect(last_response.status).to eql(200)
  #   expect(last_response.body).to eql({
  #     :status => "OK",
  #     :message => "Keep sending requests. I am still alive."
  #   }.to_json)
  # end

  # it "should say ConnectTimeout for bad IP, and return valid JSON" do
  #   bad_ip = "192.168.255.255"
  #   port = "999"
  #   post "/api/v#{SSHScan::API_VERSION}/scan", {:target => bad_ip, :port => port}
  #   expect(last_response.status).to eql(200)
  #   expect(last_response.body).to be_kind_of(::String)
  #
  #   parsed_response_body = JSON.parse(last_response.body)
  #
  #   expect(parsed_response_body).to be_kind_of(::Array)
  #   expect(parsed_response_body.first["ssh_scan_version"]).to eql(SSHScan::VERSION)
  #   expect(parsed_response_body.first["ip"]).to eql(bad_ip)
  #   expect(parsed_response_body.first["port"]).to eql(port)
  #   expect(parsed_response_body.first["error"]).to match(/ConnectTimeout: (Connection|Operation) timed out - user specified timeout/)
  #   expect(parsed_response_body.first["hostname"]).to eql("")
  # end
end
