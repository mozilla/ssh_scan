require 'spec_helper'
require 'rspec'
require 'ssh_scan/result'

describe SSHScan::Result do
  it "should have sane defaults" do
    result = SSHScan::Result.new()

    expect(result).to be_kind_of(SSHScan::Result)
    expect(result.version).to eql(SSHScan::VERSION)
    expect(result.ip).to be_nil
    expect(result.port).to be_nil
    expect(result.banner).to be_kind_of(SSHScan::Banner)
    expect(result.banner.to_s).to eql("")
    expect(result.hostname).to eql("")
    expect(result.ssh_version).to eql("unknown")
    expect(result.os_guess_common).to eql("unknown")
    expect(result.os_guess_cpe).to eql("o:unknown")
    expect(result.ssh_lib_guess_common).to eql("unknown")
    expect(result.ssh_lib_guess_cpe).to eql("a:unknown")
    expect(result.cookie).to eql("")
    expect(result.key_algorithms).to eql([])
    expect(result.server_host_key_algorithms).to eql([])
    expect(result.encryption_algorithms_client_to_server).to eql([])
    expect(result.encryption_algorithms_server_to_client).to eql([])
    expect(result.mac_algorithms_client_to_server).to eql([])
    expect(result.mac_algorithms_server_to_client).to eql([])
    expect(result.compression_algorithms_client_to_server).to eql([])
    expect(result.compression_algorithms_server_to_client).to eql([])
    expect(result.languages_client_to_server).to eql([])
    expect(result.languages_server_to_client).to eql([])
    expect(result.start_time).to be_nil
    expect(result.end_time).to be_nil
    expect{ result.scan_duration }.to raise_error(
      RuntimeError,
      "Cannot calculate scan duration without start_time set"
    )
  end

  context "when setting IP" do 
    it "should allow setting result.ip" do
      result = SSHScan::Result.new()
      expect(result.ip).to be_nil

      result.ip = "192.168.1.1"
      expect(result.ip).to eql("192.168.1.1")
    end

    it "should prevent setting result.ip to invalid values" do
      result = SSHScan::Result.new()
      expect(result.ip).to be_nil

      invalid_inputs = [
        "hello",
        123,
        "192.168.10.265"
      ]

      invalid_inputs.each do |invalid_input|
        expect { result.ip = invalid_input}.to raise_error(
          ArgumentError,
          "Invalid attempt to set IP to a non-IP address value"
        )
        expect(result.ip).to be_nil
      end
    end
  end

  context "when setting Port" do 
    it "should allow setting result.port" do
      result = SSHScan::Result.new()
      expect(result.port).to be_nil

      result.port = 31337
      expect(result.port).to eql(31337)
    end

    it "should prevent setting result.port to invalid values" do
      result = SSHScan::Result.new()
      expect(result.port).to be_nil

      invalid_inputs = [
        65537,
        -1,
        "",
        "22"
      ]

      invalid_inputs.each do |invalid_input|
        expect { result.port = invalid_input}.to raise_error(
          ArgumentError,
          "Invalid attempt to set port to a non-port value"
        )
        expect(result.ip).to be_nil
      end
    end
  end

  context "when setting banner" do 
    it "should allow setting result.banner" do
      banner = SSHScan::Banner.new("This is my SSH Banner")
      result = SSHScan::Result.new()
      expect(result.banner).to be_kind_of(SSHScan::Banner)
      expect(result.banner.to_s).to eql("")

      result.banner = banner
      expect(result.banner).to be_kind_of(SSHScan::Banner)
      expect(result.banner.to_s).to eql("This is my SSH Banner")
    end

    it "should prevent setting result.banner to invalid values" do
      result = SSHScan::Result.new()
      expect(result.banner).to be_kind_of(SSHScan::Banner)
      expect(result.banner.to_s).to eql("")

      invalid_inputs = [
        65537,
        -1,
        "",
        "22",
      ]

      invalid_inputs.each do |invalid_input|
        expect { result.banner = invalid_input}.to raise_error(
          ArgumentError,
          "Invalid attempt to set banner with a non-banner object"
        )
        expect(result.banner).to be_kind_of(SSHScan::Banner)
        expect(result.banner.to_s).to eql("")
      end
    end
  end

  context "when setting ssh_version via banner" do 
    it "should allow setting result.ssh_version" do
      result = SSHScan::Result.new()
      expect(result.ssh_version).to eql("unknown")

      result.banner = SSHScan::Banner.new("SSH-2.0-server")
      expect(result.ssh_version).to eql(2.0)
    end
  end

  context "when setting hostname" do 
    it "should allow setting result.hostname" do
      result = SSHScan::Result.new()
      expect(result.hostname).to eql("")

      result.hostname = "bananas.example.com"
      expect(result.hostname).to eql("bananas.example.com")
    end
  end

  context "when exporting the Result object to different Objects" do 
    it "should translate the result into a valid hash" do
      result = SSHScan::Result.new()
      result.set_start_time
      result.set_end_time

      result_hash = result.to_hash
      expect(result_hash).to be_kind_of(Hash)
    end

    it "should translate the result into a valid JSON string" do
      result = SSHScan::Result.new()
      result.set_start_time
      result.set_end_time

      result_json_string = result.to_json
      expect(result_json_string).to be_kind_of(String)

      # Make sure we're generating valid JSON documents
      expect(JSON.parse(result_json_string)).to be_kind_of(Hash)
    end
  end

  context "when setting compliance" do 
    it "should allow setting of the compliance information" do
      compliance = {
        :policy => "Test Policy",
        :compliant => true,
        :recommendations => ["do this", "do that"],
        :references => ["https://reference.example.com"],
      }
      result = SSHScan::Result.new()
      result.set_compliance = compliance

      expect(result.compliance_policy).to eql(compliance[:policy])
      expect(result.compliant?).to eql(compliance[:compliant])
      expect(result.compliance_recommendations).to eql(compliance[:recommendations])
      expect(result.compliance_references).to eql(compliance[:references])
    end
  end

  context "when setting grade" do 
    it "should allow setting of the grade information" do
      compliance = {
        :policy => "Test Policy",
        :compliant => true,
        :recommendations => ["do this", "do that"],
        :references => ["https://reference.example.com"],
      }
      result = SSHScan::Result.new()
      result.set_compliance = compliance
      result.grade = "D"

      expect(result.compliance_policy).to eql(compliance[:policy])
      expect(result.compliant?).to eql(compliance[:compliant])
      expect(result.compliance_recommendations).to eql(compliance[:recommendations])
      expect(result.compliance_references).to eql(compliance[:references])
      expect(result.grade).to eql("D")
    end
  end

end