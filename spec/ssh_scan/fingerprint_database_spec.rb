require 'rspec'
require 'tempfile'
require 'ssh_scan/fingerprint_database'

describe SSHScan::FingerprintDatabase do
  context "when initializing a new FingerprintDatabase" do
    it "should create a new DB on disk if it doesn't exist" do
      file_name = "test.db"

      #start with a known good state
      File.unlink(file_name) if File.exists?(file_name)
      expect(File.exist?(file_name)).to eql(false)

      database = SSHScan::FingerprintDatabase.new(file_name)
      expect(database).to be_kind_of(SSHScan::FingerprintDatabase)

      # The file isn't created until something is written
      expect(File.exist?(file_name)).to eql(false)

      # Write something, to trigger file creation
      database.add_fingerprint("hello_world", "192.168.1.1")

      # Verify the file exists now
      expect(File.exist?(file_name)).to eql(true)
      
      File.unlink(file_name) #clean up after ourselves
    end

    it "should use a pre-existing DB if it exists" do
      file_name = "test.db"

      #start with a known good state
      File.unlink(file_name) if File.exists?(file_name)

      # Create a pre-existing DB
      database = SSHScan::FingerprintDatabase.new(file_name)
      database.add_fingerprint("hello_world", "192.168.1.1")

      expect(File.exist?(file_name)).to eql(true)
      database2 = SSHScan::FingerprintDatabase.new(file_name)
      expect(database2).to be_kind_of(SSHScan::FingerprintDatabase)

      expect(database2.find_fingerprints("hello_world")).to eql(["192.168.1.1"])
      File.unlink(file_name) #clean up after ourselves
    end
  end
end
