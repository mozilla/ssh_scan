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
      expect(File.exist?(file_name)).to eql(true)
      File.unlink(file_name) #clean up after ourselves
    end

    it "should use a pre-existing DB if it exists" do
      file_name = "test.db"

      #start with a known good state
      File.unlink(file_name) if File.exists?(file_name)

      # Create a pre-existing DB
      db = ::SQLite3::Database.new(file_name)
      db.execute <<-SQL
        create table fingerprints (
          fingerprint varchar(100),
          ip varchar(100)
        );
      SQL
      db.execute "insert into fingerprints values ( ?, ? )", ["fake_fingerprint", "127.0.0.1"]

      expect(File.exist?(file_name)).to eql(true)
      database = SSHScan::FingerprintDatabase.new(file_name)
      expect(database).to be_kind_of(SSHScan::FingerprintDatabase)

      expect(database.find_fingerprints("fake_fingerprint")).to eql(["127.0.0.1"])
      File.unlink(file_name) #clean up after ourselves
    end
  end
end
