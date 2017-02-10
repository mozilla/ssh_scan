require 'spec_helper'
require 'rspec'
require 'ssh_scan/database'
require 'securerandom'
require 'tempfile'

describe SSHScan::Database do
  before :each do
    @test_database = double("test_database")
    @abstract_database = SSHScan::Database.new(@test_database)
  end

  it "should behave like an SSHScan::Database object" do
    expect(@abstract_database.database).to be_kind_of(RSpec::Mocks::Double)
    expect(@abstract_database.respond_to?(:add_scan)).to be true
    expect(@abstract_database.respond_to?(:delete_scan)).to be true
    expect(@abstract_database.respond_to?(:delete_all)).to be true
    expect(@abstract_database.respond_to?(:find_scan_result)).to be true
  end

  it "should defer #add_scan calls to the specific DB implementation" do
    worker_id = SecureRandom.uuid
    uuid = SecureRandom.uuid
    result = {:ip => "127.0.0.1", :port => 1337, :foo => "bar", :biz => "baz"}
    socket = {:target => "127.0.0.1", :port => 1337}

    expect(@test_database).to receive(:add_scan).with(worker_id, uuid, result, socket)
    @abstract_database.add_scan(worker_id, uuid, result, socket)
  end

  it "should defer #delete_scan calls to the specific DB implementation" do
    uuid = SecureRandom.uuid

    expect(@test_database).to receive(:delete_scan).with(uuid)
    @abstract_database.delete_scan(uuid)
  end

  it "should defer #delete_all calls to the specific DB implementation" do
    expect(@test_database).to receive(:delete_all)
    @abstract_database.delete_all
  end

  it "should defer #find_scan_result calls to the specific DB implementation" do
    uuid = SecureRandom.uuid

    expect(@test_database).to receive(:find_scan_result).with(uuid)
    @abstract_database.find_scan_result(uuid)
  end

  it "should generate SQLite from a SQLite options set" do
    temp_file = Tempfile.new('sqlite_database_file')

    db_opts = {
      "database" => {
        "type" => "sqlite",
        "file" => temp_file.path
      }
    }

    database = SSHScan::Database.from_hash(db_opts)
    expect(database).to be_kind_of(SSHScan::Database)
    expect(database.database).to be_kind_of(SSHScan::DB::SQLite)
  end

end
