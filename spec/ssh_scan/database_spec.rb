require 'rspec'
require 'ssh_scan/database'
require 'securerandom'

describe SSHScan::Database do
  before :each do
    @test_database = double("test_database")
    @abstract_database = SSHScan::Database.new(
      :database => @test_database,
      :username => "foo",
      :password => "bar",
      :server => "127.0.0.1",
      :port => 1337,
    )  
  end

  it "should create a SSHScan::Database object and set attributes" do    
    expect(@abstract_database.database).to be_kind_of(RSpec::Mocks::Double)
    expect(@abstract_database.username).to eql("foo")
    expect(@abstract_database.password).to eql("bar")
    expect(@abstract_database.server).to eql("127.0.0.1")
    expect(@abstract_database.port).to eql(1337)

    expect(@abstract_database.respond_to?(:add_scan)).to be true
    expect(@abstract_database.respond_to?(:delete_scan)).to be true
    expect(@abstract_database.respond_to?(:delete_all)).to be true
    expect(@abstract_database.respond_to?(:find_scan_result)).to be true
  end

  it "should defer #add_scan calls to the specific DB implementation" do
    worker_id = SecureRandom.uuid
    uuid = SecureRandom.uuid
    result = {:ip => "127.0.0.1", :port => 1337, :foo => "bar", :biz => "baz"}

    expect(@test_database).to receive(:add_scan).with(worker_id, uuid, result)
    @abstract_database.add_scan(worker_id, uuid, result)
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
end
