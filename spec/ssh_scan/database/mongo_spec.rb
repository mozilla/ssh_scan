require 'ssh_scan/database/mongo'
require 'json'

describe SSHScan::Database::MongoDb do

  file_string = File.expand_path('../../config/mongo.yml', __FILE__)
  mongo_db = SSHScan::Database::MongoDb.from_config_file(file_string)

  it "should be able to add scan correctly" do	

    # start with a known good state
    mongo_db.delete_all if mongo_db.size > 0
    
    expect(mongo_db.size).to eql(0) 
    worker_id = "20b4b3c7-2329-45ce-b8cd-a58aa08101b7"
    uuid = "bb5a31b6-45d0-4316-ae3e-938ef0cd7e95"
    result = File.read(File.join(Dir.pwd, '/examples/github.com.json'))
    mongo_db.add_scan(worker_id, uuid, result)
    expect(mongo_db).to be_kind_of(SSHScan::Database::MongoDb)
    expect(mongo_db.size).to eql(1)
  end

  it "should be able to find scan correctly" do
    
    expect(mongo_db.size).to eql(1)

    uuid = "bb5a31b6-45d0-4316-ae3e-938ef0cd7e95"
    result = mongo_db.find_scan_result(uuid)
    expect(result).to be_kind_of(::String)
  end

  it "should be able to delete scan correctly" do
    
    expect(mongo_db.size).to eql(1)

    uuid = "bb5a31b6-45d0-4316-ae3e-938ef0cd7e95"
    mongo_db.delete_scan(uuid)
    expect(mongo_db.size).to eql(0)    
  end  

end
