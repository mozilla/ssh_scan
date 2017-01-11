require 'ssh_scan/database/sqlite'
require 'json'
require 'yaml'

describe SSHScan::Database::SQLite do

  file_string = File.expand_path('../../config/sqlite.yml', __FILE__)
  sqlite = SSHScan::Database::SQLite.from_config_file(file_string)

  it "should be able to add scan correctly" do	

    # start with a known good state
    sqlite.delete_all if sqlite.size[0][0] > 0
    
    expect(sqlite.size[0][0]).to eql(0)
    worker_id = "20b4b3c7-2329-45ce-b8cd-a58aa08101b7"
    uuid = "bb5a31b6-45d0-4316-ae3e-938ef0cd7e95"
    result = File.read(File.join(Dir.pwd, '/examples/github.com.json'))
    sqlite.add_scan(worker_id, uuid, result)
    expect(sqlite).to be_kind_of(SSHScan::Database::SQLite)
    expect(sqlite.size[0][0]).to eql(1)
  end

  it "should be able to find scan correctly" do
    
    expect(sqlite.size[0][0]).to eql(1)

    uuid = "bb5a31b6-45d0-4316-ae3e-938ef0cd7e95"
    result = sqlite.find_scan_result(uuid)

    expect(result.first).to be_kind_of(::String)
  end

  it "should be able to delete scan correctly" do
    
    expect(sqlite.size[0][0]).to eql(1)

    uuid = "bb5a31b6-45d0-4316-ae3e-938ef0cd7e95"
    sqlite.delete_scan(uuid)
    expect(sqlite.size[0][0]).to eql(0)    
  end  

end
