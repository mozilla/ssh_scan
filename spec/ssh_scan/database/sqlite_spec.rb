require 'spec_helper'
require 'rspec'
require 'ssh_scan/database/sqlite'
require 'securerandom'
require 'tempfile'
require 'json'

describe SSHScan::DB::SQLite do
  it "should create a SSHScan::Database::SQLite object from scratch" do
    temp_file = Tempfile.new('sqlite_database_file')

    opts = {
      "file" => temp_file.path
    }

    sqlite_db = SSHScan::DB::SQLite.from_hash(opts)
    expect(sqlite_db.database).to be_kind_of(::SQLite3::Database)

    temp_file.close
  end

  it "should #add_scan scans to the database" do
    worker_id = SecureRandom.uuid
    uuid = SecureRandom.uuid
    result = {"ip" => "127.0.0.1", "port" => 1337, "foo" => "bar", "biz" => "baz"}
    socket = {"target" => "127.0.0.1", "port" => 1337}

    temp_file = Tempfile.new('sqlite_database_file')

    opts = {
      "file" => temp_file.path
    }

    sqlite_db = SSHScan::DB::SQLite.from_hash(opts)
    sqlite_db.add_scan(worker_id, uuid, result, socket)

    response = sqlite_db.database.execute("select * from ssh_scan where uuid like ( ? )", uuid)

    # Example:
    # [["c61baa9d-055b-487f-87dc-517889a74703",
    #   "{\"ip\":\"127.0.0.1\",\"port\":1337,\"foo\":\"bar\",\"biz\":\"baz\"}",
    #   "116f5b0b-a768-44f4-a663-31237710139c",
    #   "2017-01-11 16:21:01 -0500"]]
    expect(response.size).to eql(1)
    expect(response.first[0]).to eql(uuid)
    expect(response.first[3]).to eql(result.to_json)
    expect(response.first[4]).to eql(worker_id)

    temp_file.close
  end

  it "should #delete_scan only the scan we ask it to" do
    worker_id = SecureRandom.uuid
    uuid1 = SecureRandom.uuid
    uuid2 = SecureRandom.uuid
    result = {"ip" => "127.0.0.1", "port" => 1337, "foo" => "bar", "biz" => "baz"}
    socket = {"target" => "127.0.0.1", "port" => 1337}

    temp_file = Tempfile.new('sqlite_database_file')

    opts = {
      "file" => temp_file.path
    }

    sqlite_db = SSHScan::DB::SQLite.from_hash(opts)
    sqlite_db.add_scan(worker_id, uuid1, result, socket)
    sqlite_db.add_scan(worker_id, uuid2, result, socket)

    # Verify that we now have two entries in the DB
    response1 = sqlite_db.database.execute("select * from ssh_scan where worker_id like ( ? )", worker_id)
    expect(response1.size).to eql(2)

    # Let's delete one and make sure it's done
    sqlite_db.delete_scan(uuid1)
    response2 = sqlite_db.database.execute("select * from ssh_scan where worker_id like ( ? )", worker_id)
    expect(response2.size).to eql(1)
    expect(response2.first[0]).to eql(uuid2)
    expect(response2.first[3]).to eql(result.to_json)
    expect(response2.first[4]).to eql(worker_id)

    temp_file.close
  end

  it "should #delete_all scans in the database" do
    worker_id = SecureRandom.uuid
    uuid1 = SecureRandom.uuid
    uuid2 = SecureRandom.uuid
    result = {"ip" => "127.0.0.1", "port" => 1337, "foo" => "bar", "biz" => "baz"}
    socket = {"target" => "127.0.0.1", "port" => 1337}

    temp_file = Tempfile.new('sqlite_database_file')

    opts = {
      "file" => temp_file.path
    }

    sqlite_db = SSHScan::DB::SQLite.from_hash(opts)
    sqlite_db.add_scan(worker_id, uuid1, result, socket)
    sqlite_db.add_scan(worker_id, uuid2, result, socket)

    # Verify that we now have two entries in the DB
    response1 = sqlite_db.database.execute("select * from ssh_scan where worker_id like ( ? )", worker_id)
    expect(response1.size).to eql(2)

    # Let's delete all scans and make sure their gone
    sqlite_db.delete_all
    response2 = sqlite_db.database.execute("select * from ssh_scan where worker_id like ( ? )", worker_id)
    expect(response2.size).to eql(0)

    temp_file.close
  end

  it "should #find_scan_result in database" do
    worker_id = SecureRandom.uuid
    uuid1 = SecureRandom.uuid
    uuid2 = SecureRandom.uuid
    result1 = {"ip" => "127.0.0.1", "port" => 1337, "foo" => "bar", "biz" => "baz"}
    result2 = {"ip" => "127.0.0.1", "port" => 1337, "foo" => "bar2", "biz" => "baz2"}
    socket = {"target" => "127.0.0.1", "port" => 1337}


    temp_file = Tempfile.new('sqlite_database_file')

    opts = {
      "file" => temp_file.path
    }

    sqlite_db = SSHScan::DB::SQLite.from_hash(opts)
    sqlite_db.add_scan(worker_id, uuid1, result1, socket)
    sqlite_db.add_scan(worker_id, uuid2, result2, socket)

    # It should find the first scan
    response1 = sqlite_db.find_scan_result(uuid1)
    expect(response1).to be_kind_of(::Hash)
    expect(response1).to eql(result1)

    # # It should find the second scan
    response2 = sqlite_db.find_scan_result(uuid2)
    expect(response2).to be_kind_of(::Hash)
    expect(response2).to eql(result2)

    temp_file.close
  end

  it "should NOT #find_scan_result in database" do
    worker_id = SecureRandom.uuid
    uuid1 = SecureRandom.uuid
    bogus_uuid = SecureRandom.uuid
    result1 = {"ip" => "127.0.0.1", "port" => 1337, "foo" => "bar", "biz" => "baz"}
    socket = {"target" => "127.0.0.1", "port" => 1337}

    temp_file = Tempfile.new('sqlite_database_file')

    opts = {
      "file" => temp_file.path
    }

    sqlite_db = SSHScan::DB::SQLite.from_hash(opts)
    sqlite_db.add_scan(worker_id, uuid1, result1, socket)

    # It should return nil for a non-existant uuid
    response = sqlite_db.find_scan_result(bogus_uuid)
    expect(response).to eql(nil)

    temp_file.close
  end

end
