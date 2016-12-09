require 'sqlite3'

module SSHScan
  class APIDatabaseHelper
    def initialize(database_name)
      if File.exist?(database_name)
        @db = ::SQLite3::Database.open(database_name)			
      else
        @db = ::SQLite3::Database.new(database_name)
        self.create_schema
      end
    end

    def create_schema
      @db.execute <<-SQL
        create table api_schema (
          worker_id varchar(100),
          uuid varchar(100),
          result json
        );
      SQL
    end

    def add_scan(worker_id, uuid, result)
      @db.execute "insert into api_schema values ( ? , ? , ? )", [worker_id, uuid, result]
    end

    def delete_scan(worker_id, uuid)
      @db.execute(
      	"delete from api_schema where worker_id = ? and uuid = ?",
      	worker_id, uuid)
    end

    def delete_all
    	@db.execute("delete from api_schema")    	
    end

    def find_scan_result(uuid)
      scans = []
      @db.execute(
        "select * from api_schema where uuid like ( ? )",
        uuid
      ) do |row|
        scans << row[2]
      end
      return scans
    end

    def find_work_result(worker_id, uuid)
      scans = []
      @db.execute(
        "select * from api_schema where uuid =  ? and worker_id = ?",
        uuid, worker_id
      ) do |row|
        scans << row[2]
      end
      return scans
    end    

  end
end