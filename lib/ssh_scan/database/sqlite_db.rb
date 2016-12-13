require 'sqlite3'

module   SSHScan
  module Database
    class SQLite
      def initialize(opts = {})
        database_name = opts["database"]["name"]
        if File.exist?(database_name)
          @db = ::SQLite3::Database.open(database_name)
        else
          @db = ::SQLite3::Database.new(database_name)
          create_schema
        end
      end

      def self.from_config_file(file_string)
        opts = YAML.load_file(file_string)
        SSHScan::Database::SQLite.new(opts)
      end

      def create_schema
        @db.execute <<-SQL
          create table api_schema (
            uuid varchar(100),
            result json,
            worker_id varchar(100),
            scanned_on datetime
          );
        SQL
      end

      def add_scan(worker_id, uuid, result)
        @db.execute "insert into api_schema values ( ? , ? , ? , ? )",
                    [uuid, result.to_json, worker_id, Time.now.to_s]
      end

      def delete_scan(uuid)
        @db.execute(
          "delete from api_schema where uuid = ?",
          uuid
        )
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
          scans << row[1]
        end
        return scans
      end
    end
  end
end
