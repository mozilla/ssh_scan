require 'sqlite3'

module SSHScan
  module DB
    class SQLite
      attr_reader :database

      def initialize(database)
        @database = database # the SQLite database object
      end

      # Helps us create a SSHScan::DB::SQLite object with a hash
      def self.from_hash(opts)
        file_name = opts["file"]

        if File.exist?(file_name)
          db = ::SQLite3::Database.open(file_name)
        else
          db = ::SQLite3::Database.new(file_name)
        end

        #Check to see if the schema is setup or not
        result = db.execute <<-SQL
          SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'ssh_scan';
        SQL

        # If not, create it
        if result == [[0]]
          # Create the schema for the database
          db.execute <<-SQL
            create table ssh_scan (
              uuid varchar(100),
              result json,
              worker_id varchar(100),
              scanned_on datetime
            );
          SQL
        end

        return SSHScan::DB::SQLite.new(db)
      end

      def add_scan(worker_id, uuid, result)
        @database.execute "insert into ssh_scan values ( ? , ? , ? , ? )",
                    [uuid, result.to_json, worker_id, Time.now.to_s]
      end

      def delete_scan(uuid)
        @database.execute(
          "delete from ssh_scan where uuid = ?",
          uuid
        )
      end

      def delete_all
        @database.execute("delete from ssh_scan")
      end

      def find_scan_result(uuid)
        scans = []
        @database.execute(
          "select * from ssh_scan where uuid like ( ? )",
          uuid
        ) do |row|
          scans << row[1]
        end
        return scans
      end
    end
  end
end
