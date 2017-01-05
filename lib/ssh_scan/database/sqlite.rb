require 'sqlite3'

module   SSHScan
  module Database
    class SQLite
      attr_reader :file, :database

      def initialize(opts = {})
        @file = opts[:file]
        @database = if File.exists?(@file)
                ::SQLite3::Database.open(@file)
              else
                ::SQLite3::Database.new(@file)
                create_schema
              end
      end

      def create_schema
        @database.execute <<-SQL
          create table ssh_scan (
            uuid varchar(100),
            result json,
            worker_id varchar(100),
            scanned_on datetime
          );
        SQL
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
