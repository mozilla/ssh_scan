require 'sqlite3'
require 'json'

module SSHScan
  module QueueDB
    class SQLite
      attr_reader :queue_database

      def initialize(queue_database)
        @queue_database = queue_database # the SQLite database object
      end

      # Helps us create a SSHScan::DB::SQLite object with a hash
      def self.from_hash(opts)
        file_name = opts["queue_db_file"]

        if File.exist?(file_name)
          queue_db = ::SQLite3::Database.open(file_name)
        else
          queue_db = ::SQLite3::Database.new(file_name)
        end

        #Check to see if the schema is setup or not
        result = queue_db.execute <<-SQL
          SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'ssh_scan_queue';
        SQL

        # If not, create it
        if result == [[0]]
          # Create the schema for the database
          queue_db.execute <<-SQL
            create table ssh_scan_queue (
              socket json,
              status varchar(100)
            );
          SQL
        end

        return SSHScan::QueueDB::SQLite.new(queue_db)
      end

      # @param [String] a socket we want to scan (Example: "192.168.1.1:22")
      # @return [nil]
      def push(socket)
        @queue_database.execute "insert into ssh_scan_queue values ( ? , ? )",
          [socket.to_json, "pending"]
      end

      # @return [FixNum] the number of jobs in the JobQueue
      def size
        count = @queue_database.execute("select count() from ssh_scan_queue where status = 'pending'")
        return count[0][0]
      end

      # @return [FixNum] truth value if there is any pending record or not
      def empty?
        size.zero?
      end

      # @return [String] a socket we want to scan (Example: "192.168.1.1:22")
      def pop
        res = @queue_database.execute("select socket from ssh_scan_queue where status = 'pending'")
        @queue_database.execute("update ssh_scan_queue set status = 'running'
                                where status = (select status from ssh_scan_queue
                                where status = 'pending' limit 1)")
        JSON.parse(res.first.first)
      end

      # @return [Nil]
      def delete_all
        @queue_database.execute("delete from ssh_scan_queue")
      end
    end
  end
end
