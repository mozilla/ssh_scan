require 'sqlite3'

module SSHScan
  class FingerprintDatabase
    def initialize(database_name)
      if File.exists?(database_name)
        @db = ::SQLite3::Database.open(database_name)
      else
        @db = ::SQLite3::Database.new(database_name)
        self.create_schema
      end
    end

    def create_schema
      @db.execute <<-SQL
        create table fingerprints (
          fingerprint varchar(100),
          ip varchar(100)
        );
      SQL
    end

    def clear_fingerprints(ip)
      @db.execute "delete from fingerprints where ip like ( ? )", [ip]
    end

    def add_fingerprint(fingerprint, ip)
      @db.execute "insert into fingerprints values ( ?, ? )", [fingerprint, ip]
    end

    def find_fingerprints(fingerprint)
      ips = []
      @db.execute( "select * from fingerprints where fingerprint like ( ? )", [fingerprint] ) do |row|
        ips << row[1]
      end
      return ips
    end
  end
end
