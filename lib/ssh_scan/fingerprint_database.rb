require 'yaml/store'

module SSHScan
  class FingerprintDatabase
    def initialize(database_name)
      @store = YAML::Store.new(database_name)
    end

    def clear_fingerprints(ip)
      @store.transaction do
        @store[ip] = []
      end
    end

    def add_fingerprint(fingerprint, ip)
      @store.transaction do
        @store[ip] = [] if @store[ip].nil?
        @store[ip] << fingerprint
      end
    end

    def find_fingerprints(fingerprint)
      ip_matches = []

      @store.transaction(true) do
        @store.roots.each do |ip|
          @store[ip].each do |other_fingerprint|
            if fingerprint == other_fingerprint
              ip_matches << ip
            end
          end
        end
      end

      return ip_matches.uniq
    end
  end
end
