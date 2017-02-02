require 'yaml/store'

module SSHScan
  # Create and/or maintain a fingerprint database using YAML Store.
  class FingerprintDatabase
    def initialize(database_name)
      @store = YAML::Store.new(database_name)
    end

    # Empty the fingerprints database for given IP.
    # @param ip [String] IP for which fingerprints should be
    #   cleared.
    def clear_fingerprints(ip)
      @store.transaction do
        @store[ip] = []
      end
    end

    # Insert a (fingerprint, IP) record.
    # @param fingerprint [String] fingerprint to insert
    # @param ip [String] IP for which fingerprint has to be added
    def add_fingerprint(fingerprint, ip)
      @store.transaction do
        @store[ip] = [] if @store[ip].nil?
        @store[ip] << fingerprint
      end
    end

    # Find IPs that have the given fingerprint.
    # @param fingerprint [String] fingerprint for which search
    #   should be performed
    # @return [Array<String>] return unique IPs for which the given
    #   fingerprint has an entry
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
