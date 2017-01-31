module SSHScan
  class Stats
    def initialize
      @requests = []
    end

    def new_scan_request
      @requests << Time.now
      # Purges the request queue of old requests
      purge_old_requests
    end

    def get_stats(queue_size)
      {
         :items_queued => queue_size,
         :avg_requests_per_min => requests_avg_per,
         :requests_per_min => requests_per
      }.to_json
    end

    def size
      @requests.size
    end

    # Purges the request queue of old requests, so we don't run the API out of memory
    # @param [Fixnum] seconds
    def purge_old_requests(seconds = 60)
      @requests.delete_if {|request_time| request_time < Time.now - seconds}
    end

    # Determines the number of requests in a second-based
    # time period (up to 60 seconds)
    # @param [Fixnum] seconds
    # @return [Fixnum] request per time period
    def requests_per(seconds = 60)
      requests_per = 0
      past_time = Time.now - seconds

      @requests.each do |request_time|
        requests_per += 1 if request_time >= past_time
      end

      return requests_per
    end

    # Determines average requests per time period
    def requests_avg_per(seconds = 60)
      requests_per = requests_per(seconds)
      requests_per / seconds.to_f
    end
  end
end
