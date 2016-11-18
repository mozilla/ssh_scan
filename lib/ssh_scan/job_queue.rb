module SSHScan
  class JobQueue
    def initialize
      @queue = Queue.new
    end

    # @param [String] a socket we want to scan (Example: "192.168.1.1:22")
    # @return [nil]
    def add(socket)
      @queue.push(socket)
    end

    # @return [String] a socket we want to scan (Example: "192.168.1.1:22")
    def next
      return nil if @queue.empty?
      @queue.pop
    end

    # @return [FixNum] the number of jobs in the JobQueue
    def size
      @queue.size
    end
  end
end
