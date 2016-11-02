require 'thread'

module SSHScan
  class ThreadPool
    def initialize(threads)
      @threads = threads
      @jobs = Queue.new
      @pool = Array.new(@threads) do |i|
        Thread.new do
          catch(:exit) do
            loop do
              job, args = @jobs.pop
              job.call(*args)
            end
          end
        end
      end
  	end
  	
  	def schedule(*args, &block)
  		@jobs << [block, args]  		
  	end

  	def shutdown
  	  @threads.times do
  	    schedule { throw :exit }
  	  end
  	  @pool.map(&:join)
  	end
  	
  end
end