require 'ssh_scan/scan_engine'

module SSHScan
  class Worker
    @scan_engine = SSHScan::ScanEngine.new
    @logger = Logger.new(STDOUT)

    def self.process_job(job)
      @logger.info("SSHScan::ScanEngine started for job: #{job[:uuid]}")
      scan_result = scan_engine.scan(job).to_json
      puts scan_result.inspect
      @logger.info("SSHScan::ScanEngine finished for job: #{job[:uuid]}")
      return scan_result
    end
  end
end
