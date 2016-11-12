require 'ssh_scan/scan_engine'

module SSHScan
  class Worker
    scan_engine = SSHScan::ScanEngine.new()

    def process_job(job)
      scan_engine.scan(job).to_json
    end
  end
end
