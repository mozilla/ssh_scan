require 'ssh_scan/scan_engine'

module SSHScan
  class Worker
    def process_job(job)
      SSHScan::ScanEngine.scan(job).to_json
    end
  end
end
