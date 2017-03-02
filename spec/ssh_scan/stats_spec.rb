require 'spec_helper'
require 'ssh_scan/stats'

describe SSHScan::Stats do
  it "should have zero requests to start with" do
    stats = SSHScan::Stats.new
    expect(stats.size).to eql(0)
  end

  it "should increment requests with new_scan_request" do
    stats = SSHScan::Stats.new
    expect(stats.size).to eql(0)

    stats.new_scan_request
    expect(stats.size).to eql(1)

    stats.new_scan_request
    expect(stats.size).to eql(2)
  end

  it "should track requests per min" do
    stats = SSHScan::Stats.new

    # Should see the request in the search path
    stats.new_scan_request
    expect(stats.size).to eql(1)
    expect(stats.requests_per(2)).to eql(1)

    # After the time window, it should have fallen off
    sleep 2
    expect(stats.requests_per(2)).to eql(0)
  end

  it "should purge old requests" do
    stats = SSHScan::Stats.new

    # Should see the request in the search path
    stats.new_scan_request
    expect(stats.size).to eql(1)
    stats.purge_old_requests
    expect(stats.size).to eql(1)

    # After the time window, it should have fallen off
    sleep 3
    stats.purge_old_requests(2)
    expect(stats.size).to eql(0)
  end

  it "should determine request average for a time period" do
    stats = SSHScan::Stats.new()

    # Should see the request in the search path
    stats.new_scan_request
    expect(stats.requests_avg_per(1)).to eql(1.0)
    expect(stats.requests_avg_per(2)).to eql(0.5)

    5.times { stats.new_scan_request }
    expect(stats.requests_avg_per(5)).to eql(1.2)
  end
end
