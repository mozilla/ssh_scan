require 'rspec'
require 'ssh_scan/version'

describe SSHScan::VERSION do
  it "SSHScan::VERSION should be a string" do
    expect(SSHScan::VERSION).to be_kind_of(::String)
  end

  it "SSHScan::VERSION should have 3 levels" do
    expect(SSHScan::VERSION.split('.').size).to eql(3)
  end
end
