require 'spec_helper'
require 'rspec'
require_relative '../helper'

describe SSHScan::Banner do
  context "when dropbear fingerprinting" do
    expectations = {}

    # Scraped from Dropbear's Changelog
    VERSIONS = ["2016.74", "2016.73", "2016.72", "2015.71", "2015.70",
                "2015.69", "2015.68", "2015.67", "2014.66", "2014.65",
                "2014.64", "2014.63", "2013.62", "2013.61test", "2013.60",
                "2013.59", "2013.58", "2013.57", "2013.56", "2012.55",
                "2011.54", "0.53.1", "0.53", "0.52", "0.51", "0.50",
                "0.49", "0.48.1", "0.48", "0.47", "0.46", "0.45", "0.44",
                "0.44test4", "0.44test3", "0.44test2", "0.44test1", "0.43",
                "0.42", "0.41", "0.40", "0.39", "0.38", "0.37", "0.36",
                "0.35", "0.34", "0.33", "0.32", "0.31", "0.30", "0.29",
                "0.28"]
    VERSIONS.each do |dropbear_version|
      expectations["SSH-2.0-dropbear_#{dropbear_version}"] = {
        :ssh_lib_class => SSHScan::SSHLib::Dropbear,
        :ssh_lib_version => dropbear_version,
        :ssh_lib_cpe => "a:dropbear:dropbear:#{dropbear_version}",
      }
    end
    checkFingerprints(expectations)
  end
end
