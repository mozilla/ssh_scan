require 'yaml'

module SSHScan
  # A helper to turn array of strings into arrays of attributes for quick comparison
  def self.make_attributes(array)
    array.map {|item| SSHScan::Attribute.new(item)}
  end

  # A class for making attribute comparison possible beyond simple string comparison
  class Attribute
    def initialize(attribute_string)
      @attribute_string = attribute_string
    end

    def to_s
      @attribute_string
    end

    def base
      @attribute_string.split("@").first
    end

    def ==(other)
      self.base == other.base
    end
  end
end