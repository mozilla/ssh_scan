module SSHScan
  module Error
    # Target did not respond with an SSH banner.
    class NoBanner < RuntimeError
      def initialize(message)
        @message = message
      end
      def to_s
        "#{self.class.to_s.split('::')[-1]}: #{@message}"
      end
    end
  end
end
