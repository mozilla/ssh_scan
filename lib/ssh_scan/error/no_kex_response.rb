module SSHScan
  module Error
    # Failed to do key exchange.
    class NoKexResponse < RuntimeError
      def initialize(message)
        @message = message
      end
      def to_s
        "#{self.class.to_s.split('::')[-1]}: #{@message}"
      end
    end
  end
end
