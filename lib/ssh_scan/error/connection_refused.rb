module SSHScan
  module Error
    # Target refused connection attempt.
    class ConnectionRefused < RuntimeError
      def initialize(message)
        @message = message
      end
      def to_s
        "#{self.class.to_s.split('::')[-1]}: #{@message}"
      end
    end
  end
end
