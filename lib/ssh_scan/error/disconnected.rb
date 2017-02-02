module SSHScan
  module Error
    # Got disconnected somehow.
    class Disconnected < RuntimeError
      def initialize(message)
        @message = message
      end
      def to_s
        "#{self.class.to_s.split('::')[-1]}: #{@message}"
      end
    end
  end
end
