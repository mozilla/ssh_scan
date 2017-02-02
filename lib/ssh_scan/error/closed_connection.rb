module SSHScan
  module Error
    # Connection closed from the other side.
    class ClosedConnection < RuntimeError
      def to_s
        "#{self.class.to_s.split('::')[-1]}"
      end
    end
  end
end
