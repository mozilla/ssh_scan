module SSHScan
  module Error
    class ClosedConnection < Exception
      def to_s
        "#{self.class.to_s.split('::')[-1]}"
      end
    end
  end
end
