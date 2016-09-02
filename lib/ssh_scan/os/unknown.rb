module SSHScan
  module OS
    class Unknown
      def common
        "unknown"
      end

      def cpe
        "o:unknown"
      end

      def version
        nil
      end
    end
  end
end
