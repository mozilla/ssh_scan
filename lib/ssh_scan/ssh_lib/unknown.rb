module SSHScan
  module SSHLib
    class Unknown
      def common
        "unknown"
      end

      def cpe
        "a:unknown"
      end

      def version
        nil
      end
    end
  end
end
