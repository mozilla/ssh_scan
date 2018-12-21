module SSHScan
  module OS
    class RedHat
      def common
        "redhat"
      end

      def cpe
        "o:redhat:redhat"
      end

      def version
        nil
      end
    end
  end
end
