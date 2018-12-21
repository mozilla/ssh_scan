module SSHScan
  module OS
    class CentOS
      def common
        "centos"
      end

      def cpe
        "o:centos:centos"
      end

      def version
        nil
      end
    end
  end
end
