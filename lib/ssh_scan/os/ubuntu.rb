module SSHScan
  module OS
    class Ubuntu
      def common
        "ubuntu"
      end

      def cpe
        "o:canonical:freebsd"
      end
    end
  end
end
