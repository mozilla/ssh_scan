module SSHScan
  module OS
    class Ubuntu
      def common
        "ubuntu"
      end

      def cpe
        "o:canonical:ubuntu"
      end
    end
  end
end
