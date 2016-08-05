module SSHScan
  module OS
    class Debian
      def common
        "debian"
      end

      def cpe
        "o:debian:debian"
      end
    end
  end
end
