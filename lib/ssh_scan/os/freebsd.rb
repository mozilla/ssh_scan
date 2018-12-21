module SSHScan
  module OS
    class FreeBSD
      def common
        "freebsd"
      end

      def cpe
        "o:freebsd:freebsd"
      end

      def version
        nil
      end
    end
  end
end
