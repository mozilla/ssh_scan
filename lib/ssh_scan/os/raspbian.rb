module SSHScan
  module OS
    class Raspbian
      def common
        "raspbian"
      end

      def cpe
        "o:raspbian:raspbian"
      end

      def version
        nil
      end
    end
  end
end
