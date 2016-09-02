module SSHScan
  module OS
    class Windows
      def common
        "windows"
      end

      def cpe
        "o:microsoft:windows"
      end

      def version
        nil
      end
    end
  end
end
