module SSHScan
  module SSHLib
    class CiscoSSH
      def common
        "ciscossh"
      end

      def cpe
        "a:cisco:ciscossh"
      end
      
      def version
        nil
      end
    end
  end
end
