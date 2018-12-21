module SSHScan
  module SSHLib
    class NosSSH
      class Version
        def initialize(version_string)
          @version_string = version_string
        end

        def to_s
          @version_string
        end
      end

      def initialize(banner = nil)
        @banner = banner
      end

      def version()
        return nil if @banner.nil?
        match = @banner.match(/NOS-SSH_(\d+[\.\d+]+)/)
        return nil if match.nil?
        return NosSSH::Version.new(match[1])
      end

      def common
        "nosssh"
      end

      def cpe
        "a:nosssh:nosssh" << (":" + version.to_s) unless version.nil?
      end
    end
  end
end
