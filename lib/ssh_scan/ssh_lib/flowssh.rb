module SSHScan
  module SSHLib
    class FlowSsh
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
        match = @banner.match(/(\d+[\.\d+]+(p)?(\d+)?) FlowSsh/)
        return nil if match.nil?
        return FlowSsh::Version.new(match[1])
      end

      def common
        "flowssh"
      end

      def cpe
        "a:bitvise:flowssh" << (":" + version.to_s) unless version.nil?
      end
    end
  end
end
