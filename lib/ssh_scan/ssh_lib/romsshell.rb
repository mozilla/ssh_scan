module SSHScan
  module SSHLib
    class RomSShell
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
        match = @banner.match(/RomSShell_(\d+[\.\d+]+(p)?(\d+)?)/)
        return nil if match.nil?
        return RomSShell::Version.new(match[1])
      end

      def common
        "romsshell"
      end

      def cpe
        "a:allegrosoft:romsshell" << (":" + version.to_s) unless version.nil?
      end
    end
  end
end
