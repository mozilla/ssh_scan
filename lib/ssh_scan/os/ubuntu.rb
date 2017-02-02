module SSHScan
  module OS
    class Ubuntu
      attr_reader :version

      class Version
        def initialize(version_string)
          @version_string = version_string
        end

        def to_s
          @version_string
        end
      end

      # Obtained from scraping ChangeLog on Launchpad
      FINGERPRINTS = {
       "4.10" => [
         "3.8.1p1-11ubuntu3.3",
         "3.8.1p1-11ubuntu3.2",
         "3.8.1p1-11ubuntu3"
       ],
       "5.04" => [
         "3.9p1-1ubuntu2.3",
         "3.9p1-1ubuntu2.2",
         "3.9p1-1ubuntu2.1",
         "3.9p1-1ubuntu2"
       ],
       "5.10" => [
         "4.1p1-7ubuntu4.2",
         "4.1p1-7ubuntu4.1",
         "4.1p1-7ubuntu4"
       ],
       "6.04" => [
         "4.2p1-7ubuntu3.5",
         "4.2p1-7ubuntu3.4",
         "4.2p1-7ubuntu3.3",
         "4.2p1-7ubuntu3.2",
         "4.2p1-7ubuntu3.1",
         "4.2p1-7ubuntu3",
         "4.2p1-7ubuntu2",
         "4.2p1-7ubuntu1",
         "4.2p1-5ubuntu2",
         "4.2p1-5ubuntu1"
       ],
       "6.10" => [
         "4.3p2-5ubuntu1.2",
         "4.3p2-5ubuntu1.1",
         "4.3p2-5ubuntu1",
         "4.3p2-4ubuntu1",
         "4.3p2-2ubuntu5",
         "4.3p2-2ubuntu4",
         "4.3p2-2ubuntu3",
         "4.3p2-2ubuntu2",
         "4.3p2-2ubuntu1"
       ],
       "7.04" => [],
       "7.10" => [
         "4.6p1-5ubuntu0.6",
         "4.6p1-5ubuntu0.5",
         "4.6p1-5ubuntu0.4",
         "4.6p1-5ubuntu0.3",
         "4.6p1-5ubuntu0.2",
         "4.6p1-5ubuntu0.1",
         "4.6p1-5build1",
         "4.3p2-10ubuntu1"
       ],
       "8.04" => [
         "4.7p1-8ubuntu3",
         "4.7p1-8ubuntu2",
         "4.7p1-8ubuntu1.2",
         "4.7p1-8ubuntu1.1",
         "4.7p1-8ubuntu1",
         "4.7p1-7ubuntu1",
         "4.7p1-6ubuntu1",
         "4.7p1-5ubuntu1",
         "4.7p1-4ubuntu1"
       ],
       "8.10" => [
         "5.1p1-3ubuntu1",
         "5.1p1-1ubuntu2",
         "5.1p1-1ubuntu1",
         "4.7p1-12ubuntu4",
         "4.7p1-12ubuntu3",
         "4.7p1-12ubuntu2",
         "4.7p1-12ubuntu1",
         "4.7p1-10ubuntu1",
         "4.7p1-9ubuntu1"
       ],
       "9.04" => [
         "5.1p1-5ubuntu1",
         "5.1p1-4ubuntu1"
       ],
       "9.10" => [
         "5.1p1-6ubuntu2",
         "5.1p1-6ubuntu1",
         "5.1p1-5ubuntu2"
       ],
       "10.04" => [
         "5.3p1-3ubuntu7.1",
         "5.3p1-3ubuntu7",
         "5.3p1-3ubuntu6",
         "5.3p1-3ubuntu5",
         "5.3p1-3ubuntu4",
         "5.3p1-3ubuntu3",
         "5.3p1-3ubuntu2",
         "5.3p1-3ubuntu1",
         "5.3p1-1ubuntu2",
         "5.3p1-1ubuntu1",
         "5.2p1-2ubuntu1",
         "5.2p1-1ubuntu1",
         "5.1p1-8ubuntu2",
         "5.1p1-8ubuntu1"
       ],
       "10.10" => [
         "5.5p1-4ubuntu6",
         "5.5p1-4ubuntu5",
         "5.5p1-4ubuntu4",
         "5.5p1-4ubuntu3",
         "5.5p1-4ubuntu2",
         "5.5p1-4ubuntu1",
         "5.5p1-3ubuntu1"
       ],
       "11.04" => [
         "5.8p1-1ubuntu3",
         "5.8p1-1ubuntu2",
         "5.8p1-1ubuntu1",
         "5.7p1-2ubuntu1",
         "5.7p1-1ubuntu1",
         "5.6p1-2ubuntu4",
         "5.6p1-2ubuntu3",
         "5.6p1-2ubuntu2",
         "5.6p1-2ubuntu1",
         "5.6p1-1ubuntu1"
       ],
       "11.10" => [
         "5.8p1-7ubuntu1",
         "5.8p1-4ubuntu2",
         "5.8p1-4ubuntu1"
       ],
       "12.04" => [
         "5.9p1-5ubuntu1.10",
         "5.9p1-5ubuntu1.9",
         "5.9p1-5ubuntu1.8",
         "5.9p1-5ubuntu1.7",
         "5.9p1-5ubuntu1.6",
         "5.9p1-5ubuntu1.4",
         "5.9p1-5ubuntu1.3",
         "5.9p1-5ubuntu1.2",
         "5.9p1-5ubuntu1.1",
         "5.9p1-5ubuntu1",
         "5.9p1-4ubuntu1",
         "5.9p1-3ubuntu1",
         "5.9p1-2ubuntu2",
         "5.9p1-2ubuntu1",
         "5.9p1-1ubuntu1"
       ],
       "12.10" => [
         "6.0p1-3ubuntu1.2",
         "6.0p1-3ubuntu1.1",
         "6.0p1-3ubuntu1",
         "6.0p1-2ubuntu1",
         "6.0p1-1ubuntu1"
       ],
       "13.04" => [
         "6.1p1-1ubuntu1"
       ],
       "13.10" => [
         "6.2p2-6ubuntu0.5",
         "6.2p2-6ubuntu0.4",
         "6.2p2-6ubuntu0.3",
         "6.2p2-6ubuntu0.2",
         "6.2p2-6ubuntu0.1"
       ],
       "14.04" => [
         "6.6p1-2ubuntu2.8",
         "6.6p1-2ubuntu2.7",
         "6.6p1-2ubuntu2.6",
         "6.6p1-2ubuntu2.5",
         "6.6p1-2ubuntu2.4",
         "6.6p1-2ubuntu2.3",
         "6.6p1-2ubuntu2.2",
         "6.6p1-2ubuntu2",
         "6.6p1-2ubuntu1",
         "6.2p2-6ubuntu1",
         "6.6.1p1 Ubuntu-8"
       ],
       "14.10" => [
         "6.6p1-5build1"
       ],
       "15.04" => [
         "6.7p1-5ubuntu1.4",
         "6.7p1-5ubuntu1.3",
         "6.7p1-5ubuntu1.2",
         "6.7p1-5ubuntu1"
       ],
       "15.10" => [
         "6.9p1-2ubuntu0.2",
         "6.9p1-2ubuntu0.1",
         "6.7p1-6ubuntu2",
         "6.7p1-6ubuntu1"
       ],
       "16.04" => [
         "7.2p2-4ubuntu2.1",
         "7.2p2-4ubuntu2",
         "7.2p2-4ubuntu1"
       ],
       "16.10" => []
      }

      def initialize(banner)
        @banner = banner
        @version = Ubuntu::Version.new(ubuntu_version_guess)
      end

      def common
        "ubuntu"
      end

      # Get the FINGERPRINTS constant hash, generated from the
      # scraping script.
      # @return [Hash<String, Array<String>>] FINGERPRINTS constant
      #   hash
      def fingerprints
        OS::Ubuntu::FINGERPRINTS
      end

      def ubuntu_version_guess
        possible_versions = []
        OS::Ubuntu::FINGERPRINTS.keys.each do |ubuntu_version|
          OS::Ubuntu::FINGERPRINTS[ubuntu_version].uniq.each do |banner|
            openssh_ps, ubuntu_sig = banner.split("-")
            openssh_version = openssh_ps
            # If the version is like 6.6p1, deduce that
            if openssh_ps.include?("p")
              openssh_version = openssh_ps.split("p")[0]
            end
            if @banner.include?("OpenSSH_#{openssh_version}") &&
               @banner.include?(ubuntu_sig)
              possible_versions << ubuntu_version
            end
          end
        end
        possible_versions.uniq!
        if possible_versions.any?
          return possible_versions.join("|")
        end
        return nil
      end

      def cpe
        "o:canonical:ubuntu" + (@version.to_s ? ":#{@version}" : "")
      end
    end
  end
end
