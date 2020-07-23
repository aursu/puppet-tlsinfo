require 'spec_helper'

describe 'tlsinfo::tools::cfssl' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'version' => '1.4.0-rc1',
        }
      end

      it { is_expected.to compile }

      it {
        is_expected.to contain_exec('cfssl-checksum')
          .with_command('curl -L https://github.com/cloudflare/cfssl/releases/download/v1.4.0-rc1/cfssl_1.4.0-rc1_checksums.txt -o cfssl_1.4.0-rc1_checksums.txt')
          .with_creates('/tmp/cfssl_1.4.0-rc1_checksums.txt')
          .with_cwd('/tmp')
      }

      ['cfssl', 'cfssl-bundle', 'cfssl-certinfo', 'cfssl-newkey', 'cfssl-scan',
       'cfssljson', 'mkbundle', 'multirootca'].each do |bin|
        it {
          is_expected.to contain_exec("#{bin}-download")
            .with_command("curl -L https://github.com/cloudflare/cfssl/releases/download/v1.4.0-rc1/#{bin}_1.4.0-rc1_linux_amd64 -o #{bin}_1.4.0-rc1_linux_amd64")
            .with_unless("grep -w #{bin}_1.4.0-rc1_linux_amd64 cfssl_1.4.0-rc1_checksums.txt | sha256sum -c")
            .with_cwd('/tmp')
            .that_requires('Exec[cfssl-checksum]')
        }

        it {
          is_expected.to contain_file(bin)
            .with_path("/usr/local/bin/#{bin}")
            .with_source("file:///tmp/#{bin}_1.4.0-rc1_linux_amd64")
            .that_subscribes_to("Exec[#{bin}-download]")
        }
      end
    end
  end
end
