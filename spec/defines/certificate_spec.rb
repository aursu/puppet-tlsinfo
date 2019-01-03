require 'spec_helper'

describe 'tlsinfo::certificate' do
  let(:title) { 'namevar' }
  let(:params) do
    {}
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:pre_condition) { "class {'tlsinfo': }" }

      context 'with default parameters' do
        let(:title) { 'www.domain.com' }

        it {
          is_expected
            .to compile
            .and_raise_error(%r{Certificate data does not exists. Please specify either parameter \$cert or Hiera key "www_domain_com_certificate"})
        }
      end
    end
  end
end
