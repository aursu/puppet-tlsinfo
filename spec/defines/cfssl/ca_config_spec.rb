# frozen_string_literal: true

require 'spec_helper'

describe 'tlsinfo::cfssl::ca_config' do
  let(:title) { 'namevar' }
  let(:params) do
    {}
  end

  let(:default_content) do
    <<-JSONDATA
{
    "signing": {
        "default": {
            "expiry": "43824h"
        },
        "profiles": {
        }
    }
}
JSONDATA
  end

  let(:sample_content) do
    <<-JSONDATA
{
    "signing": {
        "default": {
            "expiry": "43824h"
        },
        "profiles": {
            "kubernetes": {
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth",
                    "client auth"
                ],
                "expiry": "43824h"
            }
        }
    }
}
JSONDATA
  end

  let(:sample_default_profile) do
    <<-JSONDATA
{
    "signing": {
        "default": {
            "usages": [
                "signing",
                "key encipherment",
                "server auth",
                "client auth"
            ],
            "expiry": "8760h"
        },
        "profiles": {
        }
    }
}
JSONDATA
  end

  let(:sample_default_profile_no_expire) do
    <<-JSONDATA
{
    "signing": {
        "default": {
            "usages": [
                "signing",
                "key encipherment",
                "server auth",
                "client auth"
            ],
            "expiry": "43824h"
        },
        "profiles": {
        }
    }
}
JSONDATA
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }

      if os_facts[:os]['family'] == 'Debian'
        it {
          is_expected.to contain_file('/etc/ssl/namevar.json')
            .with_content(default_content)
        }
      else
        it {
          is_expected.to contain_file('/etc/pki/tls/namevar.json')
            .with_content(default_content)
        }
      end

      context 'when path specified' do
        let(:title) { 'ca_config' }
        let(:params) do
          {
            path: '/etc/kubernetes/pki',
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/ca_config.json')
        }
      end

      context 'when path ends with .json' do
        let(:params) do
          {
            path: '/etc/kubernetes/pki/ca_config.json',
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/ca_config.json')
        }
      end

      context 'when path ends with /' do
        let(:params) do
          {
            path: '/etc/kubernetes/pki/',
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/namevar.json')
        }
      end

      context 'when signing profiles specified' do
        let(:params) do
          {
            signing_profiles: {
              'kubernetes' => {
                usages: ['signing', 'key encipherment', 'server auth', 'client auth'],
                expiry: '43824h',
              },
            },
            path: '/etc/kubernetes/pki/',
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/namevar.json')
            .with_content(sample_content)
        }
      end

      context 'when default profile specified' do
        let(:params) do
          {
            default_profile: {
              usages: ['signing', 'key encipherment', 'server auth', 'client auth'],
              expiry: '8760h',
            },
            path: '/etc/kubernetes/pki/',
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/namevar.json')
            .with_content(sample_default_profile)
        }
      end

      context 'when default profile specified w/o expiry' do
        let(:params) do
          {
            default_profile: {
              usages: ['signing', 'key encipherment', 'server auth', 'client auth'],
            },
            path: '/etc/kubernetes/pki/',
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/namevar.json')
            .with_content(sample_default_profile_no_expire)
        }
      end
    end
  end
end
