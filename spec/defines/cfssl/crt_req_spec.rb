# frozen_string_literal: true

require 'spec_helper'

describe 'tlsinfo::cfssl::crt_req' do
  let(:title) { 'namevar' }
  let(:params) do
    {}
  end

  let(:default_content) do
    <<-JSONDATA
{
    "names": {
        "C": "DE",
        "ST": "Hesse",
        "L": "Frankfurt"
    },
    "key": {
        "size": 2048,
        "algo": "rsa"
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

      context 'when common name is provided' do
        let(:params) do
          {
            common_name: 'Kubernetes',
            path: '/etc/kubernetes/pki/',
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/namevar.json')
            .with_content(%r{"CN": "Kubernetes",$})
        }
      end

      context 'when common name is provided in req as well' do
        let(:params) do
          {
            common_name: 'Kubernetes',
            path: '/etc/kubernetes/pki/',
            req: {
              'CN' => 'K8S Cluster',
              names: {},
              key: {
                algo: 'rsa',
                size: 4096,
              }
            },
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/namevar.json')
            .with_content(%r{"CN": "K8S Cluster",$})
        }

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/namevar.json')
            .with_content(%r{"size": 4096,$})
        }
      end

      context 'when names is provided in few sources' do
        let(:params) do
          {
            path: '/etc/kubernetes/pki/',
            names: {
              'L' => 'Hamburg',
            },
            req: {
              'CN' => 'Kubernetes',
              names: {
                'L' => 'Berlin',
                'ST' => 'Berlin',
              },
              key: {
                algo: 'rsa',
                size: 4096,
              }
            },
          }
        end

        it {
          is_expected.to contain_file('/etc/kubernetes/pki/namevar.json')
            .with_content(%r{"L": "Berlin"})
        }
      end
    end
  end
end
