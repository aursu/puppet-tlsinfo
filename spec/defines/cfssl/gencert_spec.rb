# frozen_string_literal: true

require 'spec_helper'

describe 'tlsinfo::cfssl::gencert' do
  let(:pre_condition) { 'include tlsinfo' }
  let(:title) { 'namevar' }
  let(:params) do
    {
      csr: 'namevar.json',
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }

      context 'when default' do
        if os_facts[:os]['family'] == 'Debian'
          it {
            is_expected.to contain_exec('cfssl-gencert-namevar')
              .with_cwd('/etc/ssl')
          }
        else
          it {
            is_expected.to contain_exec('cfssl-gencert-namevar')
              .with_cwd('/etc/pki/tls')
          }
        end
      end

      context 'when path is set' do
        let(:params) do
          super().merge(
            path: '/etc/kubernetes/pki',
          )
        end

        it {
          is_expected.to contain_exec('cfssl-gencert-namevar')
            .with_cwd('/etc/kubernetes/pki')
            .with_command('cfssl gencert -ca=ca.pem -ca-key=ca-key.pem   namevar.json | cfssljson -bare namevar')
            .with_unless('test -f /etc/kubernetes/pki/namevar.pem')
            .with_onlyif(
              [
                'test -f /etc/kubernetes/pki/ca.pem',
                'test -f /etc/kubernetes/pki/ca-key.pem'
              ]
            )
        }

        context 'and initca is set' do
          let(:params) do
            super().merge(
              initca: true,
            )
          end

          it {
            is_expected.to contain_exec('cfssl-gencert-namevar')
              .with_cwd('/etc/kubernetes/pki')
              .with_command('cfssl gencert -initca namevar.json | cfssljson -bare namevar')
              .with_unless('test -f /etc/kubernetes/pki/namevar.pem')
              .without_onlyif()
          }
        end
      end

      context 'when config is set' do
        let(:params) do
          super().merge(
            path: '/etc/kubernetes/pki',
            config: 'ca-config.json',
          )
        end

        it {
          is_expected.to contain_exec('cfssl-gencert-namevar')
            .with_cwd('/etc/kubernetes/pki')
            .with_command('cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json  namevar.json | cfssljson -bare namevar')
            .with_unless('test -f /etc/kubernetes/pki/namevar.pem')
            .with_onlyif(
              [
                'test -f /etc/kubernetes/pki/ca-config.json',
                'test -f /etc/kubernetes/pki/ca.pem',
                'test -f /etc/kubernetes/pki/ca-key.pem'
              ]
            )
        }

        context 'and profile specified' do
          let(:params) do
            super().merge(
              profile: 'kubernetes',
            )
          end

          it {
            is_expected.to contain_exec('cfssl-gencert-namevar')
              .with_cwd('/etc/kubernetes/pki')
              .with_command('cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes namevar.json | cfssljson -bare namevar')
              .with_unless('test -f /etc/kubernetes/pki/namevar.pem')
              .with_onlyif(
                [
                  'test -f /etc/kubernetes/pki/ca-config.json',
                  'test -f /etc/kubernetes/pki/ca.pem',
                  'test -f /etc/kubernetes/pki/ca-key.pem'
                ]
              )
          }
        end
      end
    end
  end
end
