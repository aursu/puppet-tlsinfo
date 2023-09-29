#
class tlsinfo::params {
  include bsys::params

  # moved to bsys as basic system settings
  $certbase = $bsys::params::certbase
  $keybase  = $bsys::params::keybase

  # predefined CFSSL version - could  be overriden with kubeinstall::cfssl_version
  $cfssl_version          = '1.6.4'
  $cfssl_download_source  = 'https://github.com/cloudflare/cfssl/releases/download'

  # cfssl project provides binaries only for x86_64 architecture
  # for Windows, Linux and Darwin
  # see https://github.com/cloudflare/cfssl/releases
  $cfssl_tools = [
    'cfssl',
    'cfssl-bundle',
    'cfssl-certinfo',
    'cfssl-newkey',
    'cfssl-scan',
    'cfssljson',
    'mkbundle',
    'multirootca',
  ]

  $download_tmpdir        = '/tmp'
}
