#
class tlsinfo::params {
  if $facts['os']['name'] in ['Ubuntu', 'Debian'] {
    $certbase = '/etc/ssl/certs'
    $keybase  = '/etc/ssl/private'
  }
  else {
    $certbase = '/etc/pki/tls/certs'
    $keybase  = '/etc/pki/tls/private'
  }

  # predefined CFSSL version - could  be overriden with kubeinstall::cfssl_version
  $cfssl_version          = '1.4.1'
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
    'multirootca'
  ]

  $cfssl_checksum_command = 'sha256sum'
  $download_tmpdir        = '/tmp'
}
