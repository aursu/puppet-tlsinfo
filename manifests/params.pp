class tlsinfo::params {
  if $facts['os']['name'] in ['Ubuntu', 'Debian'] {
    $certbase = '/etc/ssl/certs'
    $keybase  = '/etc/ssl/private'
  }
  else {
    $certbase = '/etc/pki/tls/certs'
    $keybase  = '/etc/pki/tls/private'
  }
}
