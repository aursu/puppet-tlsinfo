# Certificate pair
#
# @summary Certificate pair.
#
# Description
#
# Name of resource must match TLS certificate Common Name subject field. Both
# TLS certificate and private keys must be defined or available in Hiera
#
# Parameters
#
# @param name
#   It is used as lookup key if not provided and as identity unless `identity`
#   parameter is false
#
# @param cert
#   Certificate PEM encoded data. If not provided, Puppet will look for certificate
#   data into Hiera using function `lookup()` by key `${name}_certificate`.
#   Otherwise it will use provided value
#
# @param pkey
#   Private key PEM encoded data. If not provided, Puppet will look for certificate
#   data into Hiera using function `lookup()` by key `${name}_private`. Otherwise
#   it will use provided value
#
# @param cacert
#   If String provided it will be used as one of (with same priority by looking
#   through Puppet catalog):
#   - path to TLS certificate
#   - certificate subject hash
#   - Puppet Sslcertificate resource title
#   If Boolean true provided, Puppet will look for CA intermediate certificate
#   through resources catalog using Issuer field hash from `cert` parameter.
#   If Boolean false provided - we don't care about CA intermediate certificate
#   If Array of String provided - each String would be handled separately as part
#   of CA chain
#
# @param lookupkey
#   If `cert` is not provided Puppet will use `lookup()` function with lookup key
#   `<lookupkey>_certifiacte` for SSL certificate and lookup key `<lookupkey>_private`
#   for SSL privae key
#   If lookupkey is `undef` it will use `$name` as lookupkey
#
# @param secret
#   Password for encrypted private key
#
# @param certbase
#   Directory where certificate files are stored in the system (RedHat and Debian
#   based systems are predefined)
#
# @param keybase
#   Directory where private key files are stored in the system (RedHat and Debian
#   based systems are predefined)
#
# @param identity
#   Identtity which certificate should represent (eg domain name). Certificate
#   Common Name or any of DNS names must match identity field
#   If Boolean true - resource `$name` is used as identity
#   If String - it will be used as identity alon with `$name`
#   If Array - it will be used as array of identities along with `$name`
#
# @param rootca
#   Whether to place Root CA certificate into certificate file or not
#
# @param validate
#   Whether to validate certificate expiration (Allow to define expired
#   certificates in Puppet catalog to not fail catalog compilation)
#
# @param strict
#   Whether to validate Root CA validity
#
# @example
#    tlsinfo::certpair { $server_name:
#      identity => true,
#      cert     => $ssl_cert,
#      pkey     => $ssl_key,
#      # in case of self signed CA
#      strict   => false,
#    }
define tlsinfo::certpair (
  Optional[String] $lookupkey = undef,
  Optional[String] $cert = undef,
  Optional[String] $pkey = undef,
  Optional[String] $secret = undef,
  Variant[
    Boolean,
    Stdlib::Unixpath,
    Array[Stdlib::Unixpath]
  ] $cacert = true,
  Optional[Stdlib::Unixpath] $certbase = $tlsinfo::certbase,
  Optional[Stdlib::Unixpath] $keybase = $tlsinfo::keybase,
  Optional[
    Variant[
      Boolean,
      String,
      Array[String, 1]
    ]
  ] $identity = undef,
  Boolean $rootca = false,
  Boolean $validate = true,
  Boolean $strict = true,
) {
  if $lookupkey {
    $hierakey = tlsinfo::normalize($lookupkey)
  }
  else {
    $hierakey = tlsinfo::normalize($name)
  }

  if $cert {
    $certdata = $cert
  }
  else {
    $certdata = tlsinfo::lookup($hierakey)
  }

  unless $certdata {
    fail("Certificate data does not exists. Please specify either parameter \$cert or Hiera key \"${hierakey}_certificate\"")
  }

  if $pkey {
    $pkeydata = $pkey
  }
  else {
    $pkeydata = tlsinfo::lookup($hierakey, true)
  }

  unless $pkeydata {
    fail("Private key data does not exists. Please specify either parameter \$pkey or Hiera key \"${hierakey}_private\"")
  }

  if $identity =~ Boolean and $identity {
    $identityinfo = $name
  }
  # tlsinfo::certpair name (title) must match one of ceritficate names
  elsif $identity =~ Array {
    $identityinfo = $identity + [$name]
  }
  elsif $identity =~ String {
    $identityinfo = [$identity, $name]
  }
  else {
    $identityinfo = undef
  }

  $keypath = tlsinfo::keypath($certdata, $keybase)
  sslkey { $keypath:
    content  => $pkeydata,
    password => $secret,
  }

  $certpath = tlsinfo::certpath($certdata, $certbase)
  sslcertificate { $certpath:
    content    => $certdata,
    pkey       => $keypath,
    cacert     => $cacert,
    identity   => $identityinfo,
    rootca     => $rootca,
    expiration => $validate,
    strict     => $strict,
  }
}
