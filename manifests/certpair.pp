# Certificate data pair
#
# @summary Certificate data pair.
#
# Description
#
# Name of resource must match TLS certificate Common Name subject field. Both
# TLS certificate and private keys must be defined or available in Hiera
#
# Parameters
#
# [*cert*]
#
# String. Default value is undef (optional). Certificate PEM encoded data.If not
# provided, Puppet will look for certificate data into Hiera using function
# lookup() by key "${name}_certificate". Otherwise it will use provided value
#
# [*pkey*]
#
# String. Default value is undef (optional). Private key PEM encoded data. If
# not provided, Puppet will look for certificate data into Hiera using function
# lookup() by key "${name}_private". Otherwise it will use provided value
#
# [*cacert*]
#
# String, Boolean or Array of String.
# If String provided it will be used as one of (with same priority by looking
# through Puppet catalog):
# - path to TLS certificate
# - certificate subject hash
# - Puppet Sslcertificate resource title
# If Boolean true provided, Puppet will look for CA intermediate certificate
# through resources catalog using Issuer field hash from $cert parameter.
# If Boolean false provided - we don't care about CA intermediate certificate
# If Array of String provided - each String would be handled separately as part
# of CA chain
#
# @example
#   tlsinfo::certpair { 'namevar': }
define tlsinfo::certpair (
    Optional[String]
            $cert     = undef,
    Optional[String]
            $pkey     = undef,
    Optional[
        Variant[
            Boolean,
            Stdlib::Unixpath,
            Array[Stdlib::Unixpath]
        ]
    ]       $cacert   = true,
    Optional[Stdlib::Unixpath]
            $certbase = $tlsinfo::certbase,
    Optional[Stdlib::Unixpath]
            $keybase  = $tlsinfo::keybase,
)
{
    $lookupkey = tlsinfo::normalize($name)
    if $cert {
        $certdata = $cert
    }
    else {
        $certdata = lookup("${lookupkey}_certificate", Optional[String], 'first', undef)
    }

    unless $certdata {
        fail("Certificate data does not exists. Please specify either parameter \$cert or Hiera key \"${lookupkey}_certificate\"")
    }

    if $pkey {
        $pkeydata = $pkey
    }
    else {
        $pkeydata = lookup("${lookupkey}_private", Optional[String], 'first', undef)
    }

    unless $pkeydata {
        fail("Private key data does not exists. Please specify either parameter \$pkey or Hiera key \"${lookupkey}_private\"")
    }

    $keypath = tlsinfo::keypath($certdata, $keybase)
    sslkey { $keypath:
        content => $pkeydata,
    }

    $certpath = tlsinfo::certpath($certdata, $certbase)
    sslcertificate { $certpath:
        content => $certdata,
        pkey    => $keypath,
        # cacert  => $cacert,
        cacert  => 'LetsEncryptAuthorityX3',
    }
}
