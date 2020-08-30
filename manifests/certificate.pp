# SSL certificate setup
#
# @summary SSL certificate setup
#
# @example
#   Considering 'basepath' as '/etc/pki/tls/certs' (default to CentOS)
#   this will create certificate file '/etc/pki/tls/certs/<subject_hash>.pem' as well
#   as will create file '/etc/pki/tls/certs/4f06f81d.crt' and also will create symlink
#   '/etc/pki/tls/certs/LetsEncryptAuthorityX3.pem' which points to '<subject_hash>.pem'
#   Also it will push content of Intermediate CA certificate into certificate
#   file as well as Root CA certificate
#
#   tlsinfo::certificate { "/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3":
#     cert   => file('profile/certs/4f06f81d.crt'),
#     link   => 'LetsEncryptAuthorityX3.pem',
#     path   => '4f06f81d.crt',
#     cacert => true,
#     rootca => true,
#   }
#
#   Example of intermediate certificates chain:
#
#   tlsinfo::certificate { '/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO High Assurance Secure Server CA':
#     cert => file('profile/certs/ComodoHighAssuranceSecureServerCA.crt'),
#     link => 'ComodoHighAssuranceSecureServerCA.pem',
#     path => 'ComodoHighAssuranceSecureServerCA.crt',
#   }
#
#   tlsinfo::certificate { '/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Domain Validation Secure Server CA':
#     cert   => file('profile/certs/COMODORSADomainValidationSecureServerCA.crt'),
#     link   => 'COMODORSADomainValidationSecureServerCA.pem',
#     path   => 'COMODORSADomainValidationSecureServerCA.crt',
#     cacert => true,
#   }
#
# @param cert
#   Certificate data to use for verification and processing. If not provided
#   tlsinfo::certificate will look for Hiera key "#{name}_certificate" with
#   "name" normalized with next rules (string replacement):
#     1) '*' -> 'wildcard'
#     2) '.' -> '_'
#     3) '-' -> '_'
#     4) "'" -> '_'
#     5) ' ' -> '_'
#
# @param basepath
#   System path where certificate data usually stored (eg /etc/pki/tls/certs on CentOS)
#
# @param cacert
#   Could be Boolean true or false:
#   * `true` means CA Intermediate certificate already MUST be defined in catalog
#   * `false` means we do not manage CA Intermediate certificate
#     (therefore validation over CA will not happen)
#   Also could be a Full path to certificate or array of paths (for example, if
#  certificate chain has 2 or more Intermediate CA)
#
# @param path
#   Absolute path or relative to system certificate base directory where
#   certificate data either provided with parameter `cert` or found using Hiera key
#   `#{name}_certificate` should be stored. It will be saved "as is" without
#   verification and processing
#
# @param rootca
#   Whether to place Root CA certificate into certificate file or not
#
# @param chain
#   Whether to place Intermediate certificate into certificate file or not
#
# @param link
#   If provided - will create human  symbolic link to certificate file (with link
#   name provided)
#
define tlsinfo::certificate (
    Optional[String]
            $cert     = undef,
    Optional[Stdlib::Unixpath]
            $basepath = $tlsinfo::certbase,
    Optional[
        Variant[
            Boolean,
            Stdlib::Unixpath,
            Array[Stdlib::Unixpath]
        ]
    ]       $cacert = undef,
    Boolean $rootca = false,
    Boolean $chain  = true,
    Optional[
        Variant[
            Stdlib::Unixpath,
            Pattern[/^[^\/]+\.pem$/]  # basename (relative to basepath/certbase)
        ]
    ]       $link    = undef,
    Optional[
        Variant[
            Stdlib::Unixpath,
            Pattern[/^[^\/]+\.(pem|crt|cer|cert)$/]  # basename (relative to basepath/certbase)
        ]
    ]       $path    = undef,
) {
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

    $certpath = tlsinfo::certpath($certdata, $basepath)

    sslcertificate { $certpath:
        content => $certdata,
        cacert  => $cacert,
        rootca  => $rootca,
        chain   => $chain,
    }

    if $link {
        $link_path = $link? {
            Stdlib::Unixpath => $link,
            default          => "${basepath}/${link}",
        }
        # create human readable symlink to certificate
        file { $link_path:
            ensure  => 'link',
            target  => $certpath,
            require => Sslcertificate[$certpath],
        }
    }

    if $path {
        $data_path = $path? {
            Stdlib::Unixpath => $path,
            default          => "${basepath}/${path}",
        }

        file { $data_path:
            ensure  => file,
            content => $certdata,
        }
    }
}
