# A description of what this defined type does
#
# @summary A short summary of the purpose of this defined type.
#
# @example
#   tlsinfo::certificate { 'namevar': }
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
# @param path
#   Absolute path or relative to system certificate base directory where
#   provided (with parameter "cert") or found (using Hiera key
#   "#{name}_certificate") certificate data should be stored (as is without
#   verification and processing)
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
