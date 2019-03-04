# A description of what this defined type does
#
# @summary A short summary of the purpose of this defined type.
#
# @example
#   tlsinfo::certificate { 'namevar': }
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
}
