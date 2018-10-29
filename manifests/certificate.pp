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
            $basepath = $tlsinfo::basepath,
) {
    if $cert {
        $certdata = $cert
    }
    else {
        $certdata = lookup("${name}_certificate", Optional[String], 'first', undef)
    }

    unless $certdata {
        fail("Certificate data does not exists. Please specify either parameter \$cert or Hiera key \"${name}_certificate\"")
    }

    $certpath = tlsinfo::certpath($certdata, $basepath)

    sslcertificate { $certpath:
        content => $certdata,
    }
}
