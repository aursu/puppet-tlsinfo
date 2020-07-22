# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include tlsinfo
class tlsinfo (
    Optional[Stdlib::Unixpath]
        $certbase,
    Optional[Stdlib::Unixpath]
        $keybase,
    Optional[String]
        $cfssl_version,
){
    include tlsinfo::params
}
