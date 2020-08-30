# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include tlsinfo
#
# @param certbase
#   Directory where certificate files are stored in the system (RedHat and Debian
#   based systems are predefined)
#
# @param keybase
#   Directory where private key files are stored in the system (RedHat and Debian
#   based systems are predefined)
#
# @param cfssl_version
#   Version of CF SSL toolkit to install using tlsinfo::tools::cfssl
#   see https://github.com/cloudflare/cfssl/releases
#
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
