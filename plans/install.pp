# @summary Install certificate and private key
#
# Install certificate and private key. Works only in conjuction
# with Hiera
#
# @param targets
#   Nodes on which certificate should be installed
#
# @param lookupkey
#   Certificate for which lookup inside Hiera. In most cases it is subject
#   common name
#
# @param restart_nginx
#   Flag whether to restart Nginx or not
#
plan tlsinfo::install (
  TargetSpec $targets,
  String     $lookupkey,
  Boolean    $restart_nginx = false,
) {
  run_plan(puppet::agent5::install, $targets)
  run_plan(facts, $targets)

  return apply($targets) {
    include tlsinfo
    tlsinfo::certpair { $lookupkey:
      identity => true,
      cacert   => false,
    }
    if $restart_nginx {
      service { 'nginx':
        ensure    => running,
        subscribe => Tlsinfo::Certpair[$lookupkey],
      }
    }
  }
}
