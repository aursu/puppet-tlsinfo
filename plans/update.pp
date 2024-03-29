# @summary Update certificate and private key
#
# Update certificate and private key. Works only in conjuction
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
plan tlsinfo::update (
  TargetSpec $targets,
  String $lookupkey,
  Boolean $restart_nginx = false,
  Puppet::Platform $collection = 'puppet7',
) {
  run_plan(puppet::agent::install, $targets, collection => $collection)
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
