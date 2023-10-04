# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   tlsinfo::cfssl::gencert { 'namevar': }
define tlsinfo::cfssl::gencert (
  Pattern[/\.json$/] $csr,
  String $prefix = $name,
  Optional[Stdlib::Unixpath] $path = undef,
  Boolean $initca = false,
  Variant[String, Stdlib::Unixpath] $ca = 'ca.pem',
  Variant[String, Stdlib::Unixpath] $ca_key = 'ca-key.pem',
  Optional[Variant[String, Stdlib::Unixpath]] $config = undef,
  Optional[String] $profile = undef,
) {
  include tlsinfo::tools::cfssl

  $run_path = $path ? {
    Stdlib::Unixpath => $path,
    default => $bsys::params::pkibase,
  }

  $config_option = $config ? {
    String  => "-config=${config}",
    default => "",
  }

  if $initca {
    exec { "cfssl-gencert-${prefix}":
      command => "cfssl gencert -initca ${csr} | cfssljson -bare ${prefix}",
      unless  => "test -f ${run_path}/${prefix}.pem",
      path    => '/usr/local/bin:/usr/bin:/bin',
      cwd     => $run_path,
    }
  }
  else {
    $ca_check = $ca ? {
      Stdlib::Unixpath => ["test -f ${ca}"],
      default => ["test -f ${run_path}/${ca}"],
    }

    $ca_key_check = $ca_key ? {
      Stdlib::Unixpath => ["test -f ${ca_key}"],
      default => ["test -f ${run_path}/${ca_key}"],
    }

    if $config {
      $profile_option = $profile ? {
        String  => "-profile=${profile}",
        default => "",
      }

      $config_check = $config ? {
        Stdlib::Unixpath => ["test -f ${config}"],
        default => ["test -f ${run_path}/${config}"],
      }
    }
    else {
      $profile_option = ""
      $config_check = []
    }

    exec { "cfssl-gencert-${prefix}":
      command => "cfssl gencert -ca=${ca} -ca-key=${ca_key} ${config_option} ${profile_option} ${csr} | cfssljson -bare ${prefix}",
      unless  => "test -f ${run_path}/${prefix}.pem",
      onlyif => $config_check + $ca_check + $ca_key_check,
      path    => '/usr/local/bin:/usr/bin:/bin',
      cwd     => $run_path,
    }
  }
}
