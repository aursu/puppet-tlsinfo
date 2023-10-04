# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   tlsinfo::cfssl::gencert { 'namevar': }
define tlsinfo::cfssl::gencert (
  String $prefix = $name,
  Pattern[/\.json$/] $csr = "${name}-csr.json",
  Optional[Stdlib::Unixpath] $path = undef,
  Boolean $initca = false,
  Variant[String, Stdlib::Unixpath] $ca = 'ca.pem',
  Variant[String, Stdlib::Unixpath] $ca_key = 'ca-key.pem',
  Optional[Variant[String, Stdlib::Unixpath]] $config = undef,
  Optional[String] $profile = undef,
  Array[Stdlib::Host] $hostname = [],
) {
  include tlsinfo::tools::cfssl

  $run_path = $path ? {
    Stdlib::Unixpath => $path,
    default => $bsys::params::pkibase,
  }

  $csr_check = $csr ? {
    Stdlib::Unixpath => ["test -f ${csr}"],
    default => ["test -f ${run_path}/${csr}"],
  }

  $config_option = $config ? {
    String  => "-config=${config}",
    default => "",
  }

  if $initca {
    exec { "cfssl-gencert-${prefix}":
      command => "cfssl gencert -initca ${csr} | cfssljson -bare ${prefix}",
      unless  => "test -f ${run_path}/${prefix}.pem",
      onlyif  => $csr_check,
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

    if $hostname[0] {
      $hostname_option = ['-hostname=', $hostname.join(',')].join('')
    }
    else {
      $hostname_option = ""
    }

    exec { "cfssl-gencert-${prefix}":
      command => "cfssl gencert -ca=${ca} -ca-key=${ca_key} ${config_option} ${profile_option} ${hostname_option} ${csr} | cfssljson -bare ${prefix}",
      unless  => "test -f ${run_path}/${prefix}.pem",
      onlyif => $csr_check + $config_check + $ca_check + $ca_key_check,
      path    => '/usr/local/bin:/usr/bin:/bin',
      cwd     => $run_path,
    }
  }
}
