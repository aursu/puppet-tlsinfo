# @summary CA configuration file for CFSSL
#
# CA configuration file for CloudFlare's PKI/TLS toolkit
#
# @param filename
#   CA configuration file name (not a path)
#
# @param path
#   Path to the directory where CA configuration file is located.
#   Full path to CA configuration file if value ends with ".json"
#   If value ends with "/" - it will be concidered as a directory explicitly
#
# @param default_expiry
#   CA signing configuration default expire time (default is 43824h)
#
# @param default_profile
#   Default signing profile for CA configuration
#
# @param signing_profiles
#   Signing profiles for CA configuration
#
# @example
#   tlsinfo::cfssl::ca_config { 'namevar': }
define tlsinfo::cfssl::ca_config (
  String $filename = "${name}.json",
  Optional[String] $path = undef,
  Tlsinfo::TimeDuration $default_expiry = '43824h',
  Tlsinfo::SigningProfile $default_profile = {
    expiry => $default_expiry,
  },
  Hash[String, Tlsinfo::SigningProfile] $signing_profiles = {},
) {
  include bsys::params

  # setup default expiry into default profile
  if $default_profile['expiry'] {
    $defined_default_profile = $default_profile
  }
  else {
    $defined_default_profile = $default_profile + {
      expiry => $default_expiry,
    }
  }

  $config = {
    signing => {
      'default' => $defined_default_profile,
      profiles  => $signing_profiles,
    },
  }

  case $path {
    /\.json$/: {
      $config_path = $path
    }
    /\/$/: {
      $config_path = "${path}${filename}"
    }
    String: {
      $config_path = "${path}/${filename}"
    }
    default: {
      $config_path = "${bsys::params::pkibase}/${filename}"
    }
  }

  file { $config_path:
    ensure  => file,
    content => to_json_pretty($config, true, { indent => '    ', space => ' ' }),
  }
}
