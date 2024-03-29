# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   tlsinfo::cfssl::crt_req { 'namevar': }
define tlsinfo::cfssl::crt_req (
  String $filename = "${name}.json",
  Optional[String] $path = undef,
  Tlsinfo::KeyAlgorithm $key_algorithm = 'rsa',
  Integer $key_size = 2048,
  Optional[String] $common_name = undef,
  String $name_country = 'DE',
  String $name_state = 'Hesse',
  String $name_locality = 'Frankfurt',
  Optional[String] $name_organisation = undef,
  Optional[String] $name_organisation_unit = undef,
  Tlsinfo::PKIXName $names = {},
  Optional[Tlsinfo::CertificateRequest] $req = undef,
) {
  include bsys::params

  $req_cn = $common_name ? {
    String => { 'CN' => $common_name },
    default => {},
  }

  $names_o = $name_organisation ? {
    String => { 'O' => $name_organisation },
    default => {},
  }

  $names_ou = $name_organisation_unit ? {
    String => { 'OU' => $name_organisation_unit },
    default => {},
  }

  $_req = $req ? {
    Tlsinfo::CertificateRequest => $req,
    default => {},
  }

  $req_names = $_req['names'] ? {
    Array => $_req['names'],
    default => [],
  }

  $req_names0 = $req_names[0] ? {
    Tlsinfo::PKIXName => $req_names[0],
    default => {},
  }

  # key provided inside $req or empty if not
  $req_key = $_req['key'] ? {
    Tlsinfo::KeyRequest => $_req['key'],
    default => {},
  }

  $_req_names = { names => [{ 'C' => $name_country } + { 'ST' => $name_state } + { 'L' => $name_locality } +
  $names_o + $names_ou + $names + $req_names0] + $req_names[1, -1] }

  $_req_key = { key => { size => $key_size } + { algo => $key_algorithm } + $req_key }

  $config = $req_cn + $_req + $_req_names + $_req_key

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
