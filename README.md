
# tlsinfo

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with tlsinfo](#setup)
    * [What tlsinfo affects](#what-tlsinfo-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with tlsinfo](#beginning-with-tlsinfo)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Limitations - OS compatibility, etc.](#limitations)
5. [Development - Guide for contributing to the module](#development)

## Description

tlsinfo module rpovide ability to manage x509 certificates and private keys on web node with proper validation checking (over dates, CA issuers, common names etc)

## Setup

### What tlsinfo affects **OPTIONAL**

### Setup Requirements **OPTIONAL**

### Beginning with tlsinfo

Module provides two custom types:

```puppet

sslcertificate { '':
  ensure => present,  # second value: absent
  path   => '/etc/pki/tls/certs/www.domain.com.pem',
  pkey   => '/etc/pki/tls/private/www.domain.com.key',
  cacert => true,
}
```
#### sslcertificate::ensure
#### sslcertificate::subject_hash (readonly)
#### sslcertificate::subject_hash_old (readonly)
#### sslcertificate::path
#### sslcertificate::pkey
#### sslcertificate::cacert
Default value: undef
Possible values are:
* `true` (Intermediate CA should be defined in Puppet catalog as `Sllcertificate` resource),
* `false` (we don't care about Intermediate CA),
* String. Any of certificate path, `Sslcertificate` resource title, certificate subject hash (`openssl x509 -subject_hash`) or old hash (`openssl x509 -subject_hash_old`). Should be defined in Puppet catalog as `Sllcertificate` resource
* Array of strings (list of CA certificates)

## Usage

It is required to include tlsinfo module into current scope to make parmeters `tlsinfo::certbase` and `tlsinfo::keybase` available

```puppet
include tlsinfo
```

Example:

```puppet
  tlsinfo::certificate { 'LetsEncryptAuthorityX3':
    cert => file('profile/certs/LetsEncryptAuthorityX3.crt'),
  }

  $server_name = 'registry.domain.com'
  tlsinfo::certpair { $server_name:
    identity => true,
  }

  # get certificate data from Hiera
  $certdata = tlsinfo::lookup($server_name)

  $ssl_cert_path = tlsinfo::certpath($certdata)
  $ssl_key_path = tlsinfo::keypath($certdata)
  
  class { 'profile::registry::nginx':
    server_name      => $server_name,
    ...
    ...
    ssl              => true,
    ssl_cert         => $ssl_cert_path,
    ssl_key          => $ssl_key_path,
    require          => Tlsinfo::Certpair[$server_name],
  }
```

In this example defined type `Tlsinfo::Certificate` will create certificate `/etc/pki/tls/certs/4f06f81d.pem` (`4f06f81d` is a certificate subject hash). 

`Tlsinfo::Certpair` will look for `registry_domain_com_certificate` and `registry_domain_com_private` keys through Hiera and create certpair `/etc/pki/tls/certs/registry.domain.com.pem` and `/etc/pki/tls/private/registry.domain.com.key`. It will check certificate-key validity before. Also certificate file `/etc/pki/tls/certs/registry.domain.com.pem` will consists Intermediate CA certificate on the bottom if such Intermediate CA certificate exists in Puppet catalog (defined via Tlsinfo::Certificate)

Path to certificate could be got via function `tlsinfo::certpath` and path to private key - via `tlsinfo::keypath`

## Reference

## Limitations

Module uses Ruby library 'openssl'

For unknown reasons this module has unpredicted behavior like:

1) returns old hash instead of new (for certificate Subject and Issuer fields)
2) returns negative (signed) values for Subject and Issuer hashes (eg `-ece330c` instead of `f131ccf4`)

Therefore it is better to use module functions for default path calculation (`tlsinfo::certpath` and `tlsinfo::keypath`)

## Development

## Release Notes/Contributors/Etc. **Optional**
