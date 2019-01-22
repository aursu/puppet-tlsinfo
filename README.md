
# tlsinfo

Welcome to your new module. A short overview of the generated parts can be found in the PDK documentation at https://puppet.com/pdk/latest/pdk_generating_modules.html .

The README template below provides a starting point with details about what information to include in your README.







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

## Usage

It is required to include tlsinfo module into current scope to make parmeters `tlsinfo::certbase` and `tlsinfo::keybase` available

```
include tlsinfo
```

Example:

```
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
    ssl_cert         => $ssl_cert,
    ssl_key          => $ssl_key,
    require          => Tlsinfo::Certpair[$server_name],
  }
```

In this example defined type Tlsinfo::Certificate will create certificate /etc/pki/tls/certs/4f06f81d.pem (`4f06f81d` is a certificate subject hash). 

Tlsinfo::Certpair will look for `registry_domain_com_certificate` and `registry_domain_com_private` keys through Hiera and create certpair `/etc/pki/tls/certs/registry.domain.com.pem` and `/etc/pki/tls/private/registry.domain.com.key`. It will check certificate-key validity before. Also certificate file /etc/pki/tls/certs/registry.domain.com.pem will consists Intermediate CA on the bottom if such Intermediate CA certificate exists in Puppet catalog (defined via Tlsinfo::Certificate)

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

