require 'spec_helper'

describe 'tlsinfo::certpair' do
  let(:wildcard_domain_com_private) do
    <<-RSAKEYDATA
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwk2hrEE0Cd7Lqb7RwZXh5D28eU1QVm+l3G5ZwM9UwxOjkWe6
LNkKarbcV5OC4nJ0TymNRAjNxjisTN0Y/SCYULZrZzFpLBq9JFiB8XRtcLuDoXzQ
nSmlr9hBYu0a5dcyYtSHaMRX+70tluzesm2luFEGMFd5EiddohVNwiWBhJgEeOzA
7QAJZuB+w/+GJjEJw/smTMoZXQiYA+oCkjy8Hqna6yrKdsdb34l9Sv3qG6QPRZIp
PmI1EZPnMqSL7FOdUA3ltzK0EBguJxqwzUGnX8qdSbcOlD02+Id1Yo8JpDOhbZIn
GFlSAl93N3eiVTq2IFTOxcCxdM/mxISWgzM/KQIDAQABAoIBACwQCs/TYYezfKAb
49lwse9eiLVBcSyI2SYp6DSvT9uFQpyg1zmAZrpYiZNaol3T8shY9e4tyOxgwcIU
iawtjh0PoT+flugnkCkD4UPuUTs1at5ePbjGTwqXkgxrFKR2rrh21dZOYF14QzRs
tvvjnac0yKCB1bTmNHejOSUD+GEm6sx60HVaoEDU7dLE6+YNUyHuCBOb8LaqvWoU
ZRI54v9vhfoNYzSDjrV5YUswMmbNmb6AXQbGoFzjXVN2MehhqmaLxQgLSi1Kkdm+
502PM3RjDrpBB/6YGULum9Bs4gy/BK0rGpUnIm0I+6ABJjfyni6Th2MyNWvNk0sO
IQ1PwZkCgYEA7kPS5H+rfxG3tiy5R1rK/kPU+HrxrV1QD2twNG5JY/7DQFHvu+f2
8uey6lGI+V1HBt9kXWeNc0Wz3g0KuI3Z7kAq4gmo7WwbvuPs++vPWbJikTx5jXh/
8KqlX+DpT38DlVOWWRkQVd9aSTdYFwQOCETjH7mNsKznDGeXNOrW2Q8CgYEA0MQc
XBjOFnOGKr61Bp+x0KwfQR44q548aGepvX2BOU2kTBf79O22I0q5WNjXVmOfEIcT
ubuws9FkUjOhYZHh6rnuLvwuwSco7LmSNuNVJBpdJD9nbRCTa4b4MDAFzP72xDNX
wbp+JiD2oVuBp53HDG/lMjjI64ZeNMi7bS4aNEcCgYBxmdbgaVrMQBdWfaZtNgXZ
C2BshLncDcSRRYl/BiJp0dsoPKjP775XfE9a1zs2odmuli5VNn1Du7URpyg4bDG/
HcsUcMShRs1Hy4Z/aqQ3QQ0r8CiIYi6mAcbNmv/Cjm2X8f2aR4/5UX/Lrt6KQr2q
BaZAxwiedyHGUVHPwjRj0wKBgFTlW08Me0pgAlCBqyYdbPcZ97/IZW1M9O3UMg+v
6Qv/ie+z1S8+N9JUQdlinPcxne7fr2LZc7s8TJqtClSeOYv1vml2/iBoJ1lVAaO2
gNokqnniGtIcaobQpT8bWFCL4pfY9Tf/+erRftoRV0FthROGsWLh+rrksoyukKGO
nPNjAoGBAOH5u3M4sS2UlPkqwVtQ3XPPTXVT9m0xp6cfyNsPQCpwAOHqpUgaCrsx
mOI9qJG1PiwVgbOhW3Q3mYHEh/7NDywAlieE9kPO03HExCfDIwhEOPQeZ7uXxOKR
UJB6MzKFZqSp3kQGh0PaO4YaEDPuGy5+HjXB9N0pwcKD6Ep/PF5l
-----END RSA PRIVATE KEY-----
RSAKEYDATA
  end
  let(:keypath_wildcard) { '/etc/pki/tls/private/wildcard.domain.com.key' }
  let(:wildcard_domain_com_certificate) do
    <<-CERTIFICATE
-----BEGIN CERTIFICATE-----
MIIFNDCCBBygAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRswGQYDVQQKDBJD
b21wYW55IENBIExpbWl0ZWQxNzA1BgNVBAMMLkNvbXBhbnkgUlNBIERvbWFpbiBW
YWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTkwMTA3MDAyNTQyWhcNMjAw
MTA3MDAyNTQyWjBQMSEwHwYDVQQLDBhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQx
FDASBgNVBAsMC0ludGVybmFsU1NMMRUwEwYDVQQDDAwqLmRvbWFpbi5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCTaGsQTQJ3supvtHBleHkPbx5
TVBWb6XcblnAz1TDE6ORZ7os2QpqttxXk4LicnRPKY1ECM3GOKxM3Rj9IJhQtmtn
MWksGr0kWIHxdG1wu4OhfNCdKaWv2EFi7Rrl1zJi1IdoxFf7vS2W7N6ybaW4UQYw
V3kSJ12iFU3CJYGEmAR47MDtAAlm4H7D/4YmMQnD+yZMyhldCJgD6gKSPLweqdrr
Ksp2x1vfiX1K/eobpA9Fkik+YjURk+cypIvsU51QDeW3MrQQGC4nGrDNQadfyp1J
tw6UPTb4h3VijwmkM6FtkicYWVICX3c3d6JVOrYgVM7FwLF0z+bEhJaDMz8pAgMB
AAGjggHeMIIB2jAfBgNVHSMEGDAWgBTi6r3OGwCIPrOEUa51BJSLC1MITjAdBgNV
HQ4EFgQU+LFXFI3BMiw/bN9izW9hanHOLEEwDgYDVR0PAQH/BAQDAgWgMAwGA1Ud
EwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBMGA1UdIAQM
MAowCAYGZ4EMAQIBMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwuY29tcGFu
eWNhLmNvbS9Db21wYW55UlNBRG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZlckNB
LmNybDCBiAYIKwYBBQUHAQEEfDB6MFEGCCsGAQUFBzAChkVodHRwOi8vY3J0LmNv
bXBhbnljYS5jb20vQ29tcGFueVJTQURvbWFpblZhbGlkYXRpb25TZWN1cmVTZXJ2
ZXJDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLmNvbXBhbnljYS5jb20w
YwYDVR0RBFwwWoIKZG9tYWluLmNvbYIMKi5kb21haW4uY29tghN3d3cuaG9tZS5k
b21haW4uY29tghRtYWlsLmhvbWUuZG9tYWluLmNvbYITZG5zLmhvbWUuZG9tYWlu
LmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAY6CaritAno/8gi2T1exLLAvMm8mXL9Uz
SLQNHCMwcodpQgr8ZrVZ0gaSsPdena4il0AJYiY1yhfSxwcjydH8ZjtZKojhucih
AZs75tGM6kwN/6K+kVlRUHTF5+QP07hYCPUVE6z2tVq8dXf2h4iwfHtQeqIH8cEg
szQGA7PALOtGpkvW92qSTapKsXcg/IVxDRYh9jFlyNLV9ZgbDYzZnDZt3fVhBqBR
ZXFBikfPD9607O/N8BhHsZYctusZyhdrQxI0yLEHJStuNVyuqSRdmY/2k/3TGaFR
J3DT8u0gvKcKXZNY+XAaSFGAnQHDDE5Rrhb2uhde4Qp3QziWQw6uqA==
-----END CERTIFICATE-----
CERTIFICATE
  end
  let(:certpath_wildcard) { '/etc/pki/tls/certs/wildcard.domain.com.pem' }
  let(:title) { 'namevar' }
  let(:params) do
    {}
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:pre_condition) { "class {'tlsinfo': }" }

      context 'with default parameters' do
        let(:title) { 'www.domain.com' }

        it {
          is_expected
            .to compile
            .and_raise_error(%r{Can not find www_domain_com_certificate in Hiera})
        }
      end

      context 'with validate flag disabled' do
        let(:title) { 'www.domain.com' }
        let(:params) do
          {
            'cert'     => wildcard_domain_com_certificate,
            'pkey'     => wildcard_domain_com_private,
            'cacert'   => false,
            'validate' => false
          }
        end

        it {
          is_expected
            .to compile
        }
      end
    end
  end
end
