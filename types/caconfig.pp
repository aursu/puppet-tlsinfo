type Tlsinfo::CAConfig = Struct[{
    signing             => Tlsinfo::Signing,
    Optional[ocsp]      => Tlsinfo::OCSPConfig,
    Optional[auth_keys] => Hash[String, Tlsinfo::AuthKey],
    Optional[remotes]   => Hash[String, String],
}]
