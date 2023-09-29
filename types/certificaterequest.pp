type Tlsinfo::CertificateRequest = Struct[{
    CN                           => String,
    names                        => Array[Tlsinfo::PKIXName],
    key                          => Tlsinfo::KeyRequest,
    Optional[hosts]              => Array[String],
    Optional[ca]                 => Tlsinfo::CAConfigSection,
    Optional[serialnumber]       => String,
    Optional[delegation_enabled] => Boolean,
    Optional[extensions]         => Array[Tlsinfo::PKIXExtension],
    Optional[crl_url]            => String,
}]
