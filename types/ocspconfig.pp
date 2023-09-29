type Tlsinfo::OCSPConfig = Struct[{
    ca_cert_file        => String,
    responder_cert_file => String,
    key_file            => String,
    interval            => Tlsinfo::TimeDuration,
}]
