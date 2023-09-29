type Tlsinfo::PKIXExtension = Struct[{
    id                 => Tlsinfo::OID,
    value              => String,
    Optional[critical] => Boolean,
}]
