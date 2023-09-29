type Tlsinfo::CAConfigSection = Struct[{
    pathlen               => Integer,
    Optional[pathlenzero] => Boolean,
    Optional[expiry]      => String,
    Optional[backdate]    => String,
}]
