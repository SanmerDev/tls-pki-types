# TLSPrivateKey

## PKCS#8
```asn.1
PKCS8PrivateKey ::= SEQUENCE {
    version         INTEGER,
    algorithm       AlgorithmIdentifier,
    privateKey      OCTET STRING,
    attributes      [0] IMPLICIT Attributes OPTIONAL
}

AlgorithmIdentifier ::= SEQUENCE {
    algorithm	        OBJECT IDENTIFIER,
    parameters	        ANY OPTIONAL
}

Attributes ::= SET OF Attribute

Attribute ::= SEQUENCE {
    type      OBJECT IDENTIFIER,
    value     SET OF ANY
}

```

## EC
```asn.1
ECPrivateKey ::= SEQUNCE {
    version      INTEGER,
    privateKey   OCTET STRING,
    parameters   [0] EXPLICIT OBJECT IDENTIFIER OPTIONAL
    publicKey    [1] EXPLICIT BIT STRING OPTIONAL
}

```

## RSA
```asn.1
RSAPrivateKey ::= SEQUENCE {
    version          INTEGER,
    modulus          INTEGER,
    publicExponent   INTEGER,
    privateExponent  INTEGER,
    prime1           INTEGER,
    prime2           INTEGER,
    exponent1        INTEGER,
    exponent1        INTEGER,
    coefficient      INTEGER,
    otherPrimeInfos  OtherPrimeInfos OPTIONAL
}

OtherPrimeInfos ::= SEQUENCE OF OtherPrimeInfo

OtherPrimeINfo ::= SEQUENCE {
    prime          INTEGER,
    exponent       INTEGER,
    coefficient    INTEGER
}

```