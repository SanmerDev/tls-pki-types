mod error;
mod pem;

pub use error::Error;
pub use pem::*;

use rasn::der;
use rasn::prelude::*;

pub trait DerObject: Sized {
    fn from_der_slice(input: &[u8]) -> Result<Self, Error>;
    fn der_encoded(&self) -> Result<Vec<u8>, Error>;
}

impl<T: Decode + Encode> DerObject for T {
    #[inline]
    fn from_der_slice(input: &[u8]) -> Result<Self, Error> {
        der::decode(input).map_err(|e| e.into())
    }

    #[inline]
    fn der_encoded(&self) -> Result<Vec<u8>, Error> {
        der::encode(self).map_err(|e| e.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct Version(u64);

impl Version {
    pub const V0: Self = Self(0);
    pub const V1: Self = Self(1);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
pub struct PrivatePkcs8KeyDer {
    pub version: Version,
    pub algorithm: AlgorithmIdentifier,
    pub private_key: OctetString,
    #[rasn(tag(0))]
    pub attributes: Option<Attributes>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Pkcs8Parameters>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum Pkcs8Parameters {
    Ec(ObjectIdentifier),
    Rsa(()),
    Unknown(Any),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct Attributes(pub SequenceOf<Attribute>);

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
pub struct Attribute {
    pub value_type: ObjectIdentifier,
    pub values: SetOf<Any>,
}

impl TryFrom<&PrivateSec1KeyDer> for PrivatePkcs8KeyDer {
    type Error = Error;

    fn try_from(key: &PrivateSec1KeyDer) -> Result<Self, Self::Error> {
        let parameters = key
            .parameters
            .as_ref()
            .map(|parameters| Pkcs8Parameters::Ec(parameters.0.to_owned()));

        let ec = PrivateSec1KeyDer {
            version: key.version.to_owned(),
            private_key: key.private_key.to_owned(),
            parameters: None,
            public_key: key.public_key.to_owned(),
        };

        Ok(PrivatePkcs8KeyDer {
            version: Version::V0,
            algorithm: AlgorithmIdentifier {
                algorithm: Oid::ISO_MEMBER_BODY_US_ANSI_X962_KEY_TYPE_EC_PUBLIC_KEY.to_owned(),
                parameters,
            },
            private_key: ec.der_encoded()?.into(),
            attributes: None,
        })
    }
}

impl TryFrom<&PrivatePkcs1KeyDer> for PrivatePkcs8KeyDer {
    type Error = Error;

    fn try_from(key: &PrivatePkcs1KeyDer) -> Result<Self, Self::Error> {
        Ok(PrivatePkcs8KeyDer {
            version: Version::V0,
            algorithm: AlgorithmIdentifier {
                algorithm: Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS1_RSA.to_owned(),
                parameters: Some(Pkcs8Parameters::Rsa(())),
            },
            private_key: key.der_encoded()?.into(),
            attributes: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
pub struct PrivateSec1KeyDer {
    pub version: Version,
    pub private_key: OctetString,
    #[rasn(tag(explicit(0)))]
    pub parameters: Option<EcParameters>,
    #[rasn(tag(explicit(1)))]
    pub public_key: Option<BitString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct EcParameters(pub ObjectIdentifier);

impl TryFrom<&PrivatePkcs8KeyDer> for PrivateSec1KeyDer {
    type Error = Error;

    fn try_from(key: &PrivatePkcs8KeyDer) -> Result<Self, Self::Error> {
        let parameters = if let Some(Pkcs8Parameters::Ec(parameters)) = &key.algorithm.parameters {
            Some(EcParameters(parameters.to_owned()))
        } else {
            None
        };

        let ec = PrivateSec1KeyDer::from_der_slice(&key.private_key)?;

        Ok(PrivateSec1KeyDer {
            version: ec.version,
            private_key: ec.private_key,
            parameters,
            public_key: ec.public_key,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
pub struct PrivatePkcs1KeyDer {
    pub version: Version,
    pub modulus: Integer,
    pub public_exponent: Integer,
    pub private_exponent: Integer,
    pub prime1: Integer,
    pub prime2: Integer,
    pub exponent1: Integer,
    pub exponent2: Integer,
    pub coefficient: Integer,
    pub other_prime_infos: Option<OtherPrimeInfos>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct OtherPrimeInfos(pub SequenceOf<OtherPrimeInfo>);

#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Decode, Encode)]
pub struct OtherPrimeInfo {
    prime: Integer,
    exponent: Integer,
    coefficient: Integer,
}

impl TryFrom<&PrivatePkcs8KeyDer> for PrivatePkcs1KeyDer {
    type Error = Error;

    fn try_from(key: &PrivatePkcs8KeyDer) -> Result<Self, Self::Error> {
        PrivatePkcs1KeyDer::from_der_slice(&key.private_key)
    }
}
