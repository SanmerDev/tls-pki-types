use crate::{DerObject, Error, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::ops::ControlFlow;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SectionKind {
    PrivateKey,
    EcPrivateKey,
    RsaPrivateKey,
}

impl TryFrom<&[u8]> for SectionKind {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(match value {
            b"PRIVATE KEY" => Self::PrivateKey,
            b"EC PRIVATE KEY" => Self::EcPrivateKey,
            b"RSA PRIVATE KEY" => Self::RsaPrivateKey,
            _ => return Err(()),
        })
    }
}

pub enum PrivateKeyDer {
    Pkcs8(PrivatePkcs8KeyDer),
    Sec1(PrivateSec1KeyDer),
    Pkcs1(PrivatePkcs1KeyDer),
}

impl PrivateKeyDer {
    pub fn from_pem_slice(input: &[u8]) -> Result<Self, Error> {
        match from_slice(input)? {
            None => Err(Error::NoItemsFound),
            Some((kind, bytes)) => match kind {
                SectionKind::PrivateKey => Ok(Self::Pkcs8(PrivatePkcs8KeyDer::from_der_slice(
                    bytes.as_slice(),
                )?)),
                SectionKind::EcPrivateKey => Ok(Self::Sec1(PrivateSec1KeyDer::from_der_slice(
                    bytes.as_slice(),
                )?)),
                SectionKind::RsaPrivateKey => Ok(Self::Pkcs1(PrivatePkcs1KeyDer::from_der_slice(
                    bytes.as_slice(),
                )?)),
            },
        }
    }
}

fn from_slice(mut input: &[u8]) -> Result<Option<(SectionKind, Vec<u8>)>, Error> {
    let mut bytes = Vec::with_capacity(1024);
    let mut section = None::<(Vec<_>, Vec<_>)>;

    loop {
        let next_line = if let Some(index) = input
            .iter()
            .position(|byte| *byte == b'\n' || *byte == b'\r')
        {
            let (line, newline_plus_remainder) = input.split_at(index);
            input = &newline_plus_remainder[1..];
            Some(line)
        } else if !input.is_empty() {
            let next_line = input;
            input = &[];
            Some(next_line)
        } else {
            None
        };

        match read(next_line, &mut section, &mut bytes)? {
            ControlFlow::Continue(()) => continue,
            ControlFlow::Break(item) => return Ok(item),
        }
    }
}

fn read(
    next_line: Option<&[u8]>,
    section: &mut Option<(Vec<u8>, Vec<u8>)>,
    bytes: &mut Vec<u8>,
) -> Result<ControlFlow<Option<(SectionKind, Vec<u8>)>, ()>, Error> {
    let line = if let Some(line) = next_line {
        line
    } else {
        return match section.take() {
            Some((_, end_marker)) => Err(Error::MissingSectionEnd { end_marker }),
            None => Ok(ControlFlow::Break(None)),
        };
    };

    if line.starts_with(b"-----BEGIN ") {
        let (mut trailer, mut pos) = (0, line.len());
        for (i, &b) in line.iter().enumerate().rev() {
            match b {
                b'-' => {
                    trailer += 1;
                    pos = i;
                }
                b'\n' | b'\r' | b' ' => continue,
                _ => break,
            }
        }

        if trailer != 5 {
            return Err(Error::IllegalSectionStart {
                line: line.to_vec(),
            });
        }

        let ty = &line[11..pos];
        let mut end = Vec::with_capacity(10 + 4 + ty.len());
        end.extend_from_slice(b"-----END ");
        end.extend_from_slice(ty);
        end.extend_from_slice(b"-----");
        *section = Some((ty.to_owned(), end));
        return Ok(ControlFlow::Continue(()));
    }

    if let Some((section_label, end_marker)) = section.as_ref() {
        if line.starts_with(end_marker) {
            let kind = match SectionKind::try_from(&section_label[..]) {
                Ok(kind) => kind,
                Err(()) => {
                    *section = None;
                    bytes.clear();
                    return Ok(ControlFlow::Continue(()));
                }
            };

            let der_bytes = BASE64_STANDARD
                .decode(bytes)
                .map_err(|e| Error::Base64Decode(e))?;
            return Ok(ControlFlow::Break(Some((kind, der_bytes))));
        }
    }

    if section.is_some() {
        bytes.extend(line);
    }

    Ok(ControlFlow::Continue(()))
}
