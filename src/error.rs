use base64::DecodeError as Base64DecodeError;
use rasn::error::{DecodeError as DerDecodeError, EncodeError as DerEncodeError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    DerDecode(#[from] DerDecodeError),

    #[error("{0}")]
    DerEncode(#[from] DerEncodeError),

    #[error("{0}")]
    Base64Decode(#[from] Base64DecodeError),

    #[error("missing section end marker: {end_marker:?}")]
    MissingSectionEnd { end_marker: Vec<u8> },

    #[error("illegal section start: {line:?}")]
    IllegalSectionStart { line: Vec<u8> },

    #[error("no items found")]
    NoItemsFound,
}
