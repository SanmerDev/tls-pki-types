use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DerDecode(#[from] rasn::error::DecodeError),

    #[error(transparent)]
    DerEncode(#[from] rasn::error::EncodeError),

    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),

    #[error("missing section end marker: {end_marker:?}")]
    MissingSectionEnd { end_marker: Vec<u8> },

    #[error("illegal section start: {line:?}")]
    IllegalSectionStart { line: Vec<u8> },

    #[error("no items found")]
    NoItemsFound,
}
