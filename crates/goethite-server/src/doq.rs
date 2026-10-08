//! Reading DNS over QUIC queries (RFC 9250), without I/O.
//!
//! A client sends each query on a bidirectional stream of its own: a
//! 2-byte length, the message, and the end of the stream. The message ID
//! must be 0, since the stream already tells queries apart. Anything else
//! is a protocol error, which ends the connection. Every function here
//! takes data straight from the network and never panics.

/// The application protocol (ALPN) of DNS over QUIC.
pub const ALPN: &[u8] = b"doq";

/// The most a stream may carry: the length and the largest DNS message.
pub const MAX_STREAM_LEN: usize = 2 + 65_535;

/// Why what a client sent on a stream is not a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DoqError {
    /// Fewer than the 2 bytes of the length.
    #[error("the stream ended before the length")]
    NoLength,
    /// The length says more or less than the stream carried.
    #[error("the length does not match the message")]
    LengthMismatch,
    /// The message has a nonzero ID.
    #[error("the message ID is not 0")]
    NonzeroId,
    /// The stream carried more than [`MAX_STREAM_LEN`] bytes.
    #[error("the stream is too long")]
    TooLong,
    /// The message is not a DNS query, not even one to answer with an
    /// error.
    #[error("not a DNS query")]
    NotDns,
}

/// Error codes a DNS over QUIC server closes connections and streams with
/// (RFC 9250, section 8.4).
pub mod code {
    /// No error: the connection is closed on purpose.
    pub const NO_ERROR: u32 = 0x0;
    /// The server failed.
    pub const INTERNAL_ERROR: u32 = 0x1;
    /// The client broke the protocol.
    pub const PROTOCOL_ERROR: u32 = 0x2;
    /// The server gave up on a request, such as one sent too slowly.
    pub const REQUEST_CANCELLED: u32 = 0x3;
    /// The server is too busy.
    pub const EXCESSIVE_LOAD: u32 = 0x4;
}

/// The DNS message in `stream`, everything a client sent on one stream.
///
/// # Errors
///
/// If the stream does not hold exactly one length-prefixed message, or the
/// message's ID is not 0.
pub fn query(stream: &[u8]) -> Result<&[u8], DoqError> {
    let (length, message) = stream.split_first_chunk::<2>().ok_or(DoqError::NoLength)?;
    if usize::from(u16::from_be_bytes(*length)) != message.len() {
        return Err(DoqError::LengthMismatch);
    }
    // A message too short to have an ID is left to the DNS decoder.
    if message.first_chunk::<2>().is_some_and(|id| *id != [0, 0]) {
        return Err(DoqError::NonzeroId);
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        let message = [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut stream = vec![0, 12];
        stream.extend_from_slice(&message);
        assert_eq!(query(&stream), Ok(&message[..]));
        assert_eq!(query(&[]), Err(DoqError::NoLength));
        assert_eq!(query(&[0]), Err(DoqError::NoLength));
        assert_eq!(query(&[0, 0]), Ok(&[][..]));
        assert_eq!(query(&stream[..13]), Err(DoqError::LengthMismatch));
        let mut longer = stream.clone();
        longer.push(0);
        assert_eq!(query(&longer), Err(DoqError::LengthMismatch));
        let mut numbered = stream;
        numbered[3] = 7;
        assert_eq!(query(&numbered), Err(DoqError::NonzeroId));
    }
}
