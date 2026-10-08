//! Plain DNS exchanges over UDP and TCP, shared by forwarding and
//! recursion, with the defenses against off-path spoofing: a fresh UDP
//! socket with an OS-chosen random source port per exchange, connected to
//! the server so that datagrams from other addresses are never seen; and a
//! response accepted only if its ID, opcode and question (in exactly the
//! sent case, for 0x20 randomization) match.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use goethite_proto::{DnsCodec, EncodeError, HickoryCodec, Opcode, Query, Response, ResponseError};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::tls::{DohError, exchange_framed};

/// UDP responses larger than this are dropped. goethite advertises
/// [`goethite_proto::MAX_UDP_PAYLOAD`], so honest servers stay well below
/// it.
const MAX_UDP_RESPONSE_LEN: usize = 4096;

/// Why one exchange with one server failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExchangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Decode(#[from] ResponseError),
    #[error(transparent)]
    Doh(#[from] DohError),
    #[error("response does not match the query")]
    Mismatch,
    /// The response matched but for the case of the name: the server does
    /// not keep the case 0x20 randomization relies on.
    #[error("the server does not keep the case of names")]
    CaseMismatch,
}

/// What to do with a response that matches except for the case of the
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OnCaseMismatch {
    /// Ignore it, as any other mismatch, and keep waiting.
    Ignore,
    /// Report it as [`ExchangeError::CaseMismatch`].
    Report,
}

/// Whether `response` answers `sent`: same ID, a standard query, and the
/// same question in exactly the same case.
pub(crate) fn answers(response: &Response, sent: &Query) -> bool {
    response.id == sent.id
        && response.opcode == Opcode::QUERY
        && response
            .question
            .as_ref()
            .is_some_and(|question| question.matches_exactly(&sent.question))
}

/// Whether `response` answers `sent` but for the case of the name.
fn answers_but_for_case(response: &Response, sent: &Query) -> bool {
    response.id == sent.id
        && response.opcode == Opcode::QUERY
        && response
            .question
            .as_ref()
            .is_some_and(|question| question == &sent.question)
}

/// Decodes a reply received over a connection-oriented transport and checks
/// that it answers `sent`.
pub(crate) fn accept(reply: &[u8], sent: &Query) -> Result<Response, ExchangeError> {
    let response = HickoryCodec.decode_response(reply)?;
    if answers(&response, sent) {
        Ok(response)
    } else if answers_but_for_case(&response, sent) {
        Err(ExchangeError::CaseMismatch)
    } else {
        Err(ExchangeError::Mismatch)
    }
}

/// Sends `wire` (the encoding of `sent`) to `address` over UDP and waits
/// for the response that answers it. The caller bounds the time.
pub(crate) async fn udp(
    address: SocketAddr,
    wire: &[u8],
    sent: &Query,
    on_case_mismatch: OnCaseMismatch,
) -> Result<Response, ExchangeError> {
    let local = if address.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    // Port 0: the OS picks a random ephemeral port for every exchange.
    let socket = UdpSocket::bind(local).await?;
    // Connected: datagrams from any other address are never delivered.
    socket.connect(address).await?;
    socket.send(wire).await?;

    // One spare byte tells an oversized datagram from one that fits exactly.
    let mut buf = vec![0_u8; MAX_UDP_RESPONSE_LEN + 1];
    loop {
        // The caller's timeout bounds this loop.
        let len = socket.recv(&mut buf).await?;
        let Some(packet) = buf.get(..len).filter(|_| len <= MAX_UDP_RESPONSE_LEN) else {
            debug!(%address, "ignoring an oversized response");
            continue;
        };
        match HickoryCodec.decode_response(packet) {
            Ok(response) if answers(&response, sent) => return Ok(response),
            Ok(response)
                if on_case_mismatch == OnCaseMismatch::Report
                    && answers_but_for_case(&response, sent) =>
            {
                return Err(ExchangeError::CaseMismatch);
            }
            Ok(_) => debug!(%address, "ignoring a response that does not match the query"),
            Err(err) => debug!(%address, %err, "ignoring a malformed response"),
        }
    }
}

/// Sends `wire` (the encoding of `sent`) to `address` over TCP and reads the
/// response. The caller bounds the time.
pub(crate) async fn tcp(
    address: SocketAddr,
    wire: &[u8],
    sent: &Query,
) -> Result<Response, ExchangeError> {
    let mut stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    let reply = exchange_framed(&mut stream, wire).await?;
    accept(&reply, sent)
}
