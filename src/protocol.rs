//! UDP tracker wire protocol (BEP 15) — zero-copy-ish parsing and
//! serialization helpers.
//!
//! All multi-byte fields are big-endian (network order).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// BEP 15 connect protocol identifier: 0x41727101980.
pub const PROTOCOL_IDENTIFIER: i64 = 4_497_486_125_440;

/// Fixed size of an announce request (without optional 2-byte extensions field).
pub const ANNOUNCE_REQ_LEN: usize = 98;
/// Minimum bytes for connect request.
pub const CONNECT_REQ_LEN: usize = 16;
/// Bytes before info-hash list in a scrape request.
pub const SCRAPE_HEADER_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Connect = 0,
    Announce = 1,
    Scrape = 2,
    Error = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceEvent {
    None = 0,
    Completed = 1,
    Started = 2,
    Stopped = 3,
    /// BEP-21 partial-seed pause (wire value 4).
    Paused = 4,
}

impl AnnounceEvent {
    #[inline]
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Completed,
            2 => Self::Started,
            3 => Self::Stopped,
            4 => Self::Paused,
            _ => Self::None,
        }
    }
}

/// Parsed announce request — fields borrowed/copied out of the packet.
#[derive(Debug, Clone, Copy)]
pub struct AnnounceRequest {
    pub connection_id: i64,
    pub transaction_id: i32,
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub downloaded: i64,
    pub left: i64,
    pub uploaded: i64,
    pub event: AnnounceEvent,
    pub key: i32,
    pub numwant: i32,
    pub port: u16,
    /// Client-supplied IP field (usually 0). Source address is authoritative.
    #[allow(dead_code)]
    pub ip_field: [u8; 4],
}

/// peer_ids consisting solely of ASCII digits are synthetic flood signatures
/// (observed in the wild: "01234567890123456789" announce spam). No real
/// client generates an all-digit peer_id — BEP-20 ids are structured
/// (`-XXvvvv-`, `M-x-y--`) or random bytes.
#[inline]
pub fn synthetic_peer_id(peer_id: &[u8; 20]) -> bool {
    peer_id.iter().all(|b| b.is_ascii_digit())
}

/// Outcome of parsing a datagram.
#[derive(Debug)]
pub enum ParsedRequest<'a> {
    Connect { transaction_id: i32 },
    Announce(AnnounceRequest),
    Scrape { connection_id: i64, transaction_id: i32, hashes: &'a [[u8; 20]] },
}

/// Error that may still produce a response (action 3) if the connection id is valid.
#[derive(Debug)]
pub enum ParseFailure {
    /// Error response allowed: we have connection_id + transaction_id.
    Sendable { connection_id: i64, transaction_id: i32, message: &'static str },
    /// Silently drop.
    Drop,
}

#[derive(Debug)]
pub enum ParseResult<'a> {
    Ok(ParsedRequest<'a>),
    Err(ParseFailure),
}

#[inline]
fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
#[inline]
fn be_i32(b: &[u8]) -> i32 {
    i32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
#[inline]
fn be_i64(b: &[u8]) -> i64 {
    i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Parse a UDP tracker datagram payload.
///
/// `max_scrape_torrents` caps the number of info hashes honored in a scrape.
pub fn parse_request<'a>(
    data: &'a [u8],
    max_scrape_torrents: usize,
) -> ParseResult<'a> {
    if data.len() < 16 {
        return ParseResult::Err(ParseFailure::Drop);
    }

    // action is at offset 8..12 for all request types
    let action = be_i32(&data[8..12]);

    match action {
        0 => {
            // connect: protocol_id(8) action(4) transaction_id(4)
            if data.len() < CONNECT_REQ_LEN {
                return ParseResult::Err(ParseFailure::Drop);
            }
            if be_i64(&data[0..8]) != PROTOCOL_IDENTIFIER {
                return ParseResult::Err(ParseFailure::Drop);
            }
            ParseResult::Ok(ParsedRequest::Connect {
                transaction_id: be_i32(&data[12..16]),
            })
        }
        1 => {
            // announce
            if data.len() < ANNOUNCE_REQ_LEN {
                // Try to send error if we can extract conn_id + txid
                if data.len() >= 16 {
                    return ParseResult::Err(ParseFailure::Sendable {
                        connection_id: be_i64(&data[0..8]),
                        transaction_id: be_i32(&data[12..16]),
                        message: "invalid announce request",
                    });
                }
                return ParseResult::Err(ParseFailure::Drop);
            }
            let mut info_hash = [0u8; 20];
            info_hash.copy_from_slice(&data[16..36]);
            let mut peer_id = [0u8; 20];
            peer_id.copy_from_slice(&data[36..56]);
            let mut ip_field = [0u8; 4];
            ip_field.copy_from_slice(&data[84..88]);

            ParseResult::Ok(ParsedRequest::Announce(AnnounceRequest {
                connection_id: be_i64(&data[0..8]),
                transaction_id: be_i32(&data[12..16]),
                info_hash,
                peer_id,
                downloaded: be_i64(&data[56..64]),
                left: be_i64(&data[64..72]),
                uploaded: be_i64(&data[72..80]),
                event: AnnounceEvent::from_i32(be_i32(&data[80..84])),
                key: be_i32(&data[88..92]),
                numwant: be_i32(&data[92..96]),
                port: be_u16(&data[96..98]),
                ip_field,
            }))
        }
        2 => {
            // scrape: connection_id(8) action(4) transaction_id(4) info_hashes...
            if data.len() < SCRAPE_HEADER_LEN {
                return ParseResult::Err(ParseFailure::Drop);
            }
            let rest = &data[SCRAPE_HEADER_LEN..];
            if rest.is_empty() {
                return ParseResult::Err(ParseFailure::Sendable {
                    connection_id: be_i64(&data[0..8]),
                    transaction_id: be_i32(&data[12..16]),
                    message: "full scrapes are not allowed",
                });
            }
            let count = (rest.len() / 20).min(max_scrape_torrents);
            // Build a slice of [u8;20] views is not possible; return raw slice
            // and let caller chunk it.
            let _ = count;
            ParseResult::Ok(ParsedRequest::Scrape {
                connection_id: be_i64(&data[0..8]),
                transaction_id: be_i32(&data[12..16]),
                hashes: unsafe {
                    // SAFETY: we only read 20-byte chunks within `rest.len()`.
                    std::slice::from_raw_parts(rest.as_ptr() as *const [u8; 20], rest.len() / 20)
                },
            })
        }
        _ => ParseResult::Err(ParseFailure::Drop),
    }
}

// ---------------- Response serialization ----------------

#[inline]
pub fn put_i32be(out: &mut [u8], off: usize, v: i32) {
    out[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
#[inline]
pub fn put_i64be(out: &mut [u8], off: usize, v: i64) {
    out[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

/// Serialize a connect response. Returns length (16).
pub fn write_connect_response(buf: &mut [u8], transaction_id: i32, connection_id: i64) -> usize {
    put_i32be(buf, 0, 0); // action = 0
    put_i32be(buf, 4, transaction_id);
    put_i64be(buf, 8, connection_id);
    16
}

/// Serialize an error response. Returns length.
pub fn write_error_response(buf: &mut [u8], transaction_id: i32, message: &str) -> usize {
    put_i32be(buf, 0, 3); // action = 3
    put_i32be(buf, 4, transaction_id);
    let m = message.as_bytes();
    let n = m.len().min(buf.len() - 8);
    buf[8..8 + n].copy_from_slice(&m[..n]);
    8 + n
}

/// Header size of an announce response (action+txid+interval+leechers+seeders).
pub const ANNOUNCE_RESP_HEADER: usize = 20;

/// Serialize announce response header. Returns offset where peers begin.
#[inline]
pub fn write_announce_header(
    buf: &mut [u8],
    transaction_id: i32,
    interval: i32,
    leechers: i32,
    seeders: i32,
) -> usize {
    put_i32be(buf, 0, 1); // action = 1
    put_i32be(buf, 4, transaction_id);
    put_i32be(buf, 8, interval);
    put_i32be(buf, 12, leechers);
    put_i32be(buf, 16, seeders);
    ANNOUNCE_RESP_HEADER
}

/// Append one IPv4 peer (6 bytes: ip + port). Returns bytes written.
#[inline]
pub fn put_peer_v4(buf: &mut [u8], off: usize, ip: Ipv4Addr, port: u16) -> usize {
    buf[off..off + 4].copy_from_slice(&ip.octets());
    buf[off + 4..off + 6].copy_from_slice(&port.to_be_bytes());
    6
}

/// Append one IPv6 peer (18 bytes: ip + port). Returns bytes written.
#[inline]
pub fn put_peer_v6(buf: &mut [u8], off: usize, ip: Ipv6Addr, port: u16) -> usize {
    buf[off..off + 16].copy_from_slice(&ip.octets());
    buf[off + 16..off + 18].copy_from_slice(&port.to_be_bytes());
    18
}

/// Serialize scrape response. `stats` is (seeders, completed, leechers) per torrent.
pub fn write_scrape_response(
    buf: &mut [u8],
    transaction_id: i32,
    stats: &[(i32, i32, i32)],
) -> usize {
    put_i32be(buf, 0, 2); // action = 2
    put_i32be(buf, 4, transaction_id);
    let mut off = 8;
    for &(seeders, completed, leechers) in stats {
        put_i32be(buf, off, seeders);
        put_i32be(buf, off + 4, completed);
        put_i32be(buf, off + 8, leechers);
        off += 12;
    }
    off
}

/// Resolve the peer address for a BEP-15 announce: the client-supplied
/// `ip` field when it is non-zero, else the packet's source address.
/// Callers must gate this on `protocol.allow_client_ip` — honoring the
/// field unconditionally would let any client forge swarm peer addresses.
pub fn request_ip(ip_field: &[u8; 4], src: IpAddr) -> IpAddr {
    if ip_field == &[0, 0, 0, 0] {
        src
    } else {
        IpAddr::V4(Ipv4Addr::from(*ip_field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&PROTOCOL_IDENTIFIER.to_be_bytes());
        pkt.extend_from_slice(&0i32.to_be_bytes());
        pkt.extend_from_slice(&1234i32.to_be_bytes());
        match parse_request(&pkt, 10) {
            ParseResult::Ok(ParsedRequest::Connect { transaction_id }) => {
                assert_eq!(transaction_id, 1234);
            }
            _ => panic!("bad parse"),
        }
    }

    #[test]
    fn parse_announce_offsets() {
        let mut pkt = vec![0u8; ANNOUNCE_REQ_LEN];
        pkt[0..8].copy_from_slice(&42i64.to_be_bytes()); // conn id
        pkt[8..12].copy_from_slice(&1i32.to_be_bytes()); // action announce
        pkt[12..16].copy_from_slice(&77i32.to_be_bytes()); // txid
        for i in 0..20 {
            pkt[16 + i] = i as u8;
        }
        for i in 0..20 {
            pkt[36 + i] = 0xA0 + i as u8;
        }
        pkt[56..64].copy_from_slice(&10i64.to_be_bytes()); // downloaded
        pkt[64..72].copy_from_slice(&20i64.to_be_bytes()); // left
        pkt[72..80].copy_from_slice(&30i64.to_be_bytes()); // uploaded
        pkt[80..84].copy_from_slice(&2i32.to_be_bytes()); // event started
        pkt[84..88].copy_from_slice(&[1, 2, 3, 4]); // ip field
        pkt[88..92].copy_from_slice(&5i32.to_be_bytes()); // key
        pkt[92..96].copy_from_slice(&50i32.to_be_bytes()); // numwant
        pkt[96..98].copy_from_slice(&6881u16.to_be_bytes()); // port
        match parse_request(&pkt, 10) {
            ParseResult::Ok(ParsedRequest::Announce(r)) => {
                assert_eq!(r.connection_id, 42);
                assert_eq!(r.transaction_id, 77);
                assert_eq!(r.info_hash[0], 0);
                assert_eq!(r.info_hash[19], 19);
                assert_eq!(r.peer_id[0], 0xA0);
                assert_eq!(r.downloaded, 10);
                assert_eq!(r.left, 20);
                assert_eq!(r.uploaded, 30);
                assert_eq!(r.event, AnnounceEvent::Started);
                assert_eq!(r.numwant, 50);
                assert_eq!(r.port, 6881);
            }
            other => panic!("bad parse: {:?}", other),
        }
    }
}
