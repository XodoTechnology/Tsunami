//! peer_id -> client name mapping (BEP 20 conventions).
//!
//! The first 8 bytes of a peer_id carry the client signature. We match on
//! common prefixes; anything unrecognized yields the raw prefix hex.

/// Identify a client from its 20-byte peer_id. Returns a display name.
pub fn client_name(peer_id: &[u8; 20]) -> String {
    let p = &peer_id[..8];
    // Azureus/Vuze style: "-XXXXXX-" e.g. "-qB4250-", "-TR2940-", "-lt0D80-"
    if p[0] == b'-' && p[7] == b'-' {
        let inner = &p[1..7];
        return match inner {
            b"qB4250" | b"qB4260" | b"qB4270" | b"qB4280" => "qBittorrent".into(),
            b"TR2940" | b"TR3000" | b"TR301Z" | b"TR302Z" => "Transmission".into(),
            b"lt0D00" | b"lt0D80" | b"lt01B0" | b"lt02B0" | b"lt03B0" => "libtorrent/rTorrent".into(),
            b"lt14B0" | b"lt15B0" | b"lt16B0" | b"lt17B0" => "libtorrent 2.x".into(),
            b"AZ2500" | b"AZ2600" | b"AZ2700" => "Azureus/Vuze".into(),
            b"DE150s" | b"DE160s" | b"DE161s" | b"DE170s" => "Deluge".into(),
            b"UT3530" | b"UT353B" | b"UT353T" => "uTorrent".into(),
            b"UM2100" | b"UM2200" => "uTorrent Mac".into(),
            b"BT1400" | b"BT1420" => "BitComet".into(),
            b"XL0010" | b"XL0012" | b"XL0014" | b"XL0015" | b"XL0016" | b"XL0017" => {
                "Xunlei/Thunder".into()
            }
            b"MP5510" | b"MP5500" => "MooPolice".into(),
            b"BC0250" | b"BC0260" => "BitComet".into(),
            b"KT0340" | b"KT0380" => "KTorrent".into(),
            _ => format!("Azureus-style {}", String::from_utf8_lossy(p)),
        };
    }
    // Shadow-style: "S" + 5 chars + version
    if p[0] == b'S' {
        return match &p[1..4] {
            b"has" => "Shareaza".into(),
            b"amu" => "eMule".into(),
            _ => format!("Shadow-style {}", String::from_utf8_lossy(p)),
        };
    }
    // Transmission also uses "TR" prefix without dashes in some versions
    if p.starts_with(b"TR") {
        return "Transmission".into();
    }
    // qBittorrent non-dash variants
    if p.starts_with(b"qB") {
        return "qBittorrent".into();
    }
    // Deluge sometimes "DE"
    if p.starts_with(b"DE") {
        return "Deluge".into();
    }
    format!("{:02x?}", &p[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let mut id = [0u8; 20];
        id[..8].copy_from_slice(b"-qB4250-");
        assert_eq!(client_name(&id), "qBittorrent");
        id[..8].copy_from_slice(b"-TR2940-");
        assert_eq!(client_name(&id), "Transmission");
    }
}
