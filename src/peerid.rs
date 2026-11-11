//! peer_id -> "client name + version" mapping (BEP 20 conventions).
//!
//! The first 8 bytes of a peer_id carry the client signature. Azureus-style
//! ids (`-XXvvvv-`) embed a version whose encoding is client-specific; we
//! decode the major families and fall back to a plain name (or "unknown")
//! for everything else — never raw hex, so stats pages stay readable.

/// Identify a client from its peer_id (20 bytes, or the 8-byte stats key).
/// Returns e.g. "qBittorrent 5.0.1", "Transmission 4.0.0", or "unknown".
pub fn client_name(peer_id: &[u8]) -> String {
    if peer_id.len() < 8 {
        return "unknown".into();
    }
    let p = &peer_id[..8];

    // Mainline style: 'M' + "major-minor-patch-" e.g. "M4-3-6--" / "M4-20-8-"
    if p[0] == b'M' {
        if let Some(v) = mainline_version(&p[1..8]) {
            return format!("BitTorrent {v}");
        }
        return "BitTorrent".into();
    }

    // BitComet/BitLord style: "exbc" + 2 version bytes
    if p.starts_with(b"exbc") {
        return "BitComet".into();
    }

    // Shadow-style: 'S' + 5 chars + version digit(s)
    if p[0] == b'S' {
        return match &p[1..4] {
            b"has" => "Shareaza".into(),
            b"amu" => "eMule".into(),
            _ => "Shadow-style client".into(),
        };
    }

    // Azureus-style: '-' + 2-char client code + 4-char version + '-'
    if p[0] == b'-' && p[7] == b'-' {
        let code = &p[1..3];
        let ver = &p[3..7];
        return azureus_name(code, ver);
    }

    // Non-dash prefixes used by some clients
    if p.starts_with(b"qB") {
        return "qBittorrent".into();
    }
    if p.starts_with(b"TR") {
        return "Transmission".into();
    }
    if p.starts_with(b"DE") {
        return "Deluge".into();
    }

    "unknown".into()
}

/// Parse "M4-3-6--"-style remainder into "4.3.6" (minor may be multi-digit).
fn mainline_version(p: &[u8]) -> Option<String> {
    // Expect digits/dashes only: e.g. b"4-3-6-" or b"4-20-8-"
    let s = std::str::from_utf8(p).ok()?;
    let mut it = s.split('-').filter(|x| !x.is_empty());
    let major = it.next()?;
    let minor = it.next()?;
    let patch = it.next()?;
    if major.len() > 3 || minor.len() > 3 || patch.len() > 3 {
        return None;
    }
    if !major.bytes().all(|b| b.is_ascii_digit())
        || !minor.bytes().all(|b| b.is_ascii_digit())
        || !patch.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some(format!("{major}.{minor}.{patch}"))
}

/// Azureus-style `-XXvvvv-`: map the 2-char client code to a name and decode
/// the 4 version chars where the scheme is known.
fn azureus_name(code: &[u8], ver: &[u8]) -> String {
    // uTorrent-style Mmmpp decimal: n/1000 . (n%1000)/100 . (n%100)/10
    let dec4 = |v: &[u8]| -> Option<(u32, u32, u32)> {
        if !v.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u32 = std::str::from_utf8(v).ok()?.parse().ok()?;
        Some((n / 1000, (n % 1000) / 100, (n % 100) / 10))
    };
    // qBittorrent: M m p t — patch is a single HEX digit (24A0 = 2.4.10)
    let qb = |v: &[u8]| -> Option<String> {
        if !v[0].is_ascii_digit() || !v[1].is_ascii_digit() || !v[3].is_ascii_digit() {
            return None;
        }
        let patch = (v[2] as char).to_digit(16)?;
        Some(format!("{}.{}.{}", v[0] as char, v[1] as char, patch))
    };

    let with_ver = |n: &str, v: Option<String>| -> String {
        match v {
            Some(v) => format!("{n} {v}"),
            None => n.to_string(),
        }
    };

    match code {
        b"qB" => with_ver("qBittorrent", qb(ver)),
        b"TR" => with_ver("Transmission", tr_version(ver)),
        b"UT" | b"UM" => {
            let n = if code == b"UT" { "uTorrent" } else { "uTorrent Mac" };
            with_ver(n, dec4(ver).map(|(a, b, c)| format!("{a}.{b}.{c}")))
        }
        b"AZ" => with_ver(
            "Azureus/Vuze",
            dec4(ver).map(|(a, b, c)| format!("{a}.{b}.{c}")),
        ),
        b"LT" | b"lt" => with_ver("libtorrent/rasterbar", lt_version(ver)),
        b"DE" => with_ver("Deluge", de_version(ver)),
        b"BT" => with_ver("BitTorrent", dec4(ver).map(|(a, b, c)| format!("{a}.{b}.{c}"))),
        b"XL" => "Xunlei/Thunder".to_string(),
        _ => azureus_plain_name(code).unwrap_or("unknown").to_string(),
    }
}

/// Transmission `-TR????-` version field. Two documented schemes:
///  - >=3.00: X,Y,Z base62 major/minor/patch + release tag R (0/B/Z)
///  - 0.80-3.00: X major digit, YY minor, R release tag
///  - <0.80:    two major + two minor digits
fn tr_version(v: &[u8]) -> Option<String> {
    let b62 = |c: u8| -> Option<u32> {
        match c {
            b'0'..=b'9' => Some((c - b'0') as u32),
            b'A'..=b'Z' => Some((c - b'A' + 10) as u32),
            b'a'..=b'z' => Some((c - b'a' + 36) as u32),
            _ => None,
        }
    };
    // New scheme applies to major >= 3
    if v[0] >= b'3' {
        let (x, y, z) = (b62(v[0])?, b62(v[1])?, b62(v[2])?);
        let rel = match v[3] {
            b'0' => "",
            b'B' => " beta",
            b'Z' => " dev",
            _ => "",
        };
        return Some(format!("{x}.{y}.{z}{rel}"));
    }
    // 0.80..3.00: -TRXYYR-
    if v[0].is_ascii_digit() && v[1].is_ascii_digit() && v[2].is_ascii_digit() && v[3].is_ascii_digit()
    {
        let minor: u32 = std::str::from_utf8(&v[1..3]).ok()?.parse().ok()?;
        let rel = match v[3] {
            b'0' => "",
            b'Z' => " nightly",
            b'X' => " beta",
            _ => "",
        };
        if matches!(v[3], b'0' | b'Z' | b'X') {
            return Some(format!("{}.{}{}", v[0] as char, minor, rel));
        }
    }
    // Before 0.80: -TRmmnn- e.g. "0072" = 0.72
    if v.iter().all(|b| b.is_ascii_digit()) {
        let maj: u32 = std::str::from_utf8(&v[0..2]).ok()?.parse().ok()?;
        let min: u32 = std::str::from_utf8(&v[2..4]).ok()?.parse().ok()?;
        return Some(format!("{maj}.{min}"));
    }
    None
}

/// libtorrent `-ltXXXX-`: four hex nibbles = major.minor.revision.tag
/// (e.g. "0D80" = 0.13.8).
fn lt_version(v: &[u8]) -> Option<String> {
    let nib = |c: u8| (c as char).to_digit(16);
    let (a, b, c, d) = (nib(v[0])?, nib(v[1])?, nib(v[2])?, nib(v[3])?);
    let _ = d; // build tag — not shown
    Some(format!("{}.{}.{}", a, b, c))
}

/// Deluge `-DEnnnL-`: three decimal digits major.minor.patch + optional tag.
fn de_version(v: &[u8]) -> Option<String> {
    if !(v[0].is_ascii_digit() && v[1].is_ascii_digit() && v[2].is_ascii_digit()) {
        return None;
    }
    Some(format!(
        "{}.{}.{}",
        v[0] as char, v[1] as char, v[2] as char
    ))
}

/// Name-only mapping for Azureus-style codes without a known version scheme.
fn azureus_plain_name(code: &[u8]) -> Option<&'static str> {
    Some(match code {
        b"AG" | b"A~" => "ARES",
        b"AR" => "Arctic",
        b"AV" => "Avicora",
        b"AX" => "BitPump",
        b"BB" => "BitBuddy",
        b"BC" => "BitComet",
        b"BF" => "Bitflu",
        b"BG" => "BTG",
        b"BR" => "BitRocket",
        b"BS" => "BitSlave",
        b"BX" => "BitTorrent X",
        b"CD" => "Enhanced CTorrent",
        b"CT" => "CTorrent",
        b"DP" => "Propagate Data Client",
        b"EB" => "EBit",
        b"ES" => "Electric Sheep",
        b"FT" => "FoxTorrent",
        b"FW" => "FrostWire",
        b"FX" => "Freebox BitTorrent",
        b"GS" => "GSTorrent",
        b"HL" => "Halite",
        b"HN" => "Hydranode",
        b"KG" => "KGet",
        b"KT" => "KTorrent",
        b"LH" => "LH-ABC",
        b"LP" => "Lphant",
        b"LW" => "LimeWire",
        b"MO" => "MonoTorrent",
        b"MP" => "MooPolice",
        b"MR" => "Miro",
        b"MT" => "MoonlightTorrent",
        b"NX" => "Net Transport",
        b"PD" => "Pando",
        b"QD" => "QQDownload",
        b"QT" => "Qt 4 Torrent",
        b"RT" => "Retriever",
        b"SB" => "Swiftbit",
        b"SS" => "SwarmScope",
        b"ST" => "SymTorrent",
        b"st" => "SharkTorrent",
        b"TN" => "TorrentDotNET",
        b"TS" => "Torrentstorm",
        b"TT" => "TuoTu",
        b"UL" => "uLeecher!",
        b"UW" => "uTorrent Web",
        b"VG" => "Vagaa",
        b"WT" => "BitLet",
        b"WW" => "WebTorrent",
        b"WY" => "FireTorrent",
        b"XT" => "XanTorrent",
        b"XX" => "Xtorrent",
        b"ZT" => "ZipTorrent",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(prefix: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[..prefix.len()].copy_from_slice(prefix);
        v
    }

    #[test]
    fn qbittorrent_versions() {
        assert_eq!(client_name(&pid(b"-qB5010-")), "qBittorrent 5.0.1");
        assert_eq!(client_name(&pid(b"-qB4250-")), "qBittorrent 4.2.5");
        assert_eq!(client_name(&pid(b"-qB24A0-")), "qBittorrent 2.4.10");
        assert_eq!(client_name(&pid(b"-qB5300-")), "qBittorrent 5.3.0");
    }

    #[test]
    fn transmission_versions() {
        // New base62 scheme (>=3.00): -TR4140- -> 4.1.4
        assert_eq!(client_name(&pid(b"-TR4140-")), "Transmission 4.1.4");
        // Old scheme: -TR2940- -> 2.94
        assert_eq!(client_name(&pid(b"-TR2940-")), "Transmission 2.94");
        assert_eq!(client_name(&pid(b"-TR1330-")), "Transmission 1.33");
        // Pre-0.80: -TR0072- -> 0.72
        assert_eq!(client_name(&pid(b"-TR0072-")), "Transmission 0.72");
    }

    #[test]
    fn libtorrent_hex_version() {
        assert_eq!(
            client_name(&pid(b"-lt0D80-")),
            "libtorrent/rasterbar 0.13.8"
        );
        assert_eq!(
            client_name(&pid(b"-LT14B0-")),
            "libtorrent/rasterbar 1.4.11"
        );
    }

    #[test]
    fn utorrent_deluge_azureus() {
        assert_eq!(client_name(&pid(b"-UT3530-")), "uTorrent 3.5.3");
        assert_eq!(client_name(&pid(b"-UM2100-")), "uTorrent Mac 2.1.0");
        assert_eq!(client_name(&pid(b"-DE161s-")), "Deluge 1.6.1");
        assert_eq!(client_name(&pid(b"-AZ2060-")), "Azureus/Vuze 2.0.6");
    }

    #[test]
    fn mainline_and_misc() {
        assert_eq!(client_name(&pid(b"M4-3-6--")), "BitTorrent 4.3.6");
        assert_eq!(client_name(&pid(b"M4-20-8-")), "BitTorrent 4.20.8");
        assert_eq!(client_name(&pid(b"exbc\x01\x02xx")), "BitComet");
        assert_eq!(client_name(&pid(b"-ZZ1234-")), "unknown");
        assert_eq!(client_name(&pid(b"01234567")), "unknown");
        assert_eq!(client_name(&pid(b"\x00\x01\x02\x03\x04\x05\x06\x07")), "unknown");
    }
}
