use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsParsedMessage {
    pub id: u16,
    pub is_response: bool,
    pub qname: Option<String>,
    pub qtype: Option<u16>,
    #[serde(default)]
    pub answers: Vec<String>,
}

pub fn qtype_to_string(qtype: u16) -> Option<String> {
    match qtype {
        1 => Some("A".to_string()),
        5 => Some("CNAME".to_string()),
        15 => Some("MX".to_string()),
        28 => Some("AAAA".to_string()),
        _ => None,
    }
}

fn read_u16(payload: &[u8], off: usize) -> Option<u16> {
    if off + 2 > payload.len() {
        return None;
    }
    Some(u16::from_be_bytes([payload[off], payload[off + 1]]))
}

fn read_u32(payload: &[u8], off: usize) -> Option<u32> {
    if off + 4 > payload.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        payload[off],
        payload[off + 1],
        payload[off + 2],
        payload[off + 3],
    ]))
}

fn parse_name(payload: &[u8], mut off: usize, depth: u8) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let mut labels: Vec<String> = Vec::new();
    let jumped = false;
    let mut end_off = off;

    loop {
        if off >= payload.len() {
            return None;
        }
        let len = payload[off] as usize;
        if len == 0 {
            off += 1;
            if !jumped {
                end_off = off;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if off + 1 >= payload.len() {
                return None;
            }
            let ptr = (((payload[off] as u16 & 0x3F) << 8) | payload[off + 1] as u16) as usize;
            if !jumped {
                end_off = off + 2;
            }
            let (name2, _) = parse_name(payload, ptr, depth + 1)?;
            if !name2.is_empty() {
                labels.push(name2);
            }
            break;
        }
        if len > 63 {
            return None;
        }
        off += 1;
        if off + len > payload.len() {
            return None;
        }
        let part = String::from_utf8_lossy(&payload[off..off + len]).to_string();
        labels.push(part);
        off += len;
        if !jumped {
            end_off = off;
        }
        if labels.len() > 64 {
            return None;
        }
    }

    let name = labels.join(".");
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    Some((name, end_off))
}

fn skip_name(payload: &[u8], mut off: usize) -> Option<usize> {
    let (_, end) = parse_name(payload, off, 0)?;
    off = end;
    Some(off)
}

pub fn parse_dns_message(payload: &[u8]) -> Option<DnsParsedMessage> {
    if payload.len() < 12 {
        return None;
    }
    let id = read_u16(payload, 0)?;
    let flags = read_u16(payload, 2)?;
    let qdcount = read_u16(payload, 4)? as usize;
    let ancount = read_u16(payload, 6)? as usize;

    let is_response = ((flags >> 15) & 1) == 1;

    let mut off = 12usize;
    let mut qname: Option<String> = None;
    let mut qtype: Option<u16> = None;

    if qdcount > 0 {
        let (qn, end) = parse_name(payload, off, 0)?;
        off = end;
        qname = Some(qn);
        qtype = read_u16(payload, off);
        off += 4;
    }

    let mut answers: Vec<String> = Vec::new();
    let max_answers = 8usize;

    for _ in 0..ancount {
        if answers.len() >= max_answers {
            break;
        }
        off = skip_name(payload, off)?;
        let atype = read_u16(payload, off)?;
        off += 2;
        let _aclass = read_u16(payload, off)?;
        off += 2;
        let _ttl = read_u32(payload, off)?;
        off += 4;
        let rdlen = read_u16(payload, off)? as usize;
        off += 2;
        if off + rdlen > payload.len() {
            return None;
        }
        let rdata = &payload[off..off + rdlen];
        if atype == 1 && rdlen == 4 {
            let ip = std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
            answers.push(ip.to_string());
        } else if atype == 28 && rdlen == 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(rdata);
            let ip = std::net::Ipv6Addr::from(b);
            answers.push(ip.to_string());
        }
        off += rdlen;
    }

    Some(DnsParsedMessage {
        id,
        is_response,
        qname,
        qtype,
        answers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_query_and_response() {
        let query: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // qname
            0x00, 0x01, 0x00, 0x01, // qtype A, class IN
        ];
        let q = parse_dns_message(&query).unwrap();
        assert_eq!(q.id, 0x1234);
        assert!(!q.is_response);
        assert_eq!(q.qname.as_deref(), Some("example.com"));
        assert_eq!(q.qtype, Some(1));

        let resp: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // qname
            0x00, 0x01, 0x00, 0x01, // qtype A, class IN
            0xC0, 0x0C, // name ptr to qname
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
            0x00, 0x00, 0x00, 0x3C, // ttl
            0x00, 0x04, // rdlen
            0x5D, 0xB8, 0xD8, 0x22, // 93.184.216.34
        ];
        let r = parse_dns_message(&resp).unwrap();
        assert!(r.is_response);
        assert_eq!(r.qname.as_deref(), Some("example.com"));
        assert_eq!(r.answers, vec!["93.184.216.34".to_string()]);

        assert_eq!(qtype_to_string(1).as_deref(), Some("A"));
        assert_eq!(qtype_to_string(28).as_deref(), Some("AAAA"));
    }
}
