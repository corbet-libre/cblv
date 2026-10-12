//! Inner Binary HTTP messages. The request carries a random nonce and a
//! timestamp (replay binding, OHTTP has none of its own); both directions are
//! padded with zero bytes to size classes so lengths leak less.
use crate::{Error, Result};
use bhttp::{Message, Mode, StatusCode};
use std::io::Cursor;

pub const NONCE_HEADER: &[u8] = b"x-ohttp-nonce";
pub const TIMESTAMP_HEADER: &[u8] = b"x-ohttp-ts";
const CLASSES: [usize; 3] = [1024, 4096, 16384];
const STEP: usize = 16384;
const MAX_HEADERS: usize = 64;

pub type Headers = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: Vec<u8>,
    pub authority: Vec<u8>,
    pub path: Vec<u8>,
    pub headers: Headers,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

/// A decoded request with the replay binding split off.
#[derive(Debug)]
pub struct Decoded {
    pub request: Request,
    pub nonce: [u8; 16],
    pub timestamp: u64,
}

pub fn padded_len(length: usize) -> usize {
    CLASSES
        .into_iter()
        .find(|class| *class >= length)
        .unwrap_or_else(|| length.div_ceil(STEP) * STEP)
}

fn finish(message: &Message) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    message
        .write_bhttp(Mode::KnownLength, &mut out)
        .map_err(|_| Error::Codec)?;
    out.resize(padded_len(out.len()), 0);
    Ok(out)
}

/// Parse one message and require the rest to be zero padding.
fn parse(bytes: &[u8]) -> Result<Message> {
    let mut cursor = Cursor::new(bytes);
    let message = Message::read_bhttp(&mut cursor).map_err(|_| Error::Codec)?;
    let used = usize::try_from(cursor.position()).map_err(|_| Error::Codec)?;
    if bytes[used..].iter().any(|byte| *byte != 0) {
        return Err(Error::Codec);
    }
    Ok(message)
}

pub fn encode_request(request: &Request, nonce: &[u8; 16], timestamp: u64) -> Result<Vec<u8>> {
    if request.headers.len() > MAX_HEADERS {
        return Err(Error::Codec);
    }
    let mut message = Message::request(
        request.method.clone(),
        b"https".to_vec(),
        request.authority.clone(),
        request.path.clone(),
    );
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if lower == NONCE_HEADER || lower == TIMESTAMP_HEADER {
            return Err(Error::Codec);
        }
        message.put_header(lower, value.clone());
    }
    message.put_header(NONCE_HEADER, hex(nonce).into_bytes());
    message.put_header(TIMESTAMP_HEADER, timestamp.to_string().into_bytes());
    message.write_content(&request.body);
    finish(&message)
}

pub fn decode_request(bytes: &[u8]) -> Result<Decoded> {
    let message = parse(bytes)?;
    let control = message.control();
    let (Some(method), Some(authority), Some(path)) =
        (control.method(), control.authority(), control.path())
    else {
        return Err(Error::Codec);
    };
    let mut nonce = None;
    let mut timestamp = None;
    let mut headers = Vec::new();
    for field in message.header().iter() {
        if headers.len() >= MAX_HEADERS {
            return Err(Error::Codec);
        }
        if field.name() == NONCE_HEADER {
            if nonce.replace(unhex(field.value())?).is_some() {
                return Err(Error::Codec);
            }
        } else if field.name() == TIMESTAMP_HEADER {
            let text = std::str::from_utf8(field.value()).map_err(|_| Error::Codec)?;
            if timestamp
                .replace(text.parse::<u64>().map_err(|_| Error::Codec)?)
                .is_some()
            {
                return Err(Error::Codec);
            }
        } else {
            headers.push((field.name().to_vec(), field.value().to_vec()));
        }
    }
    Ok(Decoded {
        request: Request {
            method: method.to_vec(),
            authority: authority.to_vec(),
            path: path.to_vec(),
            headers,
            body: message.content().to_vec(),
        },
        nonce: nonce.ok_or(Error::Codec)?,
        timestamp: timestamp.ok_or(Error::Codec)?,
    })
}

pub fn encode_response(response: &Response) -> Result<Vec<u8>> {
    if response.headers.len() > MAX_HEADERS {
        return Err(Error::Codec);
    }
    let status = StatusCode::try_from(response.status).map_err(|_| Error::Codec)?;
    let mut message = Message::response(status);
    for (name, value) in &response.headers {
        message.put_header(name.to_ascii_lowercase(), value.clone());
    }
    message.write_content(&response.body);
    finish(&message)
}

pub fn decode_response(bytes: &[u8]) -> Result<Response> {
    let message = parse(bytes)?;
    let status = message.control().status().ok_or(Error::Codec)?;
    Ok(Response {
        status: status.code(),
        headers: message
            .header()
            .iter()
            .map(|field| (field.name().to_vec(), field.value().to_vec()))
            .collect(),
        body: message.content().to_vec(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &[u8]) -> Result<[u8; 16]> {
    if text.len() != 32 {
        return Err(Error::Codec);
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Error::Codec),
    };
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(text.chunks(2)) {
        *slot = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Request {
        Request {
            method: b"POST".to_vec(),
            authority: b"api.example".to_vec(),
            path: b"/v1/x".to_vec(),
            headers: vec![(b"origin".to_vec(), b"https://a.example".to_vec())],
            body: b"{}".to_vec(),
        }
    }

    #[test]
    fn request_round_trips_and_is_padded() {
        let bytes = encode_request(&sample(), &[7; 16], 42).unwrap();
        assert_eq!(bytes.len(), 1024);
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.request, sample());
        assert_eq!((decoded.nonce, decoded.timestamp), ([7; 16], 42));
    }

    #[test]
    fn nonzero_padding_missing_or_duplicate_binding_is_refused() {
        let mut bytes = encode_request(&sample(), &[7; 16], 42).unwrap();
        *bytes.last_mut().unwrap() = 1;
        assert_eq!(decode_request(&bytes).unwrap_err(), Error::Codec);
        let mut plain = sample();
        plain.headers.push((NONCE_HEADER.to_vec(), b"00".to_vec()));
        assert_eq!(
            encode_request(&plain, &[7; 16], 1).unwrap_err(),
            Error::Codec
        );
        let mut message = Message::request(
            b"POST".to_vec(),
            b"https".to_vec(),
            b"a".to_vec(),
            b"/".to_vec(),
        );
        message.write_content(b"");
        let mut raw = Vec::new();
        message.write_bhttp(Mode::KnownLength, &mut raw).unwrap();
        assert_eq!(decode_request(&raw).unwrap_err(), Error::Codec);
    }

    #[test]
    fn response_round_trips() {
        let response = Response {
            status: 200,
            headers: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
            body: vec![1; 5000],
        };
        let bytes = encode_response(&response).unwrap();
        assert_eq!(bytes.len(), 16384);
        assert_eq!(decode_response(&bytes).unwrap(), response);
    }

    #[test]
    fn padding_classes() {
        assert_eq!(padded_len(1), 1024);
        assert_eq!(padded_len(1025), 4096);
        assert_eq!(padded_len(16385), 32768);
    }
}
