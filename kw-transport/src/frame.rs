//! Frame codecs. Control frames are length-prefixed JSON envelopes;
//! media frames are kind-tagged binary blobs.

use std::io::{Read, Write};

/// Maximum control frame body (1MiB). Larger frames are a protocol violation.
pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;
/// Maximum media frame body (8MiB for a 1080p IDR with headroom).
pub const MAX_MEDIA_BYTES: usize = 8 * 1024 * 1024;

/// Media payload kind. Only `H264` and `Opus` exist; anything else is
/// rejected — the agent never forwards opaque bytes it cannot describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    H264 = 1,
    Opus = 2,
}

impl MediaKind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(MediaKind::H264),
            2 => Some(MediaKind::Opus),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    TooLarge,
    UnknownMediaKind(u8),
    BadJson(serde_json::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "io: {e}"),
            FrameError::TooLarge => write!(f, "frame exceeds size cap"),
            FrameError::UnknownMediaKind(k) => write!(f, "unknown media kind {k}"),
            FrameError::BadJson(e) => write!(f, "control frame is not an envelope: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Tag byte distinguishing control from media on the wire: `0x00` = JSON
/// control envelope, `0x01`/`0x02` = media kinds.
pub enum Frame {
    Control(kw_protocol::Envelope),
    Media { kind: MediaKind, payload: Vec<u8> },
}

/// Read one frame. `Ok(None)` means orderly EOF before the tag byte.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Frame>, FrameError> {
    let mut tag = [0u8; 1];
    match reader.read_exact(&mut tag) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    }
    if tag[0] == 0x00 {
        let mut len = [0u8; 4];
        reader.read_exact(&mut len).map_err(FrameError::Io)?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_CONTROL_BYTES {
            return Err(FrameError::TooLarge);
        }
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).map_err(FrameError::Io)?;
        let envelope: kw_protocol::Envelope =
            serde_json::from_slice(&body).map_err(FrameError::BadJson)?;
        Ok(Some(Frame::Control(envelope)))
    } else {
        let kind = MediaKind::from_byte(tag[0]).ok_or(FrameError::UnknownMediaKind(tag[0]))?;
        let mut len = [0u8; 4];
        reader.read_exact(&mut len).map_err(FrameError::Io)?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MEDIA_BYTES {
            return Err(FrameError::TooLarge);
        }
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload).map_err(FrameError::Io)?;
        Ok(Some(Frame::Media { kind, payload }))
    }
}

/// Write one control envelope.
pub fn write_control(
    writer: &mut impl Write,
    message: &kw_protocol::Envelope,
) -> Result<(), FrameError> {
    let body = serde_json::to_vec(message).map_err(FrameError::BadJson)?;
    if body.is_empty() || body.len() > MAX_CONTROL_BYTES {
        return Err(FrameError::TooLarge);
    }
    writer.write_all(&[0x00]).map_err(FrameError::Io)?;
    writer
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(FrameError::Io)?;
    writer.write_all(&body).map_err(FrameError::Io)?;
    writer.flush().map_err(FrameError::Io)?;
    Ok(())
}

/// Write one media frame: kind tag + big-endian length + raw codec bytes
/// (Annex-B H.264 access unit, or one Opus packet). Empty and oversized
/// payloads are refused rather than truncated.
pub fn write_media(
    writer: &mut impl Write,
    kind: MediaKind,
    payload: &[u8],
) -> Result<(), FrameError> {
    if payload.is_empty() || payload.len() > MAX_MEDIA_BYTES {
        return Err(FrameError::TooLarge);
    }
    writer.write_all(&[kind as u8]).map_err(FrameError::Io)?;
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(FrameError::Io)?;
    writer.write_all(payload).map_err(FrameError::Io)?;
    writer.flush().map_err(FrameError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(message_type: &str) -> kw_protocol::Envelope {
        serde_json::from_value(serde_json::json!({
            "protocol": "kw-agent-v1", "protocolVersion": 1, "sessionId": "s",
            "generation": 1, "sequence": 1, "sentAtNs": 1,
            "channel": "control", "type": message_type, "payload": {},
        }))
        .unwrap()
    }

    #[test]
    fn control_round_trips() {
        let mut wire = Vec::new();
        write_control(&mut wire, &envelope("hello")).unwrap();
        match read_frame(&mut &wire[..])
            .expect("readable")
            .expect("frame")
        {
            Frame::Control(back) => assert_eq!(back.message_type, "hello"),
            Frame::Media { .. } => panic!("wrong variant"),
        }
    }

    #[test]
    fn media_round_trips_with_kind() {
        let mut wire = Vec::new();
        write_media(&mut wire, MediaKind::Opus, &[9, 9, 9]).unwrap();
        // Tag byte must be the Opus kind, not control.
        assert_eq!(wire[0], 0x02);
        match read_frame(&mut &wire[..])
            .expect("readable")
            .expect("frame")
        {
            Frame::Media { kind, payload } => {
                assert_eq!(kind, MediaKind::Opus);
                assert_eq!(payload, vec![9, 9, 9]);
            }
            Frame::Control(_) => panic!("wrong variant"),
        }
    }

    #[test]
    fn write_media_refuses_empty_and_oversize() {
        let mut wire = Vec::new();
        assert!(matches!(
            write_media(&mut wire, MediaKind::H264, &[]),
            Err(FrameError::TooLarge)
        ));
        assert!(matches!(
            write_media(&mut wire, MediaKind::H264, &vec![0u8; MAX_MEDIA_BYTES + 1]),
            Err(FrameError::TooLarge)
        ));
        assert!(wire.is_empty(), "rejected frames write nothing");
    }

    #[test]
    fn rejects_unknown_kind_and_oversize() {
        assert!(matches!(
            read_frame(&mut &[0x09u8][..]),
            Err(FrameError::UnknownMediaKind(9))
        ));
        let mut wire = vec![0x00];
        wire.extend_from_slice(&(MAX_CONTROL_BYTES as u32 + 1).to_be_bytes());
        assert!(matches!(
            read_frame(&mut &wire[..]),
            Err(FrameError::TooLarge)
        ));
    }

    #[test]
    fn eof_before_tag_is_orderly() {
        assert!(read_frame(&mut &[][..]).expect("readable").is_none());
    }
}
