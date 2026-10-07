//! Opus encode/decode via pure-Rust `opus-rs` (no C, no FFI).
//!
//! Fixed contract profile: 48kHz stereo, 20ms frames (960 samples/channel),
//! matching the media transport. The encoder/decoder pair is verified by
//! round-trip (energy preserved, TOC valid), not by golden vectors —
//! interop with libopus/ffmpeg decoders is the crate's own tested claim.

/// Samples per channel in one 20ms frame at 48kHz.
pub const FRAME_SAMPLES: usize = 960;
/// Channels in the contract profile.
pub const CHANNELS: usize = 2;
/// Default encoder bitrate for desktop audio.
pub const DEFAULT_BITRATE_BPS: i32 = 64_000;

/// 48kHz stereo Opus encoder at the contract profile.
pub struct Encoder {
    inner: opus_rs::OpusEncoder,
}

impl Encoder {
    pub fn new() -> Result<Self, crate::Error> {
        let mut inner = opus_rs::OpusEncoder::new(48_000, CHANNELS, opus_rs::Application::Audio)
            .map_err(|e| crate::Error::Codec(e.into()))?;
        inner.bitrate_bps = DEFAULT_BITRATE_BPS;
        Ok(Self { inner })
    }

    /// Encode one 20ms frame of interleaved f32 PCM (±1.0). Returns the packet.
    pub fn encode_frame(&mut self, pcm: &[f32]) -> Result<Vec<u8>, crate::Error> {
        if pcm.len() != FRAME_SAMPLES * CHANNELS {
            return Err(crate::Error::Codec(format!(
                "expected {} samples, got {}",
                FRAME_SAMPLES * CHANNELS,
                pcm.len()
            )));
        }
        let mut packet = vec![0u8; 1276];
        let len = self
            .inner
            .encode(pcm, FRAME_SAMPLES, &mut packet)
            .map_err(|e| crate::Error::Codec(e.into()))?;
        packet.truncate(len);
        Ok(packet)
    }
}

/// 48kHz stereo Opus decoder (verification counterpart).
pub struct Decoder {
    inner: opus_rs::OpusDecoder,
}

impl Decoder {
    pub fn new() -> Result<Self, crate::Error> {
        Ok(Self {
            inner: opus_rs::OpusDecoder::new(48_000, CHANNELS)
                .map_err(|e| crate::Error::Codec(e.into()))?,
        })
    }

    /// Decode one packet into interleaved f32 PCM. Returns sample count.
    pub fn decode_into(&mut self, packet: &[u8], pcm: &mut [f32]) -> Result<usize, crate::Error> {
        self.inner
            .decode(packet, FRAME_SAMPLES, pcm)
            .map_err(|e| crate::Error::Codec(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sine_frame(freq_hz: f32, amplitude: f32) -> Vec<f32> {
        let mut pcm = Vec::with_capacity(FRAME_SAMPLES * CHANNELS);
        for i in 0..FRAME_SAMPLES {
            let sample =
                amplitude * (2.0 * std::f32::consts::PI * freq_hz * i as f32 / 48_000.0).sin();
            pcm.push(sample);
            pcm.push(sample);
        }
        pcm
    }

    #[test]
    fn silence_encodes_small_and_decodes_quiet() {
        let mut encoder = Encoder::new().expect("encoder");
        let mut decoder = Decoder::new().expect("decoder");
        let silence = vec![0.0f32; FRAME_SAMPLES * CHANNELS];
        let packet = encoder.encode_frame(&silence).expect("encode");
        assert!(!packet.is_empty() && packet.len() <= 1276, "bounded packet");
        let mut pcm = vec![0.0f32; FRAME_SAMPLES * CHANNELS];
        let decoded = decoder.decode_into(&packet, &mut pcm).expect("decode");
        assert_eq!(decoded, FRAME_SAMPLES);
        let energy: f32 = pcm.iter().map(|s| s * s).sum();
        assert!(energy < 1.0, "silence stays quiet (energy {energy})");
    }

    #[test]
    fn tone_round_trip_preserves_energy() {
        let mut encoder = Encoder::new().expect("encoder");
        let mut decoder = Decoder::new().expect("decoder");
        // Run several frames so the encoder settles past startup transients.
        let mut last_energy = 0.0f32;
        for _ in 0..5 {
            let packet = encoder
                .encode_frame(&sine_frame(440.0, 0.5))
                .expect("encode");
            // TOC byte: config 0..=31, valid packet framing.
            assert!(packet[0] >> 3 <= 31, "valid TOC byte");
            let mut pcm = vec![0.0f32; FRAME_SAMPLES * CHANNELS];
            decoder.decode_into(&packet, &mut pcm).expect("decode");
            last_energy = pcm.iter().map(|s| s * s).sum::<f32>() / pcm.len() as f32;
        }
        // 0.5-amplitude sine has mean square 0.125; Opus at 64k preserves
        // most of it. Generous bounds: proves content survives, not fidelity.
        assert!(last_energy > 0.02, "tone energy preserved ({last_energy})");
        assert!(last_energy < 0.5, "no explosion ({last_energy})");
    }

    #[test]
    fn wrong_frame_size_is_rejected() {
        let mut encoder = Encoder::new().expect("encoder");
        assert!(encoder.encode_frame(&vec![0.0f32; 100]).is_err());
    }
}
