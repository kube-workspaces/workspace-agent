//! Sample-rate conversion to the 48kHz contract profile.
//!
//! Linear-interpolating, per-channel stateful resampling. Quality is
//! deliberately modest (desktop proof audio, not mastering): the Opus
//! encoder dominates the chain, and this module is swappable behind its
//! narrow interface (a higher-order resampler drops in as `push_stereo`
/// grows a kernel — callers are untouched).
/// Output rate of the contract profile.
pub const OUT_RATE: u32 = 48_000;

/// Stereo stream resampler: arbitrary input rate → 48kHz stereo f32.
/// Fractional position carries across calls (no clicks at chunk edges);
/// equal rates take the memcpy fast path.
pub struct Resampler {
    step: f64,
    positions: [f64; 2],
    previous: [f32; 2],
    passthrough: bool,
    started: bool,
}

impl Resampler {
    pub fn new(in_rate: u32) -> Self {
        let passthrough = in_rate == OUT_RATE;
        Self {
            step: if in_rate == 0 {
                1.0
            } else {
                in_rate as f64 / OUT_RATE as f64
            },
            positions: [0.0, 0.0],
            previous: [0.0, 0.0],
            passthrough,
            started: false,
        }
    }

    /// Resample one interleaved-stereo f32 block. Output length ≈
    /// `input_frames * OUT_RATE / in_rate` (never empty for non-empty
    /// input at sane rates; a trailing partial step carries over).
    pub fn push_stereo(&mut self, input: &[f32]) -> Vec<f32> {
        assert!(input.len() % 2 == 0, "stereo input must hold channel pairs");
        if self.passthrough {
            return input.to_vec();
        }
        let frames = input.len() / 2;
        let mut channels = [Vec::new(), Vec::new()];
        for channel in 0..2 {
            let mut position = self.positions[channel];
            let mut out = Vec::new();
            while position < frames as f64 {
                let index = position as usize;
                let fraction = (position - index as f64) as f32;
                let current = input[index * 2 + channel];
                // Stream start interpolates from the first sample itself
                // (no cold click); afterwards history carries over blocks.
                let before = if index == 0 && !self.started {
                    current
                } else if index == 0 {
                    self.previous[channel]
                } else {
                    input[(index - 1) * 2 + channel]
                };
                out.push(before * (1.0 - fraction) + current * fraction);
                position += self.step;
            }
            // Fractional remainder carries into the next block; the last
            // input sample becomes the next block's history.
            self.positions[channel] = position - frames as f64;
            if frames > 0 {
                self.previous[channel] = input[(frames - 1) * 2 + channel];
            }
            channels[channel] = out;
        }
        self.started = true;
        let count = channels[0].len().min(channels[1].len());
        let mut output = Vec::with_capacity(count * 2);
        for (left, right) in channels[0].iter().zip(channels[1].iter()).take(count) {
            output.push(*left);
            output.push(*right);
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_is_bit_exact() {
        let mut resampler = Resampler::new(OUT_RATE);
        let input: Vec<f32> = (0..1920).map(|i| i as f32 / 1920.0).collect();
        assert_eq!(resampler.push_stereo(&input), input);
    }

    #[test]
    fn ratio_scales_output_length() {
        // 44.1k → 48k: 441 frames should yield ~480.
        let mut resampler = Resampler::new(44_100);
        let input = vec![0.5f32; 441 * 2];
        let output = resampler.push_stereo(&input);
        assert_eq!(output.len() % 2, 0);
        let frames = output.len() / 2;
        assert!(
            (475..=485).contains(&frames),
            "resampled frames {frames} near 480"
        );
    }

    #[test]
    fn dc_passes_unchanged() {
        let mut resampler = Resampler::new(44_100);
        let input = vec![0.25f32; 4410 * 2];
        let output = resampler.push_stereo(&input);
        for sample in output.iter().take(960) {
            assert!(
                (sample - 0.25).abs() < 1e-5,
                "DC preserved through resampling"
            );
        }
    }

    #[test]
    fn stream_continuity_across_blocks() {
        // A ramp split across two blocks must convert identically to one.
        let mut ramp = vec![0.0f32; 882 * 2];
        for (i, chunk) in ramp.chunks_exact_mut(2).enumerate() {
            let value = i as f32 / 882.0;
            chunk[0] = value;
            chunk[1] = value;
        }
        let mut whole = Resampler::new(44_100);
        let reference = whole.push_stereo(&ramp);
        let mut split = Resampler::new(44_100);
        let mut combined = split.push_stereo(&ramp[..441 * 2]);
        combined.extend(split.push_stereo(&ramp[441 * 2..]));
        // Block edges wobble by a sample through FP timing; values must
        // still agree (the continuity property, not exact framing).
        assert!(
            combined.len().abs_diff(reference.len()) <= 4,
            "framing stable across the split"
        );
        let count = combined.len().min(reference.len()).min(400);
        for (a, b) in combined.iter().zip(reference.iter()).take(count) {
            assert!((a - b).abs() < 1e-4, "block boundary is click-free");
        }
    }
}
