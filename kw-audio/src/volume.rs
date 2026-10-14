//! Guest master-volume following for the loopback tap.
//!
//! Per-application session volumes are applied by the Windows audio engine
//! in software, so they are always present in a loopback capture. The
//! endpoint *master* volume and mute, however, may be delegated to the
//! audio hardware: on such devices (including the virtual HDA in some VM
//! configurations) the engine's software loopback copy taps the mix
//! *upstream* of the hardware volume node, and the guest master
//! slider/mute has no effect on captured audio. This is hardware/driver
//! dependent — the same build follows master volume on endpoints whose
//! volume is engine-applied.
//!
//! [`apply_master_volume`] closes the gap in software: the tap polls the
//! endpoint volume and the pump scales captured samples by it (mute forces
//! silence) before resampling/encoding, so remote listeners hear what the
//! guest mixer promises on every endpoint. Unity gain/mute-off is a no-op.

/// Scale normalized f32 samples by the endpoint master volume.
///
/// `scalar` is the `IAudioEndpointVolume` 0..1 level (clamped defensively);
/// `muted` forces digital silence. The stream keeps flowing — silence
/// encodes to tiny Opus packets and the session clock never stalls — so
/// mute reads as quiet, not as a dropout.
pub fn apply_master_volume(samples: &mut [f32], scalar: f32, muted: bool) {
    let gain = if muted {
        0.0
    } else if !scalar.is_finite() {
        1.0
    } else {
        scalar.clamp(0.0, 1.0)
    };
    if (gain - 1.0).abs() <= f32::EPSILON {
        return;
    }
    for sample in samples.iter_mut() {
        *sample *= gain;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unity_gain_leaves_samples_untouched() {
        let mut samples = vec![0.5, -0.25, 0.0, 1.0];
        apply_master_volume(&mut samples, 1.0, false);
        assert_eq!(samples, vec![0.5, -0.25, 0.0, 1.0]);
    }

    #[test]
    fn half_scalar_halves_amplitude() {
        let mut samples = vec![0.5, -0.5, 1.0, -1.0];
        apply_master_volume(&mut samples, 0.5, false);
        assert_eq!(samples, vec![0.25, -0.25, 0.5, -0.5]);
    }

    #[test]
    fn mute_silences_regardless_of_scalar() {
        let mut samples = vec![0.5, -0.5, 0.9];
        apply_master_volume(&mut samples, 1.0, true);
        assert_eq!(samples, vec![0.0, 0.0, 0.0]);
    }

    #[test]
    fn zero_scalar_silences_without_mute_flag() {
        let mut samples = vec![0.5, -0.5];
        apply_master_volume(&mut samples, 0.0, false);
        assert_eq!(samples, vec![0.0, 0.0]);
    }

    #[test]
    fn out_of_range_and_nonfinite_scalars_cannot_amplify_or_nan() {
        let mut samples = vec![0.5, 0.5, 0.5, 0.5];
        apply_master_volume(&mut samples, 4.0, false);
        assert_eq!(samples, vec![0.5, 0.5, 0.5, 0.5]);
        apply_master_volume(&mut samples, f32::NAN, false);
        assert_eq!(samples, vec![0.5, 0.5, 0.5, 0.5]);
        for sample in samples.iter() {
            assert!(sample.is_finite());
        }
    }
}
