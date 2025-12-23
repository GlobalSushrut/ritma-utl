use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TimeTick {
    pub raw_time: u64,
    pub mock_time: f64,
}

impl TimeTick {
    pub fn now() -> Self {
        let raw = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mock = Self::nonlinear_time(raw);
        Self {
            raw_time: raw,
            mock_time: mock,
        }
    }

    fn nonlinear_time(raw_secs: u64) -> f64 {
        let t = raw_secs as f64;
        let k = 1e-9_f64;
        let x = k * t;
        let tan = x.tan();
        let tan_clamped = tan.clamp(-1e6, 1e6);
        t * tan_clamped.abs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_produces_non_zero_time() {
        let tick = TimeTick::now();
        assert!(tick.raw_time > 0);
    }
}
