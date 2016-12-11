use std::time::Duration;

pub fn duration_to_ms(duration: Duration) -> f64 {
    let secs = duration.as_secs() as f64;
    let ns = duration.subsec_nanos() as f64;
    (secs * 1000.0) + (ns / 1_000_000.0)
}
