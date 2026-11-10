extern crate self as neqo_common;
#[macro_export]
macro_rules! qtrace {
    ($($t:tt)*) => {};
}
fn to_u64(n: usize) -> u64 {
    n as u64
}
mod rtt {
    pub const GRANULARITY: std::time::Duration = std::time::Duration::from_millis(1);
}
#[path = "firefox-pace.rs"]
mod pace;
use std::time::{Duration, Instant};
fn main() {
    let start = Instant::now();
    println!("[");
    let mut first = true;
    for (scenario, rtt_ns) in [
        ("burst-idle", 100_000_000u64),
        ("debt", 1_000_000),
        ("zero-rtt", 0),
    ] {
        let mut p = pace::Pacer::new(true, start, 2514, 1257);
        for i in 0..40u64 {
            let now_ns = if scenario == "burst-idle" {
                if i < 20 {
                    i * 5_000_000
                } else {
                    1_000_000_000 + (i - 20) * 100_000
                }
            } else {
                i * 1000
            };
            let cwnd = if scenario == "debt" {
                if i < 20 {
                    1000 * 1257
                } else {
                    2 * 1257
                }
            } else {
                10 * 1257
            };
            let now = start + Duration::from_nanos(now_ns);
            let rtt = Duration::from_nanos(rtt_ns);
            p.spend(now, rtt, cwnd, 1257);
            let next = p.next(rtt, cwnd);
            let next_ns = if next <= now {
                0
            } else {
                next.duration_since(start).as_nanos()
            };
            if !first {
                println!(",");
            }
            first = false;
            print!(
                "{{\"scenario\":\"{}\",\"now_ns\":{},\"rtt_ns\":{},\"cwnd\":{},\"next_ns\":{}}}",
                scenario, now_ns, rtt_ns, cwnd, next_ns
            );
        }
    }
    println!("\n]");
}
