// Standalone reference runner, intentionally excluded from Go builds.
// Download Firefox's cubic.rs at the pinned URL in README.md to this directory
// as firefox-cubic.rs; rustc --edition=2024 -Awarnings reference.rs -o reference.
// It executes the original Rust controller, with stubs only for tracing and stats.
// Output rows can be grouped by scenario/mss/rtt_ms to reproduce the JSON fixture.
extern crate self as neqo_common;
#[macro_export]
macro_rules! qdebug {
    ($($t:tt)*) => {};
}
#[macro_export]
macro_rules! qtrace {
    ($($t:tt)*) => {};
}
mod stats {
    #[derive(Default)]
    pub struct CongestionControlStats {
        pub w_max: Option<f64>,
    }
}
mod cc {
    #[derive(PartialEq, Clone, Copy)]
    pub enum CongestionTrigger {
        Ecn,
        Loss,
    }
    pub mod classic_cc {
        use crate::{cc::CongestionTrigger, stats::CongestionControlStats};
        use std::time::{Duration, Instant};
        pub trait WindowAdjustment {
            fn bytes_for_cwnd_increase(
                &mut self,
                cwnd: usize,
                acked: usize,
                rtt: Duration,
                mss: usize,
                now: Instant,
            ) -> usize;
            fn reduce_cwnd(
                &mut self,
                cwnd: usize,
                acked: usize,
                mss: usize,
                trigger: CongestionTrigger,
                stats: &mut CongestionControlStats,
            ) -> (usize, usize);
            fn on_app_limited(&mut self);
            fn save_undo_state(&mut self);
            fn restore_undo_state(&mut self, stats: &mut CongestionControlStats);
        }
    }
}
#[path = "firefox-cubic.rs"]
mod cubic;
use cc::classic_cc::WindowAdjustment;
use std::time::{Duration, Instant};
fn main() {
    let start = Instant::now();
    let mut first = true;
    println!("[");
    for mss in [1200usize, 1257, 1357, 1460] {
        for scenario in [
            "concave",
            "convex",
            "reno-friendly",
            "ecn",
            "fast-convergence",
            "idle",
            "undo",
        ] {
            let mut c = cubic::Cubic::default();
            let mut stats = stats::CongestionControlStats::default();
            let mut cwnd = 100 * mss;
            let mut credit = 0;
            let rtt = if scenario == "reno-friendly" { 1 } else { 100 };
            (cwnd, credit) = c.reduce_cwnd(
                cwnd,
                credit,
                mss,
                if scenario == "ecn" {
                    cc::CongestionTrigger::Ecn
                } else {
                    cc::CongestionTrigger::Loss
                },
                &mut stats,
            );
            for i in 0..40 {
                let time_ms = if scenario == "convex" {
                    i * 1000
                } else {
                    i * 50
                };
                if scenario == "fast-convergence" && i == 10 {
                    (cwnd, credit) =
                        c.reduce_cwnd(cwnd, credit, mss, cc::CongestionTrigger::Loss, &mut stats);
                }
                if scenario == "idle" && i == 20 {
                    c.on_app_limited();
                }
                if scenario == "undo" && i == 10 {
                    c.save_undo_state();
                    (cwnd, credit) =
                        c.reduce_cwnd(cwnd, credit, mss, cc::CongestionTrigger::Loss, &mut stats);
                    c.restore_undo_state(&mut stats);
                    cwnd = 70 * mss;
                    credit = 0;
                }
                let acked = if i % 3 == 0 { 23 * mss } else { mss / 3 };
                let needed = c.bytes_for_cwnd_increase(
                    cwnd,
                    acked,
                    Duration::from_millis(rtt),
                    mss,
                    start + Duration::from_millis(time_ms),
                );
                let acknowledged = credit.min(needed) + acked;
                credit = acknowledged % needed;
                cwnd += (acknowledged / needed) * mss;
                if !first {
                    println!(",");
                }
                first = false;
                print!(
                    "{{\"scenario\":\"{scenario}\",\"mss\":{mss},\"step\":{i},\"time_ms\":{time_ms},\"rtt_ms\":{rtt},\"acked\":{acked},\"cwnd\":{cwnd},\"credit\":{credit}}}"
                );
            }
        }
    }
    println!("\n]");
}
