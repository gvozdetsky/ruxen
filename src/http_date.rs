// Per-thread cached `Date` header value, ruxen's `ngx_cached_http_time`.
//
// Every response carries `Date`, so the value has to be cheap: the clock is
// read with `CLOCK_REALTIME_COARSE` (a vDSO read of the kernel's last tick,
// no TSC access) and the string is reformatted only when the second changes.
// The coarse clock lags real time by at most one tick, the same order as
// nginx, which refreshes its cached time once per event-loop iteration.

use std::cell::Cell;

/// Length of an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`). Fixed, which
/// is what lets a finished response have its `Date` value overwritten in
/// place.
pub(crate) const LEN: usize = 29;

thread_local! {
    static CACHED: Cell<(i64, [u8; LEN])> = const { Cell::new((i64::MIN, [0; LEN])) };
}

/// The current time as an IMF-fixdate.
pub(crate) fn now() -> [u8; LEN] {
    let secs = coarse_unix_secs();
    CACHED.with(|cached| {
        let (at, value) = cached.get();
        if at == secs {
            return value;
        }
        let value = crate::file::format_http_date(secs.max(0) as u64);
        cached.set((secs, value));
        value
    })
}

fn coarse_unix_secs() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer; CLOCK_REALTIME_COARSE exists on
    // every Linux ruxen supports, and the call cannot fail with valid args.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut ts) };
    ts.tv_sec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_matches_system_clock() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let got = now();
        // The coarse clock may trail by a tick, so accept the previous
        // second too.
        let ok = [before.saturating_sub(1), before, before + 1].map(crate::file::format_http_date);
        assert!(ok.contains(&got), "{}", String::from_utf8_lossy(&got));
        assert!(got.ends_with(b" GMT"));
    }
}
