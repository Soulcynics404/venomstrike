use governor::{Quota, RateLimiter as GovRateLimiter, clock::DefaultClock, state::{InMemoryState, NotKeyed}};
use std::num::NonZeroU32;
use std::sync::Arc;

pub type VenomRateLimiter = Arc<GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>>;

pub fn create_rate_limiter(requests_per_second: u32, burst: u32) -> VenomRateLimiter {
    let rps = NonZeroU32::new(requests_per_second).unwrap_or(NonZeroU32::new(10).unwrap());
    let burst_size = NonZeroU32::new(burst).unwrap_or(NonZeroU32::new(20).unwrap());

    Arc::new(GovRateLimiter::direct(
        Quota::per_second(rps).allow_burst(burst_size),
    ))
}