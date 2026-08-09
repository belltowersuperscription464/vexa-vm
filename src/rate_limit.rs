use std::{collections::HashMap, sync::Mutex};

use crate::error::{AppError, AppResult};

const MAX_BUCKETS: usize = 10_000;

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    started_at: i64,
    count: u32,
    window_seconds: i64,
}

impl RateLimiter {
    pub fn check(
        &self,
        namespace: &str,
        key: &str,
        limit: u32,
        window_seconds: i64,
        now: i64,
    ) -> AppResult<()> {
        if limit == 0 || window_seconds <= 0 {
            return Err(AppError::Internal("rate limiter configuration is invalid".into()));
        }
        let mut buckets = self
            .buckets
            .lock()
            .map_err(|_| AppError::Internal("rate limiter lock was poisoned".into()))?;
        if buckets.len() >= MAX_BUCKETS {
            buckets.retain(|_, bucket| now.saturating_sub(bucket.started_at) < bucket.window_seconds);
            if buckets.len() >= MAX_BUCKETS {
                return Err(AppError::RateLimited);
            }
        }
        let bucket = buckets.entry(format!("{namespace}:{key}")).or_insert(Bucket {
            started_at: now,
            count: 0,
            window_seconds,
        });
        if now.saturating_sub(bucket.started_at) >= bucket.window_seconds {
            *bucket = Bucket {
                started_at: now,
                count: 0,
                window_seconds,
            };
        }
        if bucket.count >= limit {
            return Err(AppError::RateLimited);
        }
        bucket.count = bucket.count.saturating_add(1);
        Ok(())
    }

    pub fn reset(&self, namespace: &str, key: &str) -> AppResult<()> {
        self.buckets
            .lock()
            .map_err(|_| AppError::Internal("rate limiter lock was poisoned".into()))?
            .remove(&format!("{namespace}:{key}"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_each_fixed_window() {
        let limiter = RateLimiter::default();
        assert!(limiter.check("login", "address", 1, 60, 100).is_ok());
        assert!(matches!(
            limiter.check("login", "address", 1, 60, 101),
            Err(AppError::RateLimited)
        ));
        assert!(limiter.check("login", "address", 1, 60, 160).is_ok());
    }
}
