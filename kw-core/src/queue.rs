//! Bounded queue with explicit drop accounting.
//!
//! Slow viewers must not stall the guest: when full, pushing a new frame
//! discards the oldest *decoded* frame and counts it. Encoded reference
//! frames are never dropped arbitrarily — abandoning a GOP requires flushing
//! to a fresh IDR, which the media layer handles, not this queue.

use std::collections::VecDeque;

/// Fixed-capacity FIFO. `dropped` counts discarded oldest items.
#[derive(Debug)]
pub struct BoundedQueue<T> {
    inner: VecDeque<T>,
    capacity: usize,
    /// Frames discarded because the queue was full (telemetry counter).
    pub dropped: u64,
}

impl<T> BoundedQueue<T> {
    /// Capacity must be at least 1.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1, "queue capacity must be at least 1");
        Self {
            inner: VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Push, discarding the oldest item when full.
    pub fn push(&mut self, item: T) {
        if self.inner.len() == self.capacity {
            self.inner.pop_front();
            self.dropped += 1;
        }
        self.inner.push_back(item);
    }

    /// Pop from the front. Kept explicit (not Deref) so drop accounting stays visible.
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_oldest_and_counts() {
        let mut queue = BoundedQueue::new(2);
        queue.push(1);
        queue.push(2);
        assert_eq!(queue.dropped, 0);
        queue.push(3);
        assert_eq!(queue.dropped, 1);
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    #[should_panic(expected = "capacity must be at least 1")]
    fn rejects_zero_capacity() {
        let _ = BoundedQueue::<u8>::new(0);
    }
}
