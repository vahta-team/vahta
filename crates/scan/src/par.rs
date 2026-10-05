//! A small ordered worker pool on `std::thread::scope`; no external crates.
//!
//! [`ordered_map`] runs `work` over `items` on several threads and hands each
//! result to `consume` on the *calling* thread, strictly in item order. That
//! is what lets the scans run in parallel and still be byte-identical to the
//! sequential code: all order-dependent logic (deduplication, progress
//! replay, error propagation) lives in `consume`, which sees exactly the
//! sequence a single thread would have produced.
//!
//! Workers claim items in index order, but never run further ahead of the
//! consumer than `window` items, and never hold more than `budget` bytes of
//! declared item cost in flight (one item may always run, so a single huge
//! file cannot deadlock). Stopping early (`consume` returns `false`) cancels
//! work that has not started.

use std::sync::{Condvar, Mutex};

/// Upper bound on worker threads.
pub const MAX_THREADS: usize = 16;

/// Threads to use by default: the available parallelism, capped at
/// [`MAX_THREADS`], at least 1.
pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, MAX_THREADS)
}

fn lock<R>(s: &(Mutex<State<R>>, Condvar)) -> std::sync::MutexGuard<'_, State<R>> {
    s.0.lock().unwrap_or_else(|e| e.into_inner())
}

struct State<R> {
    /// Next index to hand to a worker.
    next_claim: usize,
    /// Next index the consumer will take.
    consumed: usize,
    /// Declared cost of items claimed but not yet finished.
    inflight_cost: u64,
    slots: Vec<Option<R>>,
    stop: bool,
    panicked: bool,
}

/// Marks the pool poisoned if a worker unwinds, so the consumer cannot wait
/// forever for a result that will never arrive. (Release builds abort on
/// panic; this covers unwinding test builds.)
struct PanicGuard<'a, R>(&'a (Mutex<State<R>>, Condvar));

impl<R> Drop for PanicGuard<'_, R> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let mut st = self.0.0.lock().unwrap_or_else(|e| e.into_inner());
            st.panicked = true;
            st.stop = true;
            self.0.1.notify_all();
        }
    }
}

/// Run `work(index, item)` on up to `threads` threads; call
/// `consume(index, result)` on the calling thread in index order until it
/// returns `false` or the items run out.
///
/// With `threads <= 1` or fewer than two items this is a plain loop on the
/// calling thread: no thread is spawned.
pub fn ordered_map<T, R, W, C>(
    items: &[T],
    threads: usize,
    window: usize,
    budget: u64,
    cost: impl Fn(&T) -> u64,
    work: W,
    mut consume: C,
) where
    T: Sync,
    R: Send,
    W: Fn(usize, &T) -> R + Sync,
    C: FnMut(usize, R) -> bool,
{
    let n = items.len();
    let threads = threads.min(n);
    if threads <= 1 {
        for (i, item) in items.iter().enumerate() {
            if !consume(i, work(i, item)) {
                return;
            }
        }
        return;
    }
    let window = window.max(threads);
    let costs: Vec<u64> = items.iter().map(&cost).collect();
    let shared: (Mutex<State<R>>, Condvar) = (
        Mutex::new(State {
            next_claim: 0,
            consumed: 0,
            inflight_cost: 0,
            slots: (0..n).map(|_| None).collect(),
            stop: false,
            panicked: false,
        }),
        Condvar::new(),
    );

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let _guard = PanicGuard(&shared);
                loop {
                    let i = {
                        let mut st = lock(&shared);
                        loop {
                            if st.stop || st.next_claim >= n {
                                return;
                            }
                            let i = st.next_claim;
                            let fits_window = i < st.consumed + window;
                            let fits_budget =
                                st.inflight_cost == 0 || st.inflight_cost + costs[i] <= budget;
                            if fits_window && fits_budget {
                                st.next_claim += 1;
                                st.inflight_cost += costs[i];
                                break i;
                            }
                            st = shared.1.wait(st).unwrap_or_else(|e| e.into_inner());
                        }
                    };
                    let result = work(i, &items[i]);
                    let mut st = lock(&shared);
                    st.inflight_cost -= costs[i];
                    st.slots[i] = Some(result);
                    shared.1.notify_all();
                }
            });
        }

        struct StopOnDrop<'a, R>(&'a (Mutex<State<R>>, Condvar));
        impl<R> Drop for StopOnDrop<'_, R> {
            fn drop(&mut self) {
                let mut st = self.0.0.lock().unwrap_or_else(|e| e.into_inner());
                st.stop = true;
                self.0.1.notify_all();
            }
        }
        let _stop = StopOnDrop(&shared);
        for i in 0..n {
            let result = {
                let mut st = lock(&shared);
                loop {
                    if let Some(r) = st.slots[i].take() {
                        st.consumed = i + 1;
                        shared.1.notify_all();
                        break Some(r);
                    }
                    if st.panicked {
                        break None;
                    }
                    st = shared.1.wait(st).unwrap_or_else(|e| e.into_inner());
                }
            };
            let keep_going = match result {
                Some(r) => consume(i, r),
                None => false,
            };
            if !keep_going {
                let mut st = lock(&shared);
                st.stop = true;
                shared.1.notify_all();
                break;
            }
        }
    });
}
