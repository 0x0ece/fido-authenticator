//! Scale / correctness test for resident-credential bookkeeping.
//!
//! Validates that the O(1) `rk_count` cache (and the `count_credentials`
//! lazy-backfill) stays exactly correct as the number of resident credentials
//! grows large, and that enumeration returns every credential. This is the
//! software half of the "1000 credentials" goal: it exercises the fido-side
//! logic over the virtual filesystem without needing the physical Solo (whose
//! external-flash path is validated separately on hardware).
//!
//! N defaults to 100 to keep the normal test run fast; set `SCALE_N` to push it
//! (e.g. `SCALE_N=1000 cargo test --features dispatch --test scale -- --nocapture --ignored`).

#![cfg(feature = "dispatch")]

pub mod authenticator;
pub mod fs;
pub mod virt;
pub mod webauthn;

use authenticator::Authenticator;
use virt::Options;
use webauthn::{Rp, User};

fn scale_n() -> usize {
    std::env::var("SCALE_N")
        .ok()
        .and_then(|s| s.parse().ok())
        // Default kept modest: the virt CTAP stack runs full PIN-protocol +
        // P256 attestation crypto per MakeCredential, so even in release each
        // credential costs real time. N=30 is a fast, reliable correctness gate;
        // use SCALE_N / scale_large for bigger manual runs.
        .unwrap_or(30)
}

/// Create N resident credentials, each under a distinct RP, checking the cached
/// `existing` count after every creation; then enumerate and verify the total;
/// then delete a handful and verify the count decrements correctly.
fn run_scale(n: usize) {
    // Generous cap so creation is never rejected by the configured limit.
    let options = Options {
        max_resident_credential_count: Some((n as u32) + 16),
        ..Default::default()
    };
    virt::run_ctap2_with_options(options, |device| {
        let mut authenticator = Authenticator::new(device).set_pin(b"123456");

        // Fresh device: count starts at zero.
        assert_eq!(authenticator.credentials_metadata().existing, 0);

        // Create N RKs, verifying the cached counter after each.
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let rp = Rp::new(format!("scale{i:05}.example.com"));
            let user = User::new(format!("user{i:05}").as_bytes());
            let data = authenticator
                .make_credential(rp, user)
                .unwrap_or_else(|e| panic!("make_credential #{i} failed: {e:?}"));
            ids.push(data.id.clone());

            let existing = authenticator.credentials_metadata().existing;
            assert_eq!(
                existing,
                i + 1,
                "cached count wrong after creating {} creds",
                i + 1
            );
        }

        // Enumeration must return exactly N distinct RPs.
        let rps = authenticator.list_rps();
        assert_eq!(rps.len(), n, "list_rps returned wrong total");

        // Delete a spread of credentials and check the counter tracks each one.
        let to_delete: Vec<usize> = if n >= 5 {
            vec![0, n / 4, n / 2, (3 * n) / 4, n - 1]
        } else {
            (0..n).collect()
        };
        // Delete in descending index order so earlier indices stay valid.
        let mut sorted = to_delete.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let mut deleted = 0usize;
        for &idx in sorted.iter().rev() {
            authenticator.delete_credential(&ids[idx]);
            deleted += 1;
            let existing = authenticator.credentials_metadata().existing;
            assert_eq!(
                existing,
                n - deleted,
                "cached count wrong after {deleted} deletions"
            );
        }

        // Final enumeration count matches.
        let rps = authenticator.list_rps();
        assert_eq!(rps.len(), n - deleted, "list_rps wrong after deletions");
    });
}

/// Default-size run (N=100 unless SCALE_N overrides) — part of the normal suite.
#[test]
fn scale_default() {
    run_scale(scale_n());
}

/// Explicit large run, ignored by default (slow). Use:
///   SCALE_N=1000 cargo test --features dispatch --test scale -- --ignored --nocapture
#[test]
#[ignore]
fn scale_large() {
    let n = std::env::var("SCALE_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    run_scale(n);
}
