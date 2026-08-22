//! Tamper-evident event storage: a per-event SHA-256 hash chain.
//!
//! When enabled (`[database] chain_events = true`), every stored event row
//! carries:
//!
//! - `seq`     — a monotonically increasing sequence number (chain position)
//! - `prev_hash` — the `row_hash` of the previous chained row (`GENESIS`
//!   for the first row), binding each row to its predecessor
//! - `row_hash`  — `SHA-256(seq || prev_hash || canonical-row-fields)`,
//!   binding the hash to the row's full contents
//!
//! Any later modification or deletion of a stored row breaks the chain: the
//! recomputed hash of the tampered row no longer matches the stored
//! `row_hash`, and the stored hashes of all subsequent rows no longer match
//! their predecessors. [`verify_chain`] walks the rows in `seq` order and
//! reports the **first** broken link, so operators get an actionable pointer
//! instead of a bare boolean.
//!
//! This mirrors the audit-log chaining used by Patroclus. It is detection,
//! not prevention: a sufficiently privileged attacker can rewrite both the
//! rows *and* their hashes. For that reason the verifier also reports gaps in
//! `seq` (deletion is detectable even when hashes are re-stamped) and stores
//! nothing outside SQLite — export/external notarization of the latest
//! `row_hash` is left to deployment tooling.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hash of the virtual row before the first one.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Domain-separation prefix for event row hashes. Ensures hashes computed
/// here cannot be replayed as (or confused with) hashes from another log.
const ROW_HASH_DOMAIN: &[u8] = b"sentiel-event-chain-v1";

/// The fields of a stored event row that are covered by the row hash.
///
/// Everything the events table persists participates, so changing any column
/// invalidates the chain.
pub const HASHED_FIELDS: &[&str] = &[
    "id",
    "source",
    "session_id",
    "agent_id",
    "principal_id",
    "event_type",
    "severity",
    "data",
    "dlp_violations",
    "anomaly_flags",
    "timestamp",
];

/// Inputs to the row-hash computation for one event row.
#[derive(Debug, Clone)]
pub struct ChainInput<'a> {
    pub seq: u64,
    pub prev_hash: &'a str,
    /// Raw stored values, exactly as they appear in the `events` table.
    pub fields: [String; HASHED_FIELDS.len()],
}

impl ChainInput<'_> {
    /// Canonical byte serialization of the hashed material: length-prefixed
    /// fields so values containing separators cannot collide.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(self.prev_hash.as_bytes());
        for field in &self.fields {
            buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
            buf.extend_from_slice(field.as_bytes());
        }
        buf
    }

    /// Compute the chain entry for this row: `(prev_hash, row_hash)`.
    ///
    /// `prev_hash` echoes back the input so callers can persist both columns
    /// in one shot.
    pub fn chain_entry(&self) -> (String, String) {
        let mut hasher = Sha256::new();
        hasher.update(ROW_HASH_DOMAIN);
        hasher.update(self.canonical_bytes());
        let digest = hasher.finalize();
        (self.prev_hash.to_string(), hex_encode(&digest))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Outcome of verifying the event hash chain over a range of rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChainVerdict {
    /// Every present row matches its stored hash and predecessor link.
    Intact {
        verified_rows: u64,
        head_hash: String,
    },
    /// The first inconsistency found while walking forward in `seq` order.
    Broken(BrokenLink),
}

/// Description of the first broken link in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokenLink {
    /// Sequence number of the offending row (the first bad one).
    pub at_seq: u64,
    /// Why the link broke at `at_seq`.
    #[serde(rename = "reason")]
    pub kind: BreakReason,
}

/// How the chain is broken at [`BrokenLink::at_seq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakReason {
    /// Recomputing the row hash from the row's current contents does not
    /// match the stored `row_hash`: the row was modified after insertion.
    RowModified,
    /// The stored `prev_hash` does not equal the previous row's `row_hash`:
    /// a row was deleted, inserted out-of-band, or links were re-stamped.
    LinkMismatch,
}

/// Full result of a database chain verification pass.
///
/// `total_events` / `unchained_events` account for every row in the table:
/// rows inserted while chaining was disabled carry no chain columns and are
/// reported here rather than silently ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerification {
    /// All event rows currently stored.
    pub total_events: u64,
    /// Rows without chain metadata (inserted before chaining was enabled).
    pub unchained_events: u64,
    /// Outcome of the forward walk over chained rows.
    pub verdict: ChainVerdict,
}

impl ChainVerification {
    /// Whether every chained row verified and nothing is left uncovered.
    pub fn is_intact(&self) -> bool {
        self.unchained_events == 0 && matches!(self.verdict, ChainVerdict::Intact { .. })
    }
}

impl std::fmt::Display for ChainVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainVerdict::Intact {
                verified_rows,
                head_hash,
            } => write!(
                f,
                "intact: {verified_rows} row(s) verified, head {head_hash}"
            ),
            ChainVerdict::Broken(link) => match link.kind {
                BreakReason::RowModified => write!(
                    f,
                    "BROKEN at seq {}: stored row_hash does not match row contents (row modified after insert)",
                    link.at_seq
                ),
                BreakReason::LinkMismatch => write!(
                    f,
                    "BROKEN at seq {}: stored prev_hash does not match the preceding row's row_hash (rows deleted or links re-stamped)",
                    link.at_seq
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fields(id: u64) -> [String; HASHED_FIELDS.len()] {
        [
            format!("018f0000-0000-7000-8000-{id:012x}"),
            "miser".to_string(),
            "s-1".to_string(),
            String::new(),
            String::new(),
            "llm_cost".to_string(),
            "info".to_string(),
            r#"{"cost":0.01}"#.to_string(),
            String::new(),
            String::new(),
            "2026-01-01T00:00:00+00:00".to_string(),
        ]
    }

    #[test]
    fn genesis_is_a_64_char_zero_hex_string() {
        assert_eq!(GENESIS.len(), 64);
        assert!(GENESIS.chars().all(|c| c == '0'));
    }

    #[test]
    fn identical_rows_chain_identically_and_differ_by_seq() {
        let a = ChainInput {
            seq: 1,
            prev_hash: GENESIS,
            fields: sample_fields(1),
        }
        .chain_entry();
        let b = ChainInput {
            seq: 1,
            prev_hash: GENESIS,
            fields: sample_fields(1),
        }
        .chain_entry();
        assert_eq!(a, b);

        let c = ChainInput {
            seq: 2,
            prev_hash: GENESIS,
            fields: sample_fields(1),
        }
        .chain_entry();
        assert_ne!(a.1, c.1, "seq must participate in the hash");
    }

    #[test]
    fn any_field_change_changes_the_row_hash() {
        for (idx, name) in HASHED_FIELDS.iter().enumerate() {
            let baseline = ChainInput {
                seq: 1,
                prev_hash: GENESIS,
                fields: sample_fields(1),
            };
            let mut tampered = baseline.clone();
            tampered.fields[idx] = format!("{}TAMPERED", tampered.fields[idx]);

            assert_ne!(
                baseline.chain_entry().1,
                tampered.chain_entry().1,
                "field {idx} ({name}) must be hash-covered"
            );
        }
    }

    #[test]
    fn prev_hash_participates_so_links_bind() {
        let h1 = ChainInput {
            seq: 2,
            prev_hash: &"a".repeat(64),
            fields: sample_fields(1),
        }
        .chain_entry()
        .1;
        let h2 = ChainInput {
            seq: 2,
            prev_hash: &"b".repeat(64),
            fields: sample_fields(1),
        }
        .chain_entry()
        .1;
        assert_ne!(h1, h2);
    }

    #[test]
    fn chain_entry_echoes_prev_hash_for_persistence() {
        let prev = "abc".repeat(21); // 63 chars + 'x'
        let input = ChainInput {
            seq: 7,
            prev_hash: &prev,
            fields: sample_fields(1),
        };
        let (echoed_prev, hash) = input.chain_entry();
        assert_eq!(echoed_prev, prev);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verdicts_serialize_to_json_with_status_tag() {
        let intact = ChainVerdict::Intact {
            verified_rows: 3,
            head_hash: "ff".repeat(32),
        };
        let json = serde_json::to_value(&intact).unwrap();
        assert_eq!(json["status"], "intact");
        assert_eq!(json["verified_rows"], 3);

        let broken = ChainVerdict::Broken(BrokenLink {
            at_seq: 5,
            kind: BreakReason::RowModified,
        });
        let json = serde_json::to_value(&broken).unwrap();
        assert_eq!(json["status"], "broken");
        assert_eq!(json["at_seq"], 5);
        assert_eq!(json["reason"], "row_modified");

        let broken_link = BrokenLink {
            at_seq: 9,
            kind: BreakReason::LinkMismatch,
        };
        let json = serde_json::to_value(&broken_link).unwrap();
        assert_eq!(json["reason"], "link_mismatch");
    }

    #[test]
    fn display_reports_first_broken_seq() {
        let broken = ChainVerdict::Broken(BrokenLink {
            at_seq: 12,
            kind: BreakReason::LinkMismatch,
        });
        let text = broken.to_string();
        assert!(text.contains("seq 12"), "{text}");
        assert!(text.contains("BROKEN"), "{text}");

        let intact = ChainVerdict::Intact {
            verified_rows: 4,
            head_hash: "ee".repeat(32),
        };
        assert!(intact.to_string().contains("intact"));
    }
}
