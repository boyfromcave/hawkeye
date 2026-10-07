//! The leader schedule (plan §5.2, HK-9). Attestors are ordered by member key
//! ([`crate::keys::sort_members`]); for burn nonce `n` the leader is `live[n mod |live|]`, and
//! after every `TAKEOVER` blocks without an intent the next attestor in order takes over. Mints
//! use the same rule over `lockId mod |live|` (the lockId read as a big-endian integer).
//! Leadership only decides who spends fees; every attestor verifies everything.

use crate::bytes::Hash32;

/// The index into `live_members_sorted` of the leader for slot `nonce`, `blocks` after the
/// assignment, with a takeover every `takeover` blocks (`0` = never). `None` if nobody is live.
pub fn leader_index(
    nonce: u64,
    live: usize,
    blocks_since_assignment: u32,
    takeover: u32,
) -> Option<usize> {
    if live == 0 {
        return None;
    }
    let live = live as u64;
    let shifts = u64::from(blocks_since_assignment)
        .checked_div(u64::from(takeover))
        .unwrap_or(0);
    Some(((nonce % live + shifts % live) % live) as usize)
}

/// The leader for burn `nonce` (see [`leader_index`]).
pub fn leader_for<T>(
    nonce: u64,
    live_members_sorted: &[T],
    blocks_since_assignment: u32,
    takeover: u32,
) -> Option<&T> {
    leader_index(
        nonce,
        live_members_sorted.len(),
        blocks_since_assignment,
        takeover,
    )
    .map(|i| &live_members_sorted[i])
}

/// `lockId mod n` with the 32 bytes read big-endian.
pub fn lock_id_mod(lock_id: &Hash32, n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let n = u128::from(n);
    lock_id
        .iter()
        .fold(0u128, |acc, b| (acc * 256 + u128::from(*b)) % n) as u64
}

/// The leader for the mint of `lock_id`.
pub fn mint_leader_for<'a, T>(
    lock_id: &Hash32,
    live_members_sorted: &'a [T],
    blocks_since_assignment: u32,
    takeover: u32,
) -> Option<&'a T> {
    let n = live_members_sorted.len() as u64;
    leader_for(
        lock_id_mod(lock_id, n),
        live_members_sorted,
        blocks_since_assignment,
        takeover,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_and_takeover() {
        let live = ["a", "b", "c"];
        assert_eq!(leader_for(0, &live, 0, 5), Some(&"a"));
        assert_eq!(leader_for(4, &live, 0, 5), Some(&"b"));
        assert_eq!(leader_for(4, &live, 4, 5), Some(&"b"));
        assert_eq!(leader_for(4, &live, 5, 5), Some(&"c"));
        assert_eq!(leader_for(4, &live, 10, 5), Some(&"a"));
        assert_eq!(leader_for(4, &live, 15, 5), Some(&"b"));
        // no overflow at the extremes: 2^64 - 1 and 2^32 - 1 are both ≡ 0 (mod 3)
        assert_eq!(leader_for(u64::MAX, &live, u32::MAX, 1), Some(&"a"));
        assert_eq!(leader_for(4, &live, 1000, 0), Some(&"b"));
        assert_eq!(leader_for::<&str>(4, &[], 0, 5), None);
    }

    #[test]
    fn lock_id_modulus() {
        let mut id = [0u8; 32];
        id[31] = 7;
        assert_eq!(lock_id_mod(&id, 3), 1);
        id[30] = 1; // 263
        assert_eq!(lock_id_mod(&id, 10), 3);
        assert_eq!(lock_id_mod(&[0xff; 32], 1), 0);
        // 2^256 - 1 ≡ 0 mod 3 and mod 5 (2^256 ≡ 1 for both)
        assert_eq!(lock_id_mod(&[0xff; 32], 3), 0);
        assert_eq!(lock_id_mod(&[0xff; 32], 5), 0);
        assert_eq!(lock_id_mod(&id, 0), 0);
        let live = [1, 2, 3];
        assert_eq!(mint_leader_for(&[0xff; 32], &live, 0, 5), Some(&1));
    }
}
