//! Shared fixtures for the ledger's integration tests.
#![allow(dead_code)]

use hawkeye_core::bytes::Hash32;
use hawkeye_core::lock::lock_id;
use hawkeye_core::matcher::{Classification, Unmatched};
use hawkeye_core::template::{TAG_WYEC, VaultParams};
use hawkeye_core::{Deployment, EthAddress, OutPoint};
use hawkeye_store::{
    BurnKey, LockState, NewBurn, NewIntent, NewLock, NewVault, Store, StoreError, Tx,
};

pub const DEP: Deployment = Deployment {
    chain_id: 31337,
    bridge: EthAddress([0xb0; 20]),
};

pub const DEST: EthAddress = EthAddress([0xd5; 20]);
pub const SET: Hash32 = [0x5e; 32];
pub const LEADER: [u8; 33] = [0x02; 33];

pub fn fixed_clock() -> i64 {
    1_790_000_000
}

pub fn store() -> Store {
    let mut s = Store::open_in_memory().unwrap();
    s.set_clock(fixed_clock);
    s
}

/// A distinct 32-byte value per `n`.
pub fn h(tag: u8, n: u32) -> Hash32 {
    let mut b = [tag; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    b
}

pub fn op(tag: u8, n: u32) -> OutPoint {
    OutPoint::new(h(tag, n), n % 7)
}

pub fn new_lock(n: u32, height: u32) -> NewLock {
    NewLock {
        outpoint: op(0x10, n),
        value_zat: 1_000_000 + u64::from(n),
        owner_height: 900_000,
        destination: Some(DEST),
        block_hash: h(0xbb, height),
        block_height: height,
    }
}

pub fn lock_id_of(n: u32) -> Hash32 {
    lock_id(&op(0x10, n))
}

/// A stored lock taken to `POLICY_OK`.
pub fn policy_ok_lock(t: &Tx<'_>, n: u32, height: u32) -> Hash32 {
    let rec = t.insert_lock(&new_lock(n, height)).unwrap();
    t.transition_lock(&rec.lock_id, LockState::Confirmed, Some(height + 40), None)
        .unwrap();
    t.transition_lock(&rec.lock_id, LockState::PolicyOk, Some(height + 40), None)
        .unwrap();
    rec.lock_id
}

pub fn fake_sig(digest: &Hash32) -> Result<[u8; 65], StoreError> {
    let mut s = [0u8; 65];
    s[..32].copy_from_slice(digest);
    s[64] = 27;
    Ok(s)
}

pub fn burn_key(nonce: u64) -> BurnKey {
    BurnKey::new(DEP, nonce)
}

pub fn new_burn(nonce: u64, block: u64, finalized: bool) -> NewBurn {
    NewBurn {
        key: burn_key(nonce),
        tx_hash: h(0xe0, nonce as u32),
        block_number: block,
        block_hash: h(0xeb, block as u32),
        from: EthAddress([0xf1; 20]),
        amount: 500_000 + nonce,
        recipient: [0x01; 32],
        finalized,
    }
}

pub fn new_intent(n: u32, first_seen: u32, confirmed: Option<u32>) -> NewIntent {
    NewIntent {
        outpoint: op(0x20, n),
        value_zat: 500_000,
        recipient_hash: h(0x30, n),
        vault_hash: h(0x31, n),
        origin_vault: Some(op(0x40, n)),
        signer_key: Some(LEADER),
        memo: Some(vec![0x48, 0x4b, 0x42, 0x31]),
        first_seen_height: first_seen,
        confirmed_height: confirmed,
    }
}

pub fn new_vault(n: u32, created: u32) -> NewVault {
    NewVault {
        outpoint: op(0x40, n),
        value_zat: 2_000_000,
        owner_height: 900_000 + n,
        created_height: created,
    }
}

pub fn roll() -> Classification {
    Classification::MatchedRoll {
        new_vault: VaultParams {
            tag: TAG_WYEC,
            set_id: SET,
            cancel_set_id: SET,
            delay: 6,
            owner_height: 2_000_000,
            app_height: 0,
            owner_key: [0x03; 33],
        },
    }
}

pub fn unmatched() -> Classification {
    Classification::Unmatched(Unmatched::NoMemo)
}
