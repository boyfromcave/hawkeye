//! Unit tests in near-sdk's mocked blockchain. They follow the Ethereum suite
//! (wyec repo: `test/WyecBridge.t.sol`, `test/OptimisticMint.t.sol`, `test/RateLimit.t.sol`)
//! wherever the behaviour carries over. Signatures come from k256 with fixed secrets; digests are
//! recomputed independently with `sha2` over the hand-built preimage.

use super::*;
use k256::ecdsa::SigningKey;
use near_sdk::test_utils::{VMContextBuilder, get_logs};
use near_sdk::testing_env;
use sha2::{Digest, Sha256};

const NETWORK: &str = "sandbox";
const WINDOW: u64 = 60;
const T0: u64 = 1_700_000_000;
const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

fn contract_id() -> AccountId {
    "wyec.test.near".parse().unwrap()
}
fn alice() -> AccountId {
    "alice.near".parse().unwrap()
}
fn bob() -> AccountId {
    "bob.near".parse().unwrap()
}
fn relayer() -> AccountId {
    "relayer.near".parse().unwrap()
}

pub(crate) struct Guardian {
    pub sk: SigningKey,
    pub pk: GuardianKey,
}

/// Guardian `i`: secret key = SHA256("wyec-near test guardian " ‖ i).
pub(crate) fn guardian(i: u8) -> Guardian {
    let secret: [u8; 32] = Sha256::new()
        .chain_update(b"wyec-near test guardian ")
        .chain_update([i])
        .finalize()
        .into();
    let sk = SigningKey::from_bytes(&secret.into()).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let pk: GuardianKey = point.as_bytes()[1..].try_into().unwrap();
    Guardian { sk, pk }
}

/// 65-byte `r ‖ s ‖ v`, low-S, v ∈ {0,1}.
pub(crate) fn sign_raw(g: &Guardian, digest: &[u8; 32]) -> [u8; 65] {
    let (sig, recid) = g.sk.sign_prehash_recoverable(digest).unwrap();
    assert!(sig.normalize_s().is_none(), "k256 signs low-S");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = recid.to_byte();
    out
}

fn digest_for(network: &str, contract: &str, msg: &BridgeMessage) -> [u8; 32] {
    Sha256::digest(digest_preimage(network, contract, msg)).into()
}

fn lock(n: u8) -> String {
    hex::encode([n; 32])
}

fn recipient() -> String {
    let mut r = [0u8; 32];
    r[0] = 1;
    r[12..].copy_from_slice(&[0xab; 20]);
    hex::encode(r)
}

/// Parsed `EVENT_JSON` logs of the last call.
fn events() -> Vec<serde_json::Value> {
    get_logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str(j).unwrap())
        .collect()
}

fn bridge_events(name: &str) -> Vec<serde_json::Value> {
    events()
        .into_iter()
        .filter(|e| e["standard"] == EVENT_STANDARD && e["event"] == name)
        .map(|e| {
            assert_eq!(e["version"], EVENT_VERSION);
            assert_eq!(e["data"].as_array().unwrap().len(), 1);
            e["data"][0].clone()
        })
        .collect()
}

struct H {
    c: Contract,
    gs: Vec<Guardian>,
    now: u64,
}

impl H {
    /// `n` guardians, `threshold`, a 60 s window, no rate limit.
    fn new(n: u8, threshold: u8) -> Self {
        Self::with(n, threshold, WINDOW, 0, 0)
    }

    fn with(n: u8, threshold: u8, window: u64, cap: u128, cap_window: u64) -> Self {
        let gs: Vec<Guardian> = (0..n).map(guardian).collect();
        set_ctx(relayer(), NearToken::from_yoctonear(0), T0);
        let keys = gs.iter().map(|g| hex::encode(g.pk)).collect();
        let c = Contract::new(
            NETWORK.into(),
            keys,
            threshold,
            window,
            U128(cap),
            cap_window,
        );
        Self { c, gs, now: T0 }
    }

    /// Next call from `who` with `deposit`, at the current time.
    fn caller(&self, who: AccountId, deposit: NearToken) {
        set_ctx(who, deposit, self.now);
    }

    fn relay(&self) {
        self.caller(relayer(), NearToken::from_yoctonear(0));
    }

    fn warp(&mut self, secs: u64) {
        self.now += secs;
        self.relay();
    }

    fn digest(&self, msg: &BridgeMessage) -> [u8; 32] {
        let d = digest_for(NETWORK, contract_id().as_str(), msg);
        assert_eq!(
            d,
            self.c.digest(msg),
            "contract digest = independent digest"
        );
        d
    }

    fn sig(&self, i: usize, msg: &BridgeMessage) -> String {
        hex::encode(sign_raw(&self.gs[i], &self.digest(msg)))
    }

    /// Signatures of guardians `idx`, ordered by ascending public key.
    fn sigs(&self, idx: &[usize], msg: &BridgeMessage) -> Vec<String> {
        let mut v: Vec<usize> = idx.to_vec();
        v.sort_by_key(|&i| self.gs[i].pk);
        v.iter().map(|&i| self.sig(i, msg)).collect()
    }

    /// Guardian indices sorted by public key.
    fn by_key(&self) -> Vec<usize> {
        let mut v: Vec<usize> = (0..self.gs.len()).collect();
        v.sort_by_key(|&i| self.gs[i].pk);
        v
    }

    fn mint_msg(&self, l: u8, amount: u128, to: &AccountId) -> BridgeMessage {
        BridgeMessage::Mint {
            lock_id: [l; 32],
            amount,
            receiver_id: to.to_string(),
        }
    }

    fn mint(&mut self, l: u8, amount: u128, to: &AccountId, idx: &[usize]) {
        let sigs = self.sigs(idx, &self.mint_msg(l, amount, to));
        self.relay();
        self.c.mint(lock(l), U128(amount), to.clone(), sigs);
    }

    fn propose(&mut self, l: u8, amount: u128, to: &AccountId, g: usize) -> u64 {
        let sig = self.sig(g, &self.mint_msg(l, amount, to));
        self.relay();
        self.c.propose_mint(lock(l), U128(amount), to.clone(), sig)
    }

    fn challenge(&mut self, l: u8, id: u64, g: usize) {
        let sig = self.sig(
            g,
            &BridgeMessage::Challenge {
                lock_id: [l; 32],
                proposal_id: id,
            },
        );
        self.relay();
        self.c.challenge_mint(lock(l), id, sig);
    }

    fn execute(&mut self, l: u8) {
        self.relay();
        self.c.execute_mint(lock(l));
    }

    fn set_guardians(&mut self, keys: &[GuardianKey], threshold: u8, idx: &[usize]) {
        let msg = BridgeMessage::SetGuardians {
            guardians: keys.to_vec(),
            threshold,
            admin_nonce: self.c.get_admin_nonce(),
        };
        let sigs = self.sigs(idx, &msg);
        self.relay();
        self.c
            .set_guardians(keys.iter().map(hex::encode).collect(), threshold, sigs);
    }

    fn set_paused(&mut self, paused: bool, idx: &[usize]) {
        let msg = BridgeMessage::SetPaused {
            paused,
            admin_nonce: self.c.get_admin_nonce(),
        };
        let sigs = self.sigs(idx, &msg);
        self.relay();
        self.c.set_paused(paused, sigs);
    }

    fn set_limit(&mut self, cap: u128, window: u64, idx: &[usize]) {
        let msg = BridgeMessage::SetMintLimit {
            mint_cap: cap,
            cap_window_sec: window,
            admin_nonce: self.c.get_admin_nonce(),
        };
        let sigs = self.sigs(idx, &msg);
        self.relay();
        self.c.set_mint_limit(U128(cap), window, sigs);
    }

    fn burn(&mut self, who: &AccountId, amount: u128) -> u64 {
        let dep = self.c.burn_storage_deposit(who.clone());
        self.caller(who.clone(), dep);
        self.c.burn(U128(amount), recipient())
    }

    fn balance(&self, who: &AccountId) -> u128 {
        self.c.ft_balance_of(who.clone()).0
    }

    fn status(&self, l: u8) -> ProposalStatus {
        self.c.proposal_status(lock(l))
    }
}

fn set_ctx(who: AccountId, deposit: NearToken, now_sec: u64) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(contract_id())
            .predecessor_account_id(who.clone())
            .signer_account_id(who)
            .attached_deposit(deposit)
            .block_timestamp(now_sec * NS_PER_SEC)
            .block_height(now_sec / 2)
            .build()
    );
}

// ------------------------------------------------------------------------- deployment

#[test]
fn metadata_is_wrapped_ycash() {
    let h = H::new(3, 2);
    let m = h.c.ft_metadata();
    assert_eq!(
        (m.name.as_str(), m.symbol.as_str(), m.decimals),
        ("Wrapped Ycash", "wYEC", 8)
    );
    assert_eq!(m.spec, FT_METADATA_SPEC);
    m.assert_valid();
    assert_eq!(h.c.ft_total_supply().0, 0);
}

#[test]
fn constructor_params_and_events() {
    let gs: Vec<Guardian> = (0..3).map(guardian).collect();
    set_ctx(relayer(), NearToken::from_yoctonear(0), T0);
    let keys: Vec<String> = gs.iter().map(|g| hex::encode(g.pk)).collect();
    let c = Contract::new(NETWORK.into(), keys.clone(), 2, 600, U128(1_000), 86_400);
    let ev = bridge_events("guardians_changed");
    assert_eq!(ev[0]["guardians"], serde_json::json!(keys));
    assert_eq!(ev[0]["threshold"], 2);
    let ev = bridge_events("mint_limit_changed");
    assert_eq!(
        ev[0],
        serde_json::json!({"mint_cap": "1000", "cap_window_sec": 86400})
    );
    let cfg = c.config();
    assert_eq!(cfg.network_id, NETWORK);
    assert_eq!(cfg.contract_id, contract_id());
    assert_eq!(cfg.guardians, keys);
    assert_eq!(
        (cfg.threshold, cfg.challenge_window_sec, cfg.cap_window_sec),
        (2, 600, 86_400)
    );
    assert_eq!(cfg.mint_cap.0, 1_000);
    assert_eq!(
        (
            cfg.admin_nonce,
            cfg.paused,
            cfg.proposal_count,
            cfg.burn_count
        ),
        (0, false, 0, 0)
    );
    assert_eq!(c.get_threshold(), 2);
    assert_eq!(c.get_guardians(), keys);
    assert_eq!(c.mint_available().0, 1_000);
}

fn deploy(keys: Vec<String>, threshold: u8, window: u64, cap: u128, cap_window: u64) {
    set_ctx(relayer(), NearToken::from_yoctonear(0), T0);
    let _ = Contract::new(
        NETWORK.into(),
        keys,
        threshold,
        window,
        U128(cap),
        cap_window,
    );
}

fn keys(n: u8) -> Vec<String> {
    (0..n).map(|i| hex::encode(guardian(i).pk)).collect()
}

#[test]
#[should_panic(expected = "wyec: bad guardian set")]
fn constructor_threshold_zero_rejected() {
    deploy(keys(3), 0, WINDOW, 0, 0);
}

#[test]
#[should_panic(expected = "wyec: bad guardian set")]
fn constructor_threshold_above_size_rejected() {
    deploy(keys(3), 4, WINDOW, 0, 0);
}

#[test]
#[should_panic(expected = "wyec: bad guardian set")]
fn constructor_empty_set_rejected() {
    deploy(vec![], 1, WINDOW, 0, 0);
}

#[test]
#[should_panic(expected = "wyec: bad guardian set")]
fn constructor_duplicate_guardian_rejected() {
    let mut k = keys(2);
    k.push(k[0].clone());
    deploy(k, 2, WINDOW, 0, 0);
}

#[test]
#[should_panic(expected = "wyec: bad guardian set")]
fn constructor_zero_key_rejected() {
    let mut k = keys(2);
    k.push(hex::encode([0u8; 64]));
    deploy(k, 2, WINDOW, 0, 0);
}

#[test]
#[should_panic(expected = "wyec: bad guardian key")]
fn constructor_malformed_key_rejected() {
    let mut k = keys(2);
    k[1].pop();
    deploy(k, 2, WINDOW, 0, 0);
}

#[test]
#[should_panic(expected = "wyec: zero challenge window")]
fn constructor_zero_challenge_window_rejected() {
    deploy(keys(3), 2, 0, 0, 0);
}

#[test]
#[should_panic(expected = "wyec: bad mint limit")]
fn constructor_cap_without_window_rejected() {
    deploy(keys(3), 2, WINDOW, 5, 0);
}

#[test]
fn digest_views_match_independent_encoding() {
    let h = H::new(3, 2);
    let msg = h.mint_msg(7, 12_345, &alice());
    assert_eq!(
        h.c.mint_digest(lock(7), U128(12_345), alice()),
        hex::encode(h.digest(&msg))
    );
    let ch = BridgeMessage::Challenge {
        lock_id: [7; 32],
        proposal_id: 9,
    };
    assert_eq!(h.c.challenge_digest(lock(7), 9), hex::encode(h.digest(&ch)));
}

// --------------------------------------------------------------------- threshold mint

#[test]
fn mint_two_of_three() {
    let mut h = H::new(3, 2);
    h.mint(1, 500, &alice(), &[0, 2]);
    assert_eq!(h.balance(&alice()), 500);
    assert_eq!(h.c.ft_total_supply().0, 500);
    assert!(h.c.is_consumed(lock(1)));
    let ev = bridge_events("minted");
    assert_eq!(
        ev[0],
        serde_json::json!({"lock_id": lock(1), "receiver_id": "alice.near", "amount": "500"})
    );
    let ft: Vec<_> = events()
        .into_iter()
        .filter(|e| e["event"] == "ft_mint")
        .collect();
    assert_eq!(ft[0]["standard"], "nep141");
    assert_eq!(ft[0]["data"][0]["owner_id"], "alice.near");
    assert_eq!(ft[0]["data"][0]["amount"], "500");
}

#[test]
fn mint_all_three_sigs_accepted() {
    let mut h = H::new(3, 2);
    h.mint(1, 500, &alice(), &[0, 1, 2]);
    assert_eq!(h.balance(&alice()), 500);
}

#[test]
fn mint_one_of_one() {
    let mut h = H::new(1, 1);
    h.mint(1, 7, &alice(), &[0]);
    assert_eq!(h.balance(&alice()), 7);
}

#[test]
fn mint_anyone_may_submit() {
    let mut h = H::new(3, 2);
    let sigs = h.sigs(&[0, 1], &h.mint_msg(1, 5, &alice()));
    h.caller(bob(), NearToken::from_yoctonear(0));
    h.c.mint(lock(1), U128(5), alice(), sigs);
    assert_eq!(h.balance(&alice()), 5);
}

#[test]
fn mint_registers_receiver_storage_from_contract_balance() {
    let mut h = H::new(3, 2);
    assert!(h.c.storage_balance_of(alice()).is_none());
    let sigs = h.sigs(&[0, 1], &h.mint_msg(1, 5, &alice()));
    h.relay(); // a new testing_env! resets the storage-usage counter: measure after it
    let before = env::storage_usage();
    h.c.mint(lock(1), U128(5), alice(), sigs);
    assert!(h.c.storage_balance_of(alice()).is_some());
    assert_eq!(
        env::storage_usage() - before,
        // alice's account entry: 40 + key (prefix 1 + borsh "alice.near" 14) + u128 balance 16,
        // and the consumed-lock entry: 40 + key (prefix 1 + 32) + value (0 bytes)
        (40 + 15 + 16) + (40 + 33),
    );
    // NEP-145's bound reserves for the longest account id (64 bytes): 54 more than alice needs.
    assert_eq!(h.c.token.account_storage_usage, 40 + (1 + 4 + 64) + 16);
    // An already registered receiver is not registered again.
    h.mint(2, 5, &alice(), &[0, 1]);
    assert_eq!(h.balance(&alice()), 10);
}

#[test]
#[should_panic(expected = "wyec: lock consumed")]
fn mint_lock_replay_rejected() {
    let mut h = H::new(3, 2);
    h.mint(1, 5, &alice(), &[0, 1]);
    h.mint(1, 5, &alice(), &[0, 1]);
}

#[test]
#[should_panic(expected = "wyec: signers not strictly ascending")]
fn mint_signers_must_be_ascending() {
    let mut h = H::new(3, 2);
    let mut sigs = h.sigs(&[0, 1], &h.mint_msg(1, 5, &alice()));
    sigs.reverse();
    h.relay();
    h.c.mint(lock(1), U128(5), alice(), sigs);
}

#[test]
#[should_panic(expected = "wyec: signers not strictly ascending")]
fn mint_duplicate_signature_rejected() {
    let mut h = H::new(3, 2);
    let s = h.sig(0, &h.mint_msg(1, 5, &alice()));
    h.relay();
    h.c.mint(lock(1), U128(5), alice(), vec![s.clone(), s]);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn mint_non_guardian_rejected() {
    let mut h = H::new(3, 2);
    let outsider = guardian(9);
    let d = h.digest(&h.mint_msg(1, 5, &alice()));
    let mut pairs = [
        (h.gs[0].pk, sign_raw(&h.gs[0], &d)),
        (outsider.pk, sign_raw(&outsider, &d)),
    ];
    pairs.sort_by_key(|p| p.0);
    h.relay();
    h.c.mint(
        lock(1),
        U128(5),
        alice(),
        pairs.iter().map(|p| hex::encode(p.1)).collect(),
    );
}

#[test]
#[should_panic(expected = "wyec: below threshold")]
fn mint_below_threshold_rejected() {
    let mut h = H::new(3, 2);
    h.mint(1, 5, &alice(), &[0]);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn mint_tampered_amount_rejected() {
    let mut h = H::new(3, 2);
    let sigs = h.sigs(&[0, 1], &h.mint_msg(1, 5, &alice()));
    h.relay();
    h.c.mint(lock(1), U128(6), alice(), sigs);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn mint_tampered_receiver_rejected() {
    let mut h = H::new(3, 2);
    let sigs = h.sigs(&[0, 1], &h.mint_msg(1, 5, &alice()));
    h.relay();
    h.c.mint(lock(1), U128(5), bob(), sigs);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn mint_other_contract_signature_rejected() {
    let mut h = H::new(1, 1);
    let d = digest_for(NETWORK, "other.test.near", &h.mint_msg(1, 5, &alice()));
    h.relay();
    h.c.mint(
        lock(1),
        U128(5),
        alice(),
        vec![hex::encode(sign_raw(&h.gs[0], &d))],
    );
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn mint_other_network_signature_rejected() {
    let mut h = H::new(1, 1);
    let d = digest_for(
        "mainnet",
        contract_id().as_str(),
        &h.mint_msg(1, 5, &alice()),
    );
    h.relay();
    h.c.mint(
        lock(1),
        U128(5),
        alice(),
        vec![hex::encode(sign_raw(&h.gs[0], &d))],
    );
}

/// The same (r, n − s) with the flipped recovery id recovers the same key; it must be refused.
#[test]
#[should_panic(expected = "wyec: bad signature")]
fn mint_high_s_rejected() {
    let mut h = H::new(1, 1);
    let d = h.digest(&h.mint_msg(1, 5, &alice()));
    let low = sign_raw(&h.gs[0], &d);
    let sig = k256::ecdsa::Signature::from_slice(&low[..64]).unwrap();
    let (r, s) = sig.split_scalars();
    let high = k256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&high.to_bytes());
    bytes[64] = low[64] ^ 1;
    h.relay();
    h.c.mint(lock(1), U128(5), alice(), vec![hex::encode(bytes)]);
}

#[test]
#[should_panic(expected = "wyec: bad signature v")]
fn mint_v_above_one_rejected() {
    let mut h = H::new(1, 1);
    let mut s = sign_raw(&h.gs[0], &h.digest(&h.mint_msg(1, 5, &alice())));
    s[64] += 27;
    h.relay();
    h.c.mint(lock(1), U128(5), alice(), vec![hex::encode(s)]);
}

#[test]
#[should_panic(expected = "wyec: signature must be 65 bytes of hex")]
fn mint_short_signature_rejected() {
    let mut h = H::new(1, 1);
    h.relay();
    h.c.mint(lock(1), U128(5), alice(), vec!["00".repeat(64)]);
}

#[test]
#[should_panic(expected = "wyec: lock_id must be 32 bytes of hex")]
fn mint_bad_lock_id_rejected() {
    let mut h = H::new(1, 1);
    h.relay();
    h.c.mint("ab".into(), U128(5), alice(), vec![]);
}

// --------------------------------------------------------------------- optimistic mint

#[test]
fn propose_window_execute_happy_path() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 900, &alice(), 1);
    assert_eq!(id, 1);
    let ev = bridge_events("mint_proposed");
    assert_eq!(
        ev[0],
        serde_json::json!({
            "lock_id": lock(1), "proposal_id": 1, "proposer": hex::encode(h.gs[1].pk),
            "receiver_id": "alice.near", "amount": "900", "eta_sec": T0 + WINDOW,
        })
    );
    let p = h.c.get_proposal(lock(1)).unwrap();
    assert_eq!(
        p,
        ProposalView {
            proposal_id: 1,
            proposer: hex::encode(h.gs[1].pk),
            receiver_id: alice(),
            amount: U128(900),
            eta_sec: T0 + WINDOW,
            status: ProposalStatus::Pending,
        }
    );
    assert!(!h.c.is_consumed(lock(1)));
    assert_eq!(h.balance(&alice()), 0);

    h.warp(WINDOW - 1);
    assert_eq!(h.status(1), ProposalStatus::Pending);
    h.warp(1);
    assert_eq!(h.status(1), ProposalStatus::Ready);
    h.caller(bob(), NearToken::from_yoctonear(0)); // anyone executes
    h.c.execute_mint(lock(1));
    assert_eq!(h.balance(&alice()), 900);
    assert!(h.c.is_consumed(lock(1)));
    assert!(h.c.get_proposal(lock(1)).is_none());
    assert_eq!(h.status(1), ProposalStatus::None);
    // Execute emits minted (+ ft_mint), nothing else of ours.
    let ours: Vec<_> = events()
        .into_iter()
        .filter(|e| e["standard"] == EVENT_STANDARD)
        .collect();
    assert_eq!(ours.len(), 1);
    assert_eq!(ours[0]["event"], "minted");
}

#[test]
#[should_panic(expected = "wyec: challenge window open")]
fn execute_before_eta_rejected() {
    let mut h = H::new(3, 2);
    h.propose(1, 900, &alice(), 1);
    h.warp(WINDOW - 1);
    h.execute(1);
}

#[test]
#[should_panic(expected = "wyec: no such proposal")]
fn execute_without_proposal_rejected() {
    let mut h = H::new(3, 2);
    h.execute(1);
}

#[test]
#[should_panic(expected = "wyec: lock consumed")]
fn execute_twice_rejected() {
    let mut h = H::new(3, 2);
    h.propose(1, 900, &alice(), 1);
    h.warp(WINDOW);
    h.execute(1);
    h.propose(1, 900, &alice(), 2);
}

#[test]
fn same_mint_signature_serves_both_paths() {
    let mut h = H::new(3, 2);
    let msg = h.mint_msg(1, 5, &alice());
    let s1 = h.sig(1, &msg);
    h.relay();
    h.c.propose_mint(lock(1), U128(5), alice(), s1.clone());
    let s2 = h.sig(2, &msg);
    let mut pairs = [(h.gs[1].pk, s1), (h.gs[2].pk, s2)];
    pairs.sort_by_key(|p| p.0);
    h.relay();
    h.c.mint(
        lock(1),
        U128(5),
        alice(),
        pairs.into_iter().map(|p| p.1).collect(),
    );
    assert_eq!(h.balance(&alice()), 5);
    assert!(h.c.get_proposal(lock(1)).is_none());
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn propose_non_guardian_rejected() {
    let mut h = H::new(3, 2);
    let d = h.digest(&h.mint_msg(1, 5, &alice()));
    h.relay();
    h.c.propose_mint(
        lock(1),
        U128(5),
        alice(),
        hex::encode(sign_raw(&guardian(9), &d)),
    );
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn propose_tampered_fields_rejected() {
    let mut h = H::new(3, 2);
    let s = h.sig(0, &h.mint_msg(1, 5, &alice()));
    h.relay();
    h.c.propose_mint(lock(1), U128(5_000), alice(), s);
}

#[test]
#[should_panic(expected = "wyec: lock consumed")]
fn propose_consumed_lock_rejected() {
    let mut h = H::new(3, 2);
    h.mint(1, 5, &alice(), &[0, 1]);
    h.propose(1, 5, &alice(), 2);
}

#[test]
#[should_panic(expected = "wyec: proposal pending")]
fn propose_duplicate_live_proposal_rejected() {
    let mut h = H::new(3, 2);
    h.propose(1, 5, &alice(), 0);
    h.propose(1, 5, &alice(), 1);
}

#[test]
#[should_panic(expected = "wyec: zero amount")]
fn propose_zero_amount_rejected() {
    let mut h = H::new(3, 2);
    h.propose(1, 0, &alice(), 0);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn propose_other_contract_signature_rejected() {
    let mut h = H::new(3, 2);
    let d = digest_for(NETWORK, "other.test.near", &h.mint_msg(1, 5, &alice()));
    h.relay();
    h.c.propose_mint(
        lock(1),
        U128(5),
        alice(),
        hex::encode(sign_raw(&h.gs[0], &d)),
    );
}

#[test]
fn challenge_by_any_guardian_deletes_and_lock_is_reproposable() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 5, &alice(), 0);
    h.challenge(1, id, 2);
    assert_eq!(
        bridge_events("mint_challenged")[0],
        serde_json::json!({
            "lock_id": lock(1), "proposal_id": 1,
            "proposer": hex::encode(h.gs[0].pk), "challenger": hex::encode(h.gs[2].pk),
        })
    );
    assert!(h.c.get_proposal(lock(1)).is_none());
    assert!(!h.c.is_consumed(lock(1)));
    assert!(h.c.is_vetoed(lock(1), hex::encode(h.gs[0].pk)));
    assert!(!h.c.is_vetoed(lock(1), hex::encode(h.gs[1].pk)));

    let id2 = h.propose(1, 5, &alice(), 1);
    assert_eq!(id2, 2);
    h.warp(WINDOW);
    h.execute(1);
    assert_eq!(h.balance(&alice()), 5);
}

#[test]
fn challenge_own_proposal_and_at_and_after_eta() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 5, &alice(), 0);
    h.warp(WINDOW); // at eta: Ready, still challengeable
    h.challenge(1, id, 0);
    let id = h.propose(1, 5, &alice(), 1);
    h.warp(WINDOW * 10);
    h.challenge(1, id, 2);
    assert_eq!(h.status(1), ProposalStatus::None);
}

#[test]
#[should_panic(expected = "wyec: no such proposal")]
fn challenge_old_signature_cannot_block_reproposal() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 5, &alice(), 0);
    let old = h.sig(
        2,
        &BridgeMessage::Challenge {
            lock_id: [1; 32],
            proposal_id: id,
        },
    );
    h.relay();
    h.c.challenge_mint(lock(1), id, old.clone());
    let id2 = h.propose(1, 5, &alice(), 1);
    assert_ne!(id, id2);
    h.relay();
    h.c.challenge_mint(lock(1), id, old.clone()); // names the old id: no such proposal
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn challenge_old_signature_renamed_to_new_id_rejected() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 5, &alice(), 0);
    let old = h.sig(
        2,
        &BridgeMessage::Challenge {
            lock_id: [1; 32],
            proposal_id: id,
        },
    );
    h.relay();
    h.c.challenge_mint(lock(1), id, old.clone());
    let id2 = h.propose(1, 5, &alice(), 1);
    h.relay();
    h.c.challenge_mint(lock(1), id2, old); // signature is over the old id: recovers elsewhere
}

#[test]
#[should_panic(expected = "wyec: proposer vetoed for this lock")]
fn challenged_proposer_vetoed_for_that_lock() {
    let mut h = H::new(3, 2);
    let msg = h.mint_msg(1, 5, &alice());
    let s0 = h.sig(0, &msg);
    h.relay();
    let id = h.c.propose_mint(lock(1), U128(5), alice(), s0.clone());
    h.challenge(1, id, 1);
    // Replaying the public signature (by anyone) is refused.
    h.caller(bob(), NearToken::from_yoctonear(0));
    h.c.propose_mint(lock(1), U128(5), alice(), s0);
}

#[test]
fn veto_is_per_lock() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 5, &alice(), 0);
    h.challenge(1, id, 1);
    // Guardian 0 may still propose other locks, and the threshold path may still mint lock 1.
    h.propose(2, 5, &alice(), 0);
    h.mint(1, 5, &alice(), &[0, 1]);
    assert_eq!(h.balance(&alice()), 5);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn challenge_non_guardian_rejected() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 5, &alice(), 0);
    let d = h.digest(&BridgeMessage::Challenge {
        lock_id: [1; 32],
        proposal_id: id,
    });
    h.relay();
    h.c.challenge_mint(lock(1), id, hex::encode(sign_raw(&guardian(9), &d)));
}

#[test]
#[should_panic(expected = "wyec: no such proposal")]
fn challenge_unknown_proposal_rejected() {
    let mut h = H::new(3, 2);
    h.challenge(1, 1, 0);
}

#[test]
fn threshold_mint_clears_pending_proposal() {
    let mut h = H::new(3, 2);
    h.propose(1, 5, &alice(), 0);
    h.mint(1, 5, &alice(), &[1, 2]);
    assert!(h.c.get_proposal(lock(1)).is_none());
    assert_eq!(h.balance(&alice()), 5);
}

#[test]
fn threshold_mint_overrides_wrong_proposal() {
    let mut h = H::new(3, 2);
    h.propose(1, 5_000, &bob(), 0); // wrong amount and receiver
    h.mint(1, 5, &alice(), &[1, 2]);
    assert_eq!((h.balance(&alice()), h.balance(&bob())), (5, 0));
    assert_eq!(h.c.ft_total_supply().0, 5);
}

#[test]
fn rotated_out_proposer_voids_proposal_and_is_replaceable() {
    let mut h = H::new(3, 2);
    h.propose(1, 5, &alice(), 0);
    let all = h.by_key();
    // Remove guardian 0: new set {1, 2}, threshold 2.
    let keep = [h.gs[1].pk, h.gs[2].pk];
    h.set_guardians(&keep, 2, &all);
    h.warp(WINDOW);
    assert_eq!(h.status(1), ProposalStatus::Void);
    assert_eq!(
        h.c.get_proposal(lock(1)).unwrap().status,
        ProposalStatus::Void
    );
    // A current guardian replaces the void proposal with a fresh window.
    let id = h.propose(1, 5, &alice(), 1);
    assert_eq!(id, 2);
    assert_eq!(h.status(1), ProposalStatus::Pending);
    h.warp(WINDOW);
    h.execute(1);
    assert_eq!(h.balance(&alice()), 5);
}

#[test]
#[should_panic(expected = "wyec: proposer not a guardian")]
fn rotated_out_proposer_execute_rejected() {
    let mut h = H::new(3, 2);
    h.propose(1, 5, &alice(), 0);
    let all = h.by_key();
    h.set_guardians(&[h.gs[1].pk, h.gs[2].pk], 2, &all);
    h.warp(WINDOW);
    h.execute(1);
}

#[test]
fn rotated_out_proposer_readded_makes_proposal_live_again() {
    let mut h = H::new(3, 2);
    h.propose(1, 5, &alice(), 0);
    let all = h.by_key();
    h.set_guardians(&[h.gs[1].pk, h.gs[2].pk], 2, &all);
    h.warp(WINDOW);
    assert_eq!(h.status(1), ProposalStatus::Void);
    // Re-add guardian 0, signed by the current set {1, 2}.
    let set = [h.gs[0].pk, h.gs[1].pk, h.gs[2].pk];
    h.set_guardians(&set, 2, &[1, 2]);
    assert_eq!(h.status(1), ProposalStatus::Ready);
    h.execute(1);
    assert_eq!(h.balance(&alice()), 5);
}

#[test]
fn rotated_out_proposer_challenge_still_works() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 5, &alice(), 0);
    let all = h.by_key();
    h.set_guardians(&[h.gs[1].pk, h.gs[2].pk], 2, &all);
    h.challenge(1, id, 1);
    assert_eq!(h.status(1), ProposalStatus::None);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn rotated_out_guardian_cannot_challenge() {
    let mut h = H::new(3, 2);
    let id = h.propose(1, 5, &alice(), 1);
    let all = h.by_key();
    h.set_guardians(&[h.gs[1].pk, h.gs[2].pk], 2, &all);
    h.challenge(1, id, 0);
}

#[test]
fn proposal_ids_increase() {
    let mut h = H::new(3, 2);
    let ids: Vec<u64> = (1..=5)
        .map(|l| h.propose(l, 1, &alice(), (l % 3) as usize))
        .collect();
    assert_eq!(ids, [1, 2, 3, 4, 5]);
    assert_eq!(h.c.config().proposal_count, 5);
}

#[test]
fn challenge_window_is_configurable() {
    let mut h = H::with(3, 2, 3_600, 0, 0);
    h.propose(1, 5, &alice(), 0);
    assert_eq!(h.c.get_proposal(lock(1)).unwrap().eta_sec, T0 + 3_600);
    h.warp(3_599);
    assert_eq!(h.status(1), ProposalStatus::Pending);
    h.warp(1);
    h.execute(1);
}

// ---------------------------------------------------------------------------- pause

#[test]
fn pause_blocks_bridge_not_challenge_transfers_or_storage() {
    let mut h = H::new(3, 2);
    h.mint(1, 100, &alice(), &[0, 1]);
    let id = h.propose(2, 5, &alice(), 0);
    let all = h.by_key();
    h.set_paused(true, &all[..2]);
    assert_eq!(
        bridge_events("paused")[0],
        serde_json::json!({"paused": true})
    );
    assert!(h.c.is_paused());
    // Challenge works while paused.
    h.challenge(2, id, 1);
    // Transfers and storage management work while paused.
    h.caller(bob(), h.c.storage_balance_bounds().min);
    h.c.storage_deposit(None, None);
    h.caller(alice(), ONE_YOCTO);
    h.c.ft_transfer(bob(), U128(40), None);
    assert_eq!((h.balance(&alice()), h.balance(&bob())), (60, 40));
    // Windows keep running; unpause and the bridge works again.
    h.set_paused(false, &all[1..]);
    assert!(!h.c.is_paused());
    h.mint(3, 1, &alice(), &[0, 1]);
}

fn paused() -> H {
    let mut h = H::new(3, 2);
    h.mint(1, 100, &alice(), &[0, 1]);
    h.propose(2, 5, &alice(), 0);
    h.warp(WINDOW);
    h.set_paused(true, &[0, 1]);
    h
}

#[test]
#[should_panic(expected = "wyec: paused")]
fn pause_blocks_mint() {
    paused().mint(3, 1, &alice(), &[0, 1]);
}

#[test]
#[should_panic(expected = "wyec: paused")]
fn pause_blocks_propose() {
    paused().propose(3, 1, &alice(), 1);
}

#[test]
#[should_panic(expected = "wyec: paused")]
fn pause_blocks_execute() {
    paused().execute(2);
}

#[test]
#[should_panic(expected = "wyec: paused")]
fn pause_blocks_burn() {
    paused().burn(&alice(), 1);
}

#[test]
#[should_panic(expected = "wyec: already paused")]
fn pause_noop_rejected() {
    paused().set_paused(true, &[1, 2]);
}

#[test]
#[should_panic(expected = "wyec: not paused")]
fn unpause_noop_rejected() {
    H::new(3, 2).set_paused(false, &[1, 2]);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn pause_replay_of_admin_sigs_rejected() {
    let mut h = H::new(3, 2);
    let msg = BridgeMessage::SetPaused {
        paused: true,
        admin_nonce: 0,
    };
    let sigs = h.sigs(&[0, 1], &msg);
    h.relay();
    h.c.set_paused(true, sigs.clone());
    h.set_paused(false, &[0, 1]);
    h.relay();
    h.c.set_paused(true, sigs); // nonce 0 again: digest differs, recovers to a stranger
}

// ---------------------------------------------------------------------------- admin

#[test]
fn set_guardians_rotation_and_admin_nonce() {
    let mut h = H::new(3, 2);
    let g3 = guardian(3);
    let set = [h.gs[1].pk, h.gs[2].pk, g3.pk];
    h.set_guardians(&set, 3, &[0, 2]);
    assert_eq!(h.c.get_admin_nonce(), 1);
    assert_eq!(h.c.get_threshold(), 3);
    assert_eq!(
        h.c.get_guardians(),
        set.iter().map(hex::encode).collect::<Vec<_>>()
    );
    let ev = bridge_events("guardians_changed");
    assert_eq!(ev[0]["threshold"], 3);
    h.gs.push(g3);
    // Old member 0 is out; the new set needs 3.
    h.mint(1, 5, &alice(), &[1, 2, 3]);
    assert_eq!(h.balance(&alice()), 5);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn set_guardians_removed_member_cannot_sign() {
    let mut h = H::new(3, 2);
    h.set_guardians(&[h.gs[1].pk, h.gs[2].pk], 2, &[0, 1]);
    h.mint(1, 5, &alice(), &[0, 1]);
}

#[test]
fn set_guardians_mint_sigs_survive_rotation_of_others() {
    let mut h = H::new(3, 2);
    let sigs = h.sigs(&[1, 2], &h.mint_msg(1, 5, &alice()));
    h.set_guardians(&[h.gs[1].pk, h.gs[2].pk, guardian(3).pk], 2, &[0, 1]);
    h.relay();
    h.c.mint(lock(1), U128(5), alice(), sigs);
    assert_eq!(h.balance(&alice()), 5);
}

#[test]
fn set_guardians_works_while_paused() {
    let mut h = H::new(3, 2);
    h.set_paused(true, &[0, 1]);
    h.set_guardians(&[h.gs[1].pk, h.gs[2].pk], 1, &[0, 1]);
    assert_eq!(h.c.get_threshold(), 1);
    assert_eq!(h.c.get_admin_nonce(), 2);
}

#[test]
#[should_panic(expected = "wyec: bad guardian set")]
fn set_guardians_bad_set_rejected() {
    let mut h = H::new(3, 2);
    h.set_guardians(&[h.gs[1].pk], 2, &[0, 1]);
}

#[test]
#[should_panic(expected = "wyec: below threshold")]
fn set_guardians_below_threshold_rejected() {
    let mut h = H::new(3, 2);
    h.set_guardians(&[h.gs[1].pk], 1, &[0]);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn admin_signature_from_new_set_not_accepted_for_its_own_install() {
    let mut h = H::new(3, 2);
    h.gs.push(guardian(3));
    h.gs.push(guardian(4));
    // The NEW set {3, 4} cannot sign its own installation: the current set must.
    h.set_guardians(&[h.gs[3].pk, h.gs[4].pk], 2, &[3, 4]);
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn admin_nonce_shared_across_acts() {
    let mut h = H::new(3, 2);
    // Signatures for SetMintLimit at nonce 0, then another act consumes nonce 0.
    let msg = BridgeMessage::SetMintLimit {
        mint_cap: 10,
        cap_window_sec: 60,
        admin_nonce: 0,
    };
    let sigs = h.sigs(&[0, 1], &msg);
    h.set_paused(true, &[0, 1]);
    assert_eq!(h.c.get_admin_nonce(), 1);
    h.relay();
    h.c.set_mint_limit(U128(10), 60, sigs);
}

// ----------------------------------------------------------------------- rate limit

#[test]
fn set_mint_limit_flow_and_admin_nonce() {
    let mut h = H::new(3, 2);
    assert_eq!(h.c.mint_available().0, u128::MAX);
    h.set_limit(1_000, 3_600, &[1, 2]);
    assert_eq!(
        bridge_events("mint_limit_changed")[0],
        serde_json::json!({"mint_cap": "1000", "cap_window_sec": 3600})
    );
    assert_eq!(h.c.get_admin_nonce(), 1);
    assert_eq!(h.c.mint_available().0, 1_000);
    let cfg = h.c.config();
    assert_eq!((cfg.mint_cap.0, cfg.cap_window_sec), (1_000, 3_600));
}

#[test]
#[should_panic(expected = "wyec: not a guardian")]
fn set_mint_limit_replay_rejected() {
    let mut h = H::new(3, 2);
    let msg = BridgeMessage::SetMintLimit {
        mint_cap: 10,
        cap_window_sec: 60,
        admin_nonce: 0,
    };
    let sigs = h.sigs(&[0, 1], &msg);
    h.relay();
    h.c.set_mint_limit(U128(10), 60, sigs.clone());
    h.relay();
    h.c.set_mint_limit(U128(10), 60, sigs);
}

#[test]
#[should_panic(expected = "wyec: bad mint limit")]
fn set_mint_limit_cap_without_window_rejected() {
    H::new(3, 2).set_limit(10, 0, &[0, 1]);
}

#[test]
fn set_mint_limit_works_while_paused() {
    let mut h = H::new(3, 2);
    h.set_paused(true, &[0, 1]);
    h.set_limit(10, 60, &[0, 1]);
    assert_eq!(h.c.config().mint_cap.0, 10);
}

#[test]
fn threshold_path_limited_across_windows() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    // Align to a window start.
    h.now = (T0 / 3_600 + 1) * 3_600;
    h.mint(1, 600, &alice(), &[0, 1]);
    assert_eq!(h.c.mint_available().0, 400);
    h.mint(2, 400, &alice(), &[0, 1]);
    assert_eq!(h.c.mint_available().0, 0);
    h.warp(3_600);
    assert_eq!(h.c.mint_available().0, 1_000);
    h.mint(3, 1_000, &alice(), &[0, 1]);
    assert_eq!(h.balance(&alice()), 2_000);
}

#[test]
#[should_panic(expected = "wyec: mint rate limited")]
fn threshold_path_over_limit_rejected() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    h.mint(1, 600, &alice(), &[0, 1]);
    h.mint(2, 401, &alice(), &[0, 1]);
}

#[test]
fn fixed_windows_boundary_burst() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    h.now = (T0 / 3_600 + 1) * 3_600 - 1; // last second of a window
    h.mint(1, 1_000, &alice(), &[0, 1]);
    h.warp(1); // first second of the next
    h.mint(2, 1_000, &alice(), &[0, 1]);
    assert_eq!(h.balance(&alice()), 2_000); // the documented 2 × cap worst case
}

#[test]
fn zero_amount_threshold_mint_unaffected_by_full_window() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    h.mint(1, 1_000, &alice(), &[0, 1]);
    h.mint(2, 0, &alice(), &[0, 1]);
    assert!(h.c.is_consumed(lock(2)));
}

#[test]
fn optimistic_path_limited_and_executes_in_later_window() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    h.now = (T0 / 3_600 + 1) * 3_600;
    h.mint(1, 700, &alice(), &[0, 1]);
    h.propose(2, 500, &alice(), 0);
    h.warp(WINDOW);
    assert_eq!(h.status(2), ProposalStatus::Ready);
    assert_eq!(h.c.mint_available().0, 300);
    h.warp(3_600 - WINDOW);
    h.execute(2);
    assert_eq!(h.balance(&alice()), 1_200);
}

#[test]
#[should_panic(expected = "wyec: mint rate limited")]
fn optimistic_path_over_limit_rejected() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    h.now = (T0 / 3_600 + 1) * 3_600;
    h.mint(1, 700, &alice(), &[0, 1]);
    h.propose(2, 500, &alice(), 0);
    h.warp(WINDOW);
    h.execute(2);
}

#[test]
fn both_paths_share_the_budget() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    h.now = (T0 / 3_600 + 1) * 3_600;
    h.propose(1, 600, &alice(), 0);
    h.warp(WINDOW);
    h.execute(1);
    assert_eq!(h.c.mint_available().0, 400);
    h.mint(2, 400, &alice(), &[0, 1]);
    assert_eq!(h.c.mint_available().0, 0);
}

#[test]
fn set_mint_limit_resets_running_total() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    h.mint(1, 1_000, &alice(), &[0, 1]);
    assert_eq!(h.c.mint_available().0, 0);
    h.set_limit(1_000, 3_600, &[0, 1]);
    assert_eq!(h.c.mint_available().0, 1_000);
}

#[test]
fn set_mint_limit_zero_disables_then_reenables() {
    let mut h = H::with(3, 2, WINDOW, 1_000, 3_600);
    h.mint(1, 1_000, &alice(), &[0, 1]);
    h.set_limit(0, 0, &[0, 1]);
    h.mint(2, 5_000, &alice(), &[0, 1]);
    assert_eq!(h.c.mint_available().0, u128::MAX);
    h.set_limit(100, 60, &[0, 1]);
    assert_eq!(h.c.mint_available().0, 100);
}

// ---------------------------------------------------------------------------- burn

#[test]
fn burn_records_events_and_nonces() {
    let mut h = H::new(3, 2);
    h.mint(1, 1_000, &alice(), &[0, 1]);
    h.mint(2, 1_000, &bob(), &[0, 1]);
    h.now += 10;
    let n0 = h.burn(&alice(), 300);
    assert_eq!(n0, 0);
    let ft: Vec<_> = events()
        .into_iter()
        .filter(|e| e["event"] == "ft_burn")
        .collect();
    assert_eq!(ft[0]["standard"], "nep141");
    assert_eq!(ft[0]["data"][0]["owner_id"], "alice.near");
    assert_eq!(ft[0]["data"][0]["amount"], "300");
    let ev = bridge_events("burn_to_ycash");
    let expected = BurnRecord {
        nonce: 0,
        from: "alice.near".into(),
        amount: 300,
        ycash_recipient: decode_hex(&recipient()).unwrap(),
        block_height: (T0 + 10) / 2,
        timestamp_ns: (T0 + 10) * NS_PER_SEC,
    };
    let hash: [u8; 32] = Sha256::digest(burn_record_bytes(&expected)).into();
    assert_eq!(
        ev[0],
        serde_json::json!({
            "nonce": 0, "from": "alice.near", "amount": "300", "ycash_recipient": recipient(),
            "block_height": (T0 + 10) / 2, "timestamp_ns": ((T0 + 10) * NS_PER_SEC).to_string(),
            "record_hash": hex::encode(hash),
        })
    );
    assert_eq!(h.balance(&alice()), 700);
    assert_eq!(h.c.ft_total_supply().0, 1_700);

    assert_eq!(h.burn(&bob(), 1_000), 1);
    assert_eq!(h.burn(&alice(), 700), 2);
    assert_eq!(h.c.get_burn_count(), 3);
    assert_eq!(h.c.ft_total_supply().0, 0);
    // The burner stays registered.
    assert!(h.c.storage_balance_of(bob()).is_some());

    let all = h.c.get_burns(0, 10);
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].record_hash, hex::encode(hash));
    assert_eq!(all[0].from, alice());
    assert_eq!(
        (all[1].nonce, all[1].from.as_str(), all[1].amount.0),
        (1, "bob.near", 1_000)
    );
    assert_eq!(h.c.get_burns(1, 1).len(), 1);
    assert_eq!(h.c.get_burns(1, 1)[0].nonce, 1);
    assert_eq!(h.c.get_burns(2, 10).len(), 1);
    assert!(h.c.get_burns(3, 10).is_empty());
    assert!(h.c.get_burns(u64::MAX, u64::MAX).is_empty());
}

#[test]
fn burn_page_is_capped() {
    let mut h = H::new(1, 1);
    h.mint(1, 1_000, &alice(), &[0]);
    for _ in 0..(MAX_BURNS_PER_PAGE + 5) {
        h.burn(&alice(), 1);
    }
    assert_eq!(h.c.get_burns(0, 1_000).len() as u64, MAX_BURNS_PER_PAGE);
    assert_eq!(h.c.get_burns(MAX_BURNS_PER_PAGE, 1_000).len(), 5);
}

#[test]
fn burn_zero_amount_consumes_nonce() {
    let mut h = H::new(3, 2);
    h.mint(1, 10, &alice(), &[0, 1]);
    assert_eq!(h.burn(&alice(), 0), 0);
    assert_eq!(h.burn(&alice(), 10), 1);
}

#[test]
#[should_panic(expected = "The account doesn't have enough balance")]
fn burn_more_than_balance_rejected() {
    let mut h = H::new(3, 2);
    h.mint(1, 10, &alice(), &[0, 1]);
    h.burn(&alice(), 11);
}

#[test]
#[should_panic(expected = "Requires attached deposit of at least 1 yoctoNEAR")]
fn burn_without_deposit_rejected() {
    let mut h = H::new(3, 2);
    h.mint(1, 10, &alice(), &[0, 1]);
    h.caller(alice(), NearToken::from_yoctonear(0));
    h.c.burn(U128(1), recipient());
}

#[test]
#[should_panic(expected = "wyec: attached deposit below the burn record's storage cost")]
fn burn_one_yocto_is_below_storage_cost() {
    let mut h = H::new(3, 2);
    h.mint(1, 10, &alice(), &[0, 1]);
    h.caller(alice(), ONE_YOCTO);
    h.c.burn(U128(1), recipient());
}

#[test]
#[should_panic(expected = "wyec: ycash_recipient must be 32 bytes of hex")]
fn burn_bad_recipient_rejected() {
    let mut h = H::new(3, 2);
    h.mint(1, 10, &alice(), &[0, 1]);
    h.caller(alice(), NearToken::from_near(1));
    h.c.burn(U128(1), "00".into());
}

#[test]
fn burn_storage_deposit_matches_actual_storage() {
    let mut h = H::new(3, 2);
    let long: AccountId = format!("{}.near", "a".repeat(59)).parse().unwrap();
    for who in [alice(), long] {
        h.mint(who.len() as u8, 10, &who, &[0, 1]);
        let dep = h.c.burn_storage_deposit(who.clone());
        h.caller(who.clone(), dep);
        let before = env::storage_usage();
        h.c.burn(U128(1), recipient());
        h.c.burns.flush();
        let used = env::storage_usage() - before;
        assert_eq!(used, BURN_RECORD_FIXED_BYTES + who.len() as u64);
        assert_eq!(
            h.c.burn_storage_deposit(who.clone()),
            env::storage_byte_cost().saturating_mul(u128::from(used))
        );
    }
}

#[test]
fn burn_excess_deposit_refunded() {
    let mut h = H::new(3, 2);
    h.mint(1, 10, &alice(), &[0, 1]);
    h.caller(alice(), NearToken::from_near(1));
    h.c.burn(U128(1), recipient());
    let receipts = near_sdk::test_utils::get_created_receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].receiver_id, alice());
    let cost = h.c.burn_storage_deposit(alice());
    let want = NearToken::from_near(1).saturating_sub(cost);
    match &receipts[0].actions[..] {
        [near_sdk::mock::MockAction::Transfer { deposit, .. }] => assert_eq!(*deposit, want),
        other => panic!("unexpected actions {other:?}"),
    }
}

// ------------------------------------------------------------------------- NEP-141/145

#[test]
fn ft_transfer_still_works() {
    let mut h = H::new(3, 2);
    h.mint(1, 100, &alice(), &[0, 1]);
    h.caller(bob(), h.c.storage_balance_bounds().min);
    h.c.storage_deposit(None, Some(true));
    h.caller(alice(), ONE_YOCTO);
    h.c.ft_transfer(bob(), U128(30), Some("memo".into()));
    assert_eq!((h.balance(&alice()), h.balance(&bob())), (70, 30));
    let ev: Vec<_> = events()
        .into_iter()
        .filter(|e| e["event"] == "ft_transfer")
        .collect();
    assert_eq!(ev[0]["data"][0]["old_owner_id"], "alice.near");
    assert_eq!(h.c.ft_total_supply().0, 100);
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn ft_transfer_requires_one_yocto() {
    let mut h = H::new(3, 2);
    h.mint(1, 100, &alice(), &[0, 1]);
    h.mint(2, 100, &bob(), &[0, 1]);
    h.caller(alice(), NearToken::from_yoctonear(0));
    h.c.ft_transfer(bob(), U128(30), None);
}

#[test]
#[should_panic(expected = "is not registered")]
fn ft_transfer_to_unregistered_rejected() {
    let mut h = H::new(3, 2);
    h.mint(1, 100, &alice(), &[0, 1]);
    h.caller(alice(), ONE_YOCTO);
    h.c.ft_transfer(bob(), U128(30), None);
}

#[test]
fn storage_registration_and_unregistration() {
    let mut h = H::new(3, 2);
    let min = h.c.storage_balance_bounds().min;
    assert!(min > NearToken::from_yoctonear(0));
    h.caller(bob(), min);
    let b = h.c.storage_deposit(None, None);
    assert_eq!(b.total, min);
    h.caller(bob(), ONE_YOCTO);
    assert!(h.c.storage_unregister(None));
    assert!(h.c.storage_balance_of(bob()).is_none());
}

// ---------------------------------------------------------------------------- vectors

/// Writes (with `WYEC_NEAR_WRITE_VECTORS=1`) or checks `vectors/messages.json`: digests and
/// signatures of every `BridgeMessage` variant and a `BurnRecord` hash, from fixed secrets.
#[test]
fn vectors_file() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/messages.json");
    let got = serde_json::to_string_pretty(&crate::tests::vectors::build()).unwrap() + "\n";
    if std::env::var("WYEC_NEAR_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(path, &got).unwrap();
    }
    let want = std::fs::read_to_string(path)
        .expect("vectors/messages.json (regenerate with WYEC_NEAR_WRITE_VECTORS=1)");
    assert_eq!(
        got, want,
        "vectors/messages.json is stale: regenerate with WYEC_NEAR_WRITE_VECTORS=1"
    );
}

/// Every vector digest equals the one the contract computes in the mocked runtime, and every
/// vector signature recovers (through the host's ecrecover) to the vector's guardian.
#[test]
fn vectors_verify_in_the_contract() {
    let v = crate::tests::vectors::build();
    for m in v["messages"].as_array().unwrap() {
        let contract: AccountId = m["contract_id"].as_str().unwrap().parse().unwrap();
        testing_env!(VMContextBuilder::new().current_account_id(contract).build());
        let gs = v["guardians"].as_array().unwrap();
        let keys: Vec<String> = gs
            .iter()
            .map(|g| g["pubkey"].as_str().unwrap().to_string())
            .collect();
        let c = Contract::new(
            m["network_id"].as_str().unwrap().into(),
            keys,
            1,
            1,
            U128(0),
            0,
        );
        let msg: BridgeMessage =
            near_sdk::borsh::from_slice(&hex::decode(m["borsh"].as_str().unwrap()).unwrap())
                .unwrap();
        let d = c.digest(&msg);
        assert_eq!(
            hex::encode(d),
            m["digest"].as_str().unwrap(),
            "{}",
            m["name"]
        );
        for s in m["signatures"].as_array().unwrap() {
            let signer = recover(&d, s["signature"].as_str().unwrap());
            let gi = s["guardian"].as_u64().unwrap() as usize;
            assert_eq!(hex::encode(signer), gs[gi]["pubkey"].as_str().unwrap());
        }
    }
}

/// Cross-check against hawkeye-core's vectors (NH1) when that file is present.
#[test]
fn hawkeye_core_vectors_agree() {
    let n = crate::tests::vectors::check_hawkeye_core();
    eprintln!("hawkeye-core near_vectors.json: {n} entries checked");
}

pub(crate) mod vectors;
