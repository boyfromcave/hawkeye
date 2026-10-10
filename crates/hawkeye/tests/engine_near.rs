//! Engine tests over a NEAR bridge (NEAR plan NH4): three Hawkeye engines against one mock
//! ycashd (hawkeye-ycash feature `mock`) and one mock NEAR node running a model of the
//! `wyec-near` contract (hawkeye-near feature `mock`). Each engine sends through its own relayer
//! account and attests with its member key (Borsh-SHA256 digests, 64-byte guardian keys). Ticks
//! and blocks on both chains are driven by hand: every run is deterministic.
//!
//! The NEAR twins of the Ethereum engine tests (`tests/engine.rs`): (a) lock (`NYEC`, `NR1`
//! destination) → sign → threshold mint observed; (b) burn → unlock with the `HKN1` memo whose
//! data is the burn record's hash → release after the delay; (d) a restart mid-flow signs nothing
//! twice; (j) a rogue proposal with no lock is challenged within the window, its proposer
//! `vetoed` and put in a slash case, in optimistic and (j2) threshold mode; (l) optimistic happy
//! path: propose → window → execute; (m) a matching proposal challenged anyway is re-proposed by
//! another attestor; (n) a wrong-amount proposal squatting a real lock is challenged and the
//! right mint follows; (s) the scanner crosses heights NEAR skipped.

use std::sync::{Arc, Mutex, RwLock};

use hawkeye::attribution::Attributor;
use hawkeye::config::Params;
use hawkeye::engine::{Ctx, Engine};
use hawkeye::foreign::{ForeignChain, NearChain};
use hawkeye::peers::Peers;
use hawkeye::status::Status;
use hawkeye_core::address::Network;
use hawkeye_core::attribution::{Attribution, SetSigner};
use hawkeye_core::memo::{MemoKind, parse_memo_script_for};
use hawkeye_core::near::{BridgeMessage, Domain, guardian_key_of, sign_digest};
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_core::setsig::Role;
use hawkeye_core::template::{TAG_NYEC, VaultParams};
use hawkeye_core::{AccountId, BridgeKind, OutPoint as CoreOutPoint, SecretKey};
use hawkeye_eth::MintMode;
use hawkeye_near::contract::DEFAULT_GAS;
use hawkeye_near::mock::{Contract, MockNear, MockState as NearState};
use hawkeye_near::{KeyFile, WyecNear};
use hawkeye_store::{BurnKey, BurnState, IntentState, LockState, SlashState, Store};
use hawkeye_ycash::mock::{KnownScript, MockState, MockYcashd};
use hawkeye_ycash::tx::{Transaction, TxIn, TxOut};
use hawkeye_ycash::types::{SetParams, VaultFields};
use hawkeye_ycash::{Amount, Hash256, HexBytes, OutPoint, PubKey};

/// The mock's set signatures are `0x1f ‖ key ‖ sighash[..31]` (as in `tests/engine.rs`).
struct MockAttributor {
    set: [u8; 32],
}

impl Attributor for MockAttributor {
    fn attribute(
        &self,
        tx_bytes: &[u8],
        input_index: usize,
        prev_spk: &[u8],
        _value: u64,
        _branch: u32,
    ) -> Result<Attribution, String> {
        use hawkeye_core::template::{TemplateKind, parse_selector, parse_vault};
        let tx = Transaction::decode(tx_bytes).map_err(|e| e.to_string())?;
        let input = tx.inputs.get(input_index).ok_or("no input")?;
        let (set_id, role, spend) = match parse_vault(prev_spk) {
            Ok(v) => (
                v.set_id,
                Role::Unlock,
                parse_selector(TemplateKind::Vault, &input.script_sig)
                    .map_err(|e| e.to_string())?,
            ),
            Err(_) => {
                let s = parse_selector(TemplateKind::Intent, &input.script_sig)
                    .map_err(|e| e.to_string())?;
                if s.selector != 2 {
                    return Err("not a cancel".into());
                }
                (self.set, Role::Cancel, s)
            }
        };
        if role == Role::Unlock && spend.selector != 1 {
            return Err("not an unlock".into());
        }
        let mut signers = vec![];
        let mut sighash = [0u8; 32];
        for a in &spend.args {
            let sig: [u8; 65] = a.as_slice().try_into().map_err(|_| "not 65 bytes")?;
            sighash[..31].copy_from_slice(&sig[34..]);
            signers.push(SetSigner {
                pubkey: sig[1..34].try_into().expect("33"),
                signature: sig,
            });
        }
        Ok(Attribution {
            set_id,
            role,
            prevout: CoreOutPoint::new(input.prevout.txid.0, input.prevout.vout),
            sighash,
            signers,
        })
    }
}

const DELAY: u16 = 6;
/// The contract's challenge window in these tests, seconds (the mock's clock is warped).
const WINDOW: u64 = 3600;
const C_Y: u32 = 2;
const TAKEOVER: u32 = 4;
const NETWORK: &str = "sandbox";
const CONTRACT: &str = "wyec.test.near";

fn secret(i: u8) -> SecretKey {
    let mut s = [0u8; 32];
    s[0] = 0x42;
    s[31] = i;
    SecretKey::from_bytes(&s).unwrap()
}

fn id(s: &str) -> AccountId {
    AccountId::parse(s).unwrap()
}

fn domain() -> Domain {
    Domain::new(NETWORK, id(CONTRACT)).unwrap()
}

struct Env {
    mode: MintMode,
    mock: MockYcashd,
    near: MockNear,
    set: Hash256,
    keys: Vec<SecretKey>,
    relayers: Vec<KeyFile>,
    holder: KeyFile,
    dir: tempfile::TempDir,
}

async fn setup(mode: MintMode) -> Env {
    let keys: Vec<SecretKey> = (1..=3).map(secret).collect();
    // threshold mode deploys at its k; optimistic at 2 (the mainnet rule)
    let threshold = match mode {
        MintMode::Threshold { k } => k,
        MintMode::Optimistic => 2,
    };
    let contract = Contract::new(
        NETWORK,
        keys.iter().map(guardian_key_of).collect(),
        threshold,
        WINDOW,
        0,
        0,
    );
    let mut ns = NearState::new(domain(), contract);
    let relayers: Vec<KeyFile> = (1..=3u8)
        .map(|i| KeyFile::from_seed(id(&format!("hawkeye{i}.test.near")), &[i; 32]))
        .collect();
    let holder = KeyFile::from_seed(id("holder.test.near"), &[9; 32]);
    for k in relayers.iter().chain([&holder]) {
        ns.add_access_key(k.account_id.as_str(), k.public_key());
    }
    let near = MockNear::start(ns).await.unwrap();

    let mut st = MockState::new();
    let admit = st.new_wallet_key();
    let set = st.add_set(SetParams {
        seats: 3,
        unlockthreshold: 1,
        cancelthreshold: 1,
        slashthreshold: 2,
        open: false,
        ratelimitbps: 0,
        ratewindow: 20,
        livenesswindow: 1000,
        bondmin: Amount(100_000_000),
        bondlockmin: 0,
        maturity: 0,
        admitkey: admit,
    });
    for k in &keys {
        st.add_member(&set, PubKey(k.public_key()), true);
    }
    st.mine(1);
    let mock = MockYcashd::start_with(st).await.unwrap();
    Env {
        mode,
        mock,
        near,
        set,
        keys,
        relayers,
        holder,
        dir: tempfile::tempdir().unwrap(),
    }
}

impl Env {
    fn params(&self) -> Params {
        Params {
            network: Network::Regtest,
            mainnet: false,
            set_id: self.set.0,
            bridge_kind: BridgeKind::Near,
            deployment: domain().deployment(),
            eth_start_block: 1,
            delay: DELAY,
            confirmations: C_Y,
            min_owner_age: 400,
            roll_margin: 50,
            takeover: TAKEOVER,
            heartbeat_blocks: 10,
            min_lock: 10_000_000,
            max_lock: 100_000_000_000,
            mint_mode: self.mode,
            auto_slash: true,
            drills: true,
            ycash_start_height: Some(1),
        }
    }

    /// A `wyec-near` client sending as `key`.
    fn client(&self, key: &KeyFile) -> WyecNear {
        WyecNear::new(&self.near.url(), domain(), Some(key.clone()), DEFAULT_GAS).unwrap()
    }

    fn chain(&self, i: usize) -> NearChain {
        NearChain::new(self.client(&self.relayers[i]))
    }

    /// Attestor `i`'s engine over the ledger file `attestor<i>.db`.
    fn engine(&self, i: usize) -> Engine {
        let key = self.keys[i].clone();
        let store = Store::open(self.dir.path().join(format!("attestor{i}.db"))).unwrap();
        Engine::new(Ctx {
            params: Arc::new(self.params()),
            me: key.public_key(),
            foreign: Arc::new(self.chain(i)),
            key,
            ycash: Arc::new(self.mock.client()),
            store: Arc::new(Mutex::new(store)),
            attributor: Arc::new(MockAttributor { set: self.set.0 }),
            peers: Peers::new(vec![]).unwrap(),
            status: Arc::new(RwLock::new(Status::default())),
            network_name: "regtest".into(),
        })
    }

    fn three(&self) -> Vec<Engine> {
        (0..3).map(|i| self.engine(i)).collect()
    }

    fn mine(&self, n: u32) {
        self.mock.state().mine(n);
    }

    fn near_blocks(&self, n: u64) {
        self.near.state().produce_blocks(n);
    }

    /// A deposit of `value` zat to NEAR account `to`: a real §15.3 `NYEC` V plus the `NR1`
    /// destination `OP_RETURN`, mined.
    fn lock(&self, value: i64, to: &AccountId) -> CoreOutPoint {
        let (owner, tip) = {
            let mut st = self.mock.state();
            (st.new_wallet_key(), st.tip_height())
        };
        let vp = VaultParams {
            tag: TAG_NYEC,
            set_id: self.set.0,
            cancel_set_id: self.set.0,
            delay: DELAY,
            owner_height: tip + 1000,
            app_height: 0,
            owner_key: owner.0,
        };
        let script = vp.script().unwrap();
        self.mock.state().register_script(
            script.clone(),
            KnownScript::Vault(VaultFields {
                tag: HexBytes(b"NYEC".to_vec()),
                tagtext: "NYEC".into(),
                setid: self.set,
                cancelsetid: self.set,
                delay: u32::from(DELAY),
                ownerheight: vp.owner_height,
                appheight: 0,
                ownerkey: PubKey(vp.owner_key),
            }),
        );
        let mut st = self.mock.state();
        let tx = Transaction::new_v4(
            vec![TxIn {
                prevout: OutPoint::new(Hash256([0xc1; 32]), tip),
                script_sig: vec![0x51],
                sequence: u32::MAX,
            }],
            vec![
                TxOut {
                    value,
                    script_pubkey: script,
                },
                TxOut {
                    value: 0,
                    script_pubkey: hawkeye_core::lock::near_destination_script(to),
                },
            ],
            0,
            0,
        );
        let txid = st.submit(tx.encode()).unwrap();
        st.mine(1);
        CoreOutPoint::new(txid.0, 0)
    }

    fn key_of_index(&self, i: usize) -> [u8; 33] {
        self.keys[i].public_key()
    }

    fn mint_sig(&self, i: usize, lock: &[u8; 32], amount: u128, to: &AccountId) -> [u8; 65] {
        let d = domain().digest(&BridgeMessage::Mint {
            lock_id: *lock,
            amount,
            receiver_id: to.clone(),
        });
        sign_digest(&self.keys[i], &d).unwrap()
    }
}

async fn tick_all(engines: &mut [Engine]) {
    for e in engines.iter_mut() {
        let r = e.tick().await;
        assert!(r.errors.is_empty(), "tick errors: {:?}", r.errors);
    }
}

/// Ticks with NEAR blocks produced in between, no Ycash blocks.
async fn near_rounds(env: &Env, engines: &mut [Engine], n: usize) {
    for _ in 0..n {
        tick_all(engines).await;
        env.near_blocks(2);
    }
    tick_all(engines).await;
}

async fn drive_mint(env: &Env, engines: &mut [Engine], op: &CoreOutPoint) -> [u8; 32] {
    let lock_id = hawkeye_core::lock::lock_id(op);
    tick_all(engines).await;
    env.mine(C_Y);
    near_rounds(env, engines, 3).await;
    lock_id
}

fn open_cases(e: &Engine) -> Vec<hawkeye_store::SlashCaseRecord> {
    e.ctx()
        .db(|t| {
            let mut v = vec![];
            for s in [
                SlashState::Opened,
                SlashState::Voted,
                SlashState::Submitted,
                SlashState::Slashed,
            ] {
                v.extend(t.slash_cases_in_state(s)?);
            }
            Ok(v)
        })
        .unwrap()
}

fn challenges(e: &Engine) -> Vec<hawkeye_store::ChallengeSignRecord> {
    e.ctx().db(|t| t.challenge_signatures()).unwrap()
}

/// The successful NEAR transactions calling `method` alone.
fn sent_ok(env: &Env, method: &str) -> Vec<hawkeye_near::mock::Sent> {
    env.near
        .state()
        .sent
        .iter()
        .filter(|s| s.methods == [method] && s.error.is_none())
        .cloned()
        .collect()
}

fn holder_account(env: &Env) -> AccountId {
    env.holder.account_id.clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lock_sign_threshold_mint_observed() {
    let env = setup(MintMode::Threshold { k: 1 }).await;
    let mut engines = env.three();
    let to = holder_account(&env);
    let op = env.lock(1_000_000_000, &to);
    let lock_id = drive_mint(&env, &mut engines, &op).await;
    let c = env.client(&env.holder);
    assert_eq!(c.balance_of(&to).await.unwrap(), 1_000_000_000);
    assert!(c.is_consumed(&lock_id).await.unwrap());
    for e in &engines {
        let (l, sig) = e
            .ctx()
            .db(|t| Ok((t.lock(&lock_id)?.unwrap(), t.mint_signature(&lock_id)?)))
            .unwrap();
        assert_eq!(
            l.state,
            LockState::Minted,
            "every attestor observes the mint"
        );
        assert_eq!(
            l.destination,
            Some(hawkeye_core::Destination::Near(to.clone()))
        );
        let sig = sig.expect("every attestor signed once");
        // the stored signature is the NEAR attestation: Borsh-SHA256 digest, v ∈ {0, 1}
        let d = domain().digest(&BridgeMessage::Mint {
            lock_id,
            amount: 1_000_000_000,
            receiver_id: to.clone(),
        });
        assert_eq!(sig.digest, d);
        assert!(sig.signature[64] <= 1);
        assert!(e.alarms().is_empty(), "{:?}", e.alarms());
    }
    // exactly one mint transaction (the leader's), sent by a relayer, never by a member key
    let mints = sent_ok(&env, "mint");
    assert_eq!(mints.len(), 1);
    assert!(mints[0].signer.starts_with("hawkeye"));
    // the status names the foreign chain and the guardian key; the old fields stay
    let s = engines[0].snapshot().await.unwrap();
    assert_eq!(s.foreign_kind, "near");
    assert_eq!(
        s.guardian,
        format!("0x{}", hex::encode(guardian_key_of(&env.keys[0])))
    );
    assert_eq!(s.eth_address, s.guardian);
    assert_eq!(s.ethereum, s.foreign);
    assert!(s.foreign.cursor > 0 && s.foreign.tip >= s.foreign.cursor);
    assert_eq!(s.supply.wyec_total_supply, 1_000_000_000);
    let json = serde_json::to_value(&s).unwrap();
    for k in [
        "eth_address",
        "ethereum",
        "guardian",
        "foreign",
        "foreign_kind",
    ] {
        assert!(json.get(k).is_some(), "{k}");
    }
}

/// Mint 10 YEC to the holder, then burn 4 to a Ycash address from the holder's NEAR account.
async fn mint_then_burn(
    env: &Env,
    engines: &mut [Engine],
) -> (u64, hawkeye_core::near::BurnRecord) {
    let to = holder_account(env);
    let op = env.lock(1_000_000_000, &to);
    drive_mint(env, engines, &op).await;
    let c = env.client(&env.holder);
    let r = YcashRecipient::p2pkh([0x77; 20]);
    let (_, nonce) = c.burn(400_000_000, &r.to_bytes32()).await.unwrap();
    let rec = env.near.state().contract.burns[nonce as usize].clone();
    env.near_blocks(2);
    (nonce, rec)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_burn_unlock_hkn1_memo_release() {
    let env = setup(MintMode::Threshold { k: 1 }).await;
    let mut engines = env.three();
    let (nonce, rec) = mint_then_burn(&env, &mut engines).await;
    tick_all(&mut engines).await;
    tick_all(&mut engines).await;
    let dep = domain().deployment();
    // exactly one unlock in the mempool, carrying the HKN1 memo naming the burn record
    let (memo, unlocks) = {
        let st = env.mock.state();
        let txs: Vec<Transaction> = st
            .mempool
            .iter()
            .map(|t| Transaction::decode(&st.txs[t].0).unwrap())
            .filter(|t| t.op_returns().count() == 1)
            .collect();
        let memo = txs.iter().find_map(|t| {
            t.outputs.iter().find_map(|o| {
                parse_memo_script_for(BridgeKind::Near, &o.script_pubkey)
                    .ok()
                    .flatten()
            })
        });
        (memo, txs.len())
    };
    assert_eq!(unlocks, 1, "one leader, one unlock");
    let memo = memo.expect("HKN1 memo");
    assert_eq!(memo.kind, MemoKind::BurnRelease);
    assert_eq!(memo.reference, nonce);
    assert_eq!(memo.deployment, dep);
    assert_eq!(memo.data, rec.hash(), "data = SHA256(borsh(BurnRecord))");
    // the ledger keys the burn by the record hash, with the NEAR burner
    let k = BurnKey::new(dep, nonce);
    let b = engines[1].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    assert_eq!(b.tx_hash, rec.hash());
    assert_eq!(
        b.from,
        hawkeye_core::Destination::Near(holder_account(&env))
    );
    env.mine(1);
    tick_all(&mut engines).await;
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::IntentConfirmed);
    }
    for _ in 0..=u32::from(DELAY) {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::Released, "released after the delay");
        let released = e
            .ctx()
            .db(|t| t.intents_in_state(IntentState::Released))
            .unwrap();
        assert_eq!(released.len(), 1);
        assert!(open_cases(e).is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d_restart_mid_flow_signs_once() {
    let env = setup(MintMode::Threshold { k: 1 }).await;
    let mut engines = env.three();
    let to = holder_account(&env);
    let op = env.lock(1_000_000_000, &to);
    let lock_id = hawkeye_core::lock::lock_id(&op);
    tick_all(&mut engines).await;
    env.mine(C_Y);
    // one tick: every attestor signs; the leader mints
    tick_all(&mut engines).await;
    let before: Vec<_> = engines
        .iter()
        .map(|e| e.ctx().db(|t| t.mint_signature(&lock_id)).unwrap().unwrap())
        .collect();
    drop(engines);
    let mut engines = env.three();
    near_rounds(&env, &mut engines, 3).await;
    for (e, b) in engines.iter().zip(&before) {
        let after = e.ctx().db(|t| t.mint_signature(&lock_id)).unwrap().unwrap();
        assert_eq!(&after, b, "the stored attestation is reused, not remade");
        assert_eq!(
            e.ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap().state,
            LockState::Minted
        );
    }
    assert_eq!(
        sent_ok(&env, "mint").len(),
        1,
        "one mint, whatever the restart"
    );
}

/// A member's key proposes a lockId with no lock behind it, from the holder's relayer account.
async fn rogue_proposal(env: &Env, r: usize, fake: [u8; 32], amount: u128) {
    let to = holder_account(env);
    let sig = env.mint_sig(r, &fake, amount, &to);
    env.client(&env.holder)
        .propose_mint(&fake, amount, &to, &sig)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn j_optimistic_proposal_without_lock_challenged_and_vetoed() {
    let env = setup(MintMode::Optimistic).await;
    let mut engines = env.three();
    let r = 1;
    let fake = [0xcd; 32];
    rogue_proposal(&env, r, fake, 700_000_000).await;
    let c = env.client(&env.holder);
    assert!(c.proposal(&fake).await.unwrap().is_some());
    env.near_blocks(2);
    tick_all(&mut engines).await;
    for _ in 0..25 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    assert!(
        c.proposal(&fake).await.unwrap().is_none(),
        "challenged before its window ends"
    );
    assert!(
        c.is_vetoed(&fake, &guardian_key_of(&env.keys[r]))
            .await
            .unwrap(),
        "the rogue proposer is barred from the lockId"
    );
    for (i, e) in engines.iter().enumerate() {
        if i == r {
            continue;
        }
        let cases = open_cases(e);
        assert!(
            cases
                .iter()
                .any(|c| c.fault == hawkeye_store::FaultKind::FraudulentMint
                    && c.target_key == env.key_of_index(r)),
            "attestor {i}: {cases:?}"
        );
        // the evidence carries the recovered NEAR guardian and the proposal's receipt
        let ev: serde_json::Value = serde_json::from_str(
            &cases
                .iter()
                .find(|c| c.target_key == env.key_of_index(r))
                .unwrap()
                .evidence_json,
        )
        .unwrap();
        assert_eq!(
            ev["signer"],
            format!("0x{}", hex::encode(guardian_key_of(&env.keys[r])))
        );
        assert_eq!(ev["to"], holder_account(&env).as_str());
    }
    // the challenge went in once (any one guardian's suffices), signed once per attestor
    assert_eq!(sent_ok(&env, "challenge_mint").len(), 1);
    for e in &engines {
        assert!(challenges(e).len() <= 1);
    }
    env.near.state().warp(WINDOW);
    near_rounds(&env, &mut engines, 1).await;
    assert_eq!(c.total_supply().await.unwrap(), 0, "no wYEC exists");
}

/// The contract's optimistic path cannot be switched off: in threshold mode the watchers still
/// challenge a one-key proposal with no lock behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn j2_threshold_mode_watchers_still_challenge() {
    let env = setup(MintMode::Threshold { k: 1 }).await;
    let mut engines = env.three();
    let fake = [0xce; 32];
    rogue_proposal(&env, 0, fake, 300_000_000).await;
    env.near_blocks(2);
    for _ in 0..C_Y + 1 {
        tick_all(&mut engines).await;
        env.mine(1);
    }
    tick_all(&mut engines).await;
    let c = env.client(&env.holder);
    assert!(
        c.proposal(&fake).await.unwrap().is_none(),
        "challenged C_Y blocks after it was judged, long before the window ends"
    );
    env.near.state().warp(WINDOW);
    tick_all(&mut engines).await;
    assert_eq!(c.total_supply().await.unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l_optimistic_propose_window_execute() {
    let env = setup(MintMode::Optimistic).await;
    let mut engines = env.three();
    let to = holder_account(&env);
    let op = env.lock(1_000_000_000, &to);
    let lock_id = drive_mint(&env, &mut engines, &op).await;
    let c = env.client(&env.holder);
    let p = c.proposal(&lock_id).await.unwrap().expect("proposed");
    assert_eq!((p.id, p.amount, &p.receiver_id), (1, 1_000_000_000, &to));
    assert!(
        (0..3).any(|i| guardian_key_of(&env.keys[i]) == p.proposer),
        "an attestor proposed"
    );
    for e in &engines {
        let l = e.ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap();
        assert_eq!(
            l.state,
            LockState::Proposed,
            "every attestor sees the proposal"
        );
        assert!(
            challenges(e).is_empty(),
            "a matching proposal is never challenged"
        );
    }
    // nothing executes inside the window
    near_rounds(&env, &mut engines, 2).await;
    assert_eq!(c.total_supply().await.unwrap(), 0);
    // after it, the leader executes and everyone observes the mint
    env.near.state().warp(WINDOW);
    near_rounds(&env, &mut engines, 3).await;
    assert_eq!(c.balance_of(&to).await.unwrap(), 1_000_000_000);
    assert_eq!(c.config().await.unwrap().proposal_count, 1, "proposed once");
    for e in &engines {
        let l = e.ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap();
        assert_eq!(l.state, LockState::Minted);
        assert!(e.alarms().is_empty(), "{:?}", e.alarms());
        assert!(challenges(e).is_empty());
        assert!(open_cases(e).is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m_challenged_matching_proposal_is_reproposed_by_another() {
    let env = setup(MintMode::Optimistic).await;
    let mut engines = env.three();
    let to = holder_account(&env);
    let op = env.lock(1_000_000_000, &to);
    let lock_id = drive_mint(&env, &mut engines, &op).await;
    let c = env.client(&env.holder);
    let first = c.proposal(&lock_id).await.unwrap().unwrap();
    // one guardian challenges the correct proposal anyway (griefing); the holder submits it
    let griefer = (0..3)
        .find(|i| guardian_key_of(&env.keys[*i]) != first.proposer)
        .unwrap();
    let d = domain().digest(&BridgeMessage::Challenge {
        lock_id,
        proposal_id: first.id,
    });
    c.challenge_mint(
        &lock_id,
        first.id,
        &sign_digest(&env.keys[griefer], &d).unwrap(),
    )
    .await
    .unwrap();
    assert!(c.is_vetoed(&lock_id, &first.proposer).await.unwrap());
    near_rounds(&env, &mut engines, 3).await;
    let second = c.proposal(&lock_id).await.unwrap().expect("re-proposed");
    assert_eq!(second.id, 2);
    assert_ne!(
        second.proposer, first.proposer,
        "the barred proposer stood aside"
    );
    for e in &engines {
        assert!(
            e.alarms()
                .iter()
                .any(|a| a.name == "matching-proposal-challenged"),
            "{:?}",
            e.alarms()
        );
        assert!(
            challenges(e).is_empty(),
            "nobody challenges the re-proposal"
        );
    }
    env.near.state().warp(WINDOW);
    near_rounds(&env, &mut engines, 3).await;
    assert_eq!(c.balance_of(&to).await.unwrap(), 1_000_000_000);
    for e in &engines {
        assert_eq!(
            e.ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap().state,
            LockState::Minted
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_wrong_amount_proposal_on_a_real_lock_challenged() {
    let env = setup(MintMode::Optimistic).await;
    let mut engines = env.three();
    let to = holder_account(&env);
    let op = env.lock(1_000_000_000, &to);
    let lock_id = hawkeye_core::lock::lock_id(&op);
    env.mine(C_Y);
    // before any attestor acts, member r proposes the real lockId with a wrong amount
    let r = 1;
    let sig = env.mint_sig(r, &lock_id, 9_000_000_000, &to);
    let c = env.client(&env.holder);
    c.propose_mint(&lock_id, 9_000_000_000, &to, &sig)
        .await
        .unwrap();
    env.near_blocks(2);
    near_rounds(&env, &mut engines, 4).await;
    let p = c
        .proposal(&lock_id)
        .await
        .unwrap()
        .expect("the correct proposal");
    assert_eq!(p.amount, 1_000_000_000);
    assert_ne!(p.proposer, guardian_key_of(&env.keys[r]));
    let challenged: usize = engines.iter().map(|e| challenges(e).len()).sum();
    assert!(challenged >= 1);
    for (i, e) in engines.iter().enumerate() {
        for ch in challenges(e) {
            assert_eq!(
                ch.amount, 9_000_000_000,
                "only the wrong proposal is challenged"
            );
        }
        if i != r {
            assert!(
                open_cases(e)
                    .iter()
                    .any(|c| c.fault == hawkeye_store::FaultKind::FraudulentMint
                        && c.target_key == env.key_of_index(r)),
                "attestor {i}"
            );
        }
    }
    env.near.state().warp(WINDOW);
    near_rounds(&env, &mut engines, 3).await;
    assert_eq!(c.total_supply().await.unwrap(), 1_000_000_000);
}

/// NEAR skips heights; the scan cursor crosses them (a range may end on one), and a burn on the
/// far side is still found once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s_scanner_crosses_skipped_heights() {
    let env = setup(MintMode::Threshold { k: 1 }).await;
    let mut engines = env.three();
    let to = holder_account(&env);
    let op = env.lock(1_000_000_000, &to);
    drive_mint(&env, &mut engines, &op).await;
    env.near.state().skip_heights(5);
    let c = env.client(&env.holder);
    let r = YcashRecipient::p2pkh([0x55; 20]);
    let (_, nonce) = c.burn(100_000_000, &r.to_bytes32()).await.unwrap();
    env.near.state().skip_heights(3);
    env.near_blocks(1);
    near_rounds(&env, &mut engines, 2).await;
    let k = BurnKey::new(domain().deployment(), nonce);
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert!(b.state != BurnState::Seen);
        let s = e.ctx().status.read().unwrap().clone();
        assert_eq!(s.foreign.cursor, s.foreign.tip, "caught up across the gaps");
    }
    // the adapter's own view of the chain agrees
    let chain = env.chain(0);
    assert_eq!(
        chain.finalized_height().await.unwrap(),
        env.near.state().head().height
    );
}
