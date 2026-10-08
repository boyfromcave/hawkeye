//! Engine tests (plan §9 H4/H5): three Hawkeye engines against one mock ycashd (hawkeye-ycash
//! feature `mock`) and a local anvil with wYEC deployed. Ticks are driven by hand, blocks are
//! mined by hand on both chains, so every run is deterministic.
//!
//! (a) lock → sign → mint observed; (b) burn → unlock with the HKB1 memo → release after the
//! delay; (c) rogue intent → cancelled + slash case → SET_REMOVE; (d) restart mid-flow: no second
//! signature; (e) leader takeover; (f) slash votes verified independently by each peer (refused
//! for a matched intent, a benign race, a wrong target, one's own removal, a backed mint);
//! (g) restart resumes a slash case and a deferred mint check without re-asking or re-signing;
//! (h) two cancels of one intent by one key → `SET_EQUIVOCATION`; (i) rolls (HK-6): a vault near
//! `ownerHeight` is rolled into a later one, not cancelled; an invalid roll is cancelled and
//! slashed; (j) an optimistic proposal with no lock is challenged and its proposer faces a case,
//! in optimistic and (j2) threshold mode alike; (k) `POST /unlock/sign` co-signs only a burn ↔
//! memo match, once; (l) optimistic happy path: the leader proposes, nobody challenges, the leader
//! executes after the window; (m) a matching proposal challenged anyway (griefing) is re-proposed
//! by another attestor (the challenged proposer is `vetoed`) and executed; (n) a wrong-amount
//! proposal squatting a real lock is challenged, its proposer faces a case, and the right mint
//! follows.
//!
//! Skipped without `anvil` on PATH unless `HAWKEYE_REQUIRE_ANVIL=1`.

use std::borrow::Cow;
use std::sync::{Arc, Mutex, RwLock};

use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::providers::{DynProvider, Provider};
use hawkeye::attribution::Attributor;
use hawkeye::config::Params;
use hawkeye::engine::{Ctx, Engine};
use hawkeye::keys::eth_signer;
use hawkeye::peers::Peers;
use hawkeye::status::Status;
use hawkeye_core::address::Network;
use hawkeye_core::attribution::{Attribution, SetSigner};
use hawkeye_core::memo::parse_memo_script;
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_core::setsig::Role;
use hawkeye_core::template::{TAG_WYEC, VaultParams};
use hawkeye_core::{Deployment as CoreDeployment, EthAddress, OutPoint as CoreOutPoint, SecretKey};
use hawkeye_eth::{
    Address, B256, DeployParams, Deployment, EthClient, EthConfig, MintMode, PrivateKeySigner,
    U256, deploy, wallet_provider,
};
use hawkeye_store::{BurnKey, BurnState, IntentState, LockState, SlashState, Store, VaultState};
use hawkeye_ycash::mock::{KnownScript, MockState, MockYcashd};
use hawkeye_ycash::tx::{Transaction, TxIn, TxOut};
use hawkeye_ycash::types::{BuildAct, MemberStatus, SetParams, VaultFields};
use hawkeye_ycash::{Amount, Hash256, HexBytes, OutPoint, PubKey};

/// The mock's set signatures are `0x1f ‖ key ‖ sighash[..31]`: attribute by reading the key.
/// A real §15.3 V spent with selector 1 is an UNLOCK; anything else (the mock's placeholder I)
/// spent with selector 2 is a CANCEL under `set`.
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
/// The bridge's challenge window in these tests, seconds (time is advanced with
/// `evm_increaseTime`).
const WINDOW: u64 = 3600;
const C_Y: u32 = 2;
const TAKEOVER: u32 = 4;

/// Per-test knobs.
#[derive(Clone, Copy)]
struct Opts {
    mode: MintMode,
    min_owner_age: u32,
    roll_margin: u32,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            mode: MintMode::Threshold { k: 1 },
            min_owner_age: 400,
            roll_margin: 50,
        }
    }
}

struct Env {
    opts: Opts,
    _anvil: AnvilInstance,
    url: String,
    mock: MockYcashd,
    set: Hash256,
    keys: Vec<SecretKey>,
    holder: SecretKey,
    dep: Deployment,
    provider: DynProvider,
    dir: tempfile::TempDir,
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

fn secret(i: u8) -> SecretKey {
    let mut s = [0u8; 32];
    s[0] = 0x42;
    s[31] = i;
    SecretKey::from_bytes(&s).unwrap()
}

async fn set_balance(p: &DynProvider, who: Address) {
    let _: serde_json::Value = p
        .raw_request(
            Cow::Borrowed("anvil_setBalance"),
            (who, U256::from(10u128.pow(21))),
        )
        .await
        .unwrap();
}

async fn setup() -> Option<Env> {
    setup_with(Opts::default()).await
}

async fn setup_with(opts: Opts) -> Option<Env> {
    if !on_path("anvil") {
        assert!(
            std::env::var("HAWKEYE_REQUIRE_ANVIL").as_deref() != Ok("1"),
            "HAWKEYE_REQUIRE_ANVIL=1 but `anvil` is not on PATH"
        );
        eprintln!("skipping: `anvil` is not on PATH");
        return None;
    }
    let anvil = Anvil::new()
        .args(["--slots-in-an-epoch", "1"])
        .try_spawn()
        .expect("spawn anvil");
    let deployer =
        PrivateKeySigner::from_bytes(&B256::from_slice(&anvil.keys()[0].to_bytes())).unwrap();
    let keys: Vec<SecretKey> = (1..=3).map(secret).collect();
    let holder = secret(9);
    let guardians: Vec<Address> = keys
        .iter()
        .map(|k| hawkeye::convert::addr(&k.eth_address()))
        .collect();
    let provider = wallet_provider(&anvil.endpoint(), deployer.clone()).unwrap();
    // threshold mode deploys at its k; optimistic mode at 2 (the mainnet rule, plan §3.3)
    let threshold = match opts.mode {
        MintMode::Threshold { k } => k,
        MintMode::Optimistic => 2,
    };
    let dep = deploy(
        &provider,
        deployer.address(),
        &DeployParams::new(&guardians, threshold, WINDOW, opts.mode),
    )
    .await
    .unwrap();
    for k in keys.iter().chain([&holder]) {
        set_balance(&provider, hawkeye::convert::addr(&k.eth_address())).await;
    }
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
    Some(Env {
        opts,
        url: anvil.endpoint(),
        _anvil: anvil,
        mock,
        set,
        keys,
        holder,
        dep,
        provider,
        dir: tempfile::tempdir().unwrap(),
    })
}

impl Env {
    fn params(&self) -> Params {
        Params {
            network: Network::Regtest,
            mainnet: false,
            set_id: self.set.0,
            deployment: CoreDeployment {
                chain_id: 31337,
                bridge: EthAddress(self.dep.bridge.0.0),
            },
            eth_start_block: self.dep.deploy_block,
            delay: DELAY,
            confirmations: C_Y,
            min_owner_age: self.opts.min_owner_age,
            roll_margin: self.opts.roll_margin,
            takeover: TAKEOVER,
            heartbeat_blocks: 10,
            min_lock: 10_000_000,
            max_lock: 100_000_000_000,
            mint_mode: self.opts.mode,
            auto_slash: true,
            drills: true,
            ycash_start_height: Some(1),
        }
    }

    async fn eth(&self, key: &SecretKey) -> EthClient {
        let mut c = EthConfig::new(self.url.clone(), 31337, self.dep.bridge);
        c.token = Some(self.dep.token);
        EthClient::connect(&c, Some(eth_signer(key).unwrap()))
            .await
            .unwrap()
    }

    /// Attestor `i`'s engine over the ledger file `attestor<i>.db`.
    async fn engine(&self, i: usize) -> Engine {
        let key = self.keys[i].clone();
        let store = Store::open(self.dir.path().join(format!("attestor{i}.db"))).unwrap();
        Engine::new(Ctx {
            params: Arc::new(self.params()),
            me: key.public_key(),
            eth: self.eth(&key).await,
            key,
            ycash: Arc::new(self.mock.client()),
            store: Arc::new(Mutex::new(store)),
            attributor: Arc::new(MockAttributor { set: self.set.0 }),
            peers: Peers::new(vec![]).unwrap(),
            status: Arc::new(RwLock::new(Status::default())),
            network_name: "regtest".into(),
        })
    }

    fn mine(&self, n: u32) {
        self.mock.state().mine(n);
    }

    /// Advance anvil's clock by `seconds` and mine a block.
    async fn warp(&self, seconds: u64) {
        let _: serde_json::Value = self
            .provider
            .raw_request(Cow::Borrowed("evm_increaseTime"), (U256::from(seconds),))
            .await
            .unwrap();
        self.eth_mine(1).await;
    }

    async fn eth_mine(&self, n: u64) {
        let _: serde_json::Value = self
            .provider
            .raw_request(Cow::Borrowed("anvil_mine"), (U256::from(n),))
            .await
            .unwrap();
    }

    /// A deposit of `value` zat to `to`: a real §15.3 V plus the destination OP_RETURN, mined.
    fn lock(&self, value: i64, to: &EthAddress) -> CoreOutPoint {
        self.lock_aged(value, to, 1000).0
    }

    /// Make the mock index a real §15.3 V script (it only indexes scripts it knows).
    fn register_vault(&self, vp: &VaultParams) {
        self.mock.state().register_script(
            vp.script().unwrap(),
            KnownScript::Vault(VaultFields {
                tag: HexBytes(b"WYEC".to_vec()),
                tagtext: "WYEC".into(),
                setid: self.set,
                cancelsetid: self.set,
                delay: u32::from(DELAY),
                ownerheight: vp.owner_height,
                appheight: 0,
                ownerkey: PubKey(vp.owner_key),
            }),
        );
    }

    /// A deposit whose `ownerHeight` is `owner_age` above the current tip.
    fn lock_aged(
        &self,
        value: i64,
        to: &EthAddress,
        owner_age: u32,
    ) -> (CoreOutPoint, VaultParams) {
        let (owner, tip) = {
            let mut st = self.mock.state();
            (st.new_wallet_key(), st.tip_height())
        };
        let vp = VaultParams {
            tag: TAG_WYEC,
            set_id: self.set.0,
            cancel_set_id: self.set.0,
            delay: DELAY,
            owner_height: tip + owner_age,
            app_height: 0,
            owner_key: owner.0,
        };
        let script = vp.script().unwrap();
        self.register_vault(&vp);
        let mut st = self.mock.state();
        let tx = Transaction::new_v4(
            vec![TxIn {
                prevout: OutPoint::new(Hash256([0xc0; 32]), tip),
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
                    script_pubkey: hawkeye_core::lock::destination_script(to),
                },
            ],
            0,
            0,
        );
        let txid = st.submit(tx.encode()).unwrap();
        st.mine(1);
        (CoreOutPoint::new(txid.0, 0), vp)
    }

    async fn burn(&self, amount: u64, recipient: &YcashRecipient) -> u64 {
        let c = self.eth(&self.holder).await;
        let b = c
            .burn(U256::from(amount), B256::from(recipient.to_bytes32()))
            .await
            .unwrap();
        u64::try_from(b.nonce).unwrap()
    }

    fn key_of_index(&self, i: usize) -> [u8; 33] {
        self.keys[i].public_key()
    }
}

async fn tick_all(engines: &mut [Engine]) {
    for e in engines.iter_mut() {
        let r = e.tick().await;
        assert!(r.errors.is_empty(), "tick errors: {:?}", r.errors);
    }
}

fn dep_of(e: &Engine) -> CoreDeployment {
    e.ctx().params.deployment
}

/// Lock 10 YEC to the holder and drive every engine until it is minted.
async fn lock_and_mint(env: &Env, engines: &mut [Engine]) -> [u8; 32] {
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    drive_mint(env, engines, &op).await
}

async fn drive_mint(env: &Env, engines: &mut [Engine], op: &CoreOutPoint) -> [u8; 32] {
    let lock_id = hawkeye_core::lock::lock_id(op);
    tick_all(engines).await;
    env.mine(C_Y);
    for _ in 0..3 {
        tick_all(engines).await;
        env.eth_mine(3).await;
    }
    tick_all(engines).await;
    lock_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lock_sign_mint_observed() {
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    let lock_id = lock_and_mint(&env, &mut engines).await;
    let c = env.eth(&env.holder).await;
    assert_eq!(
        c.balance_of(hawkeye::convert::addr(&env.holder.eth_address()))
            .await
            .unwrap(),
        U256::from(1_000_000_000u64)
    );
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
        assert!(sig.is_some(), "every attestor signed once");
    }
    // the watcher is quiet: no slash case, no alarm
    for e in &engines {
        assert!(e.alarms().is_empty(), "{:?}", e.alarms());
    }
    // the API: the lock with this attestor's signature; a slash vote it cannot verify is refused
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = hawkeye::api::router(engines[0].ctx().clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let peers = Peers::new(vec![format!("http://{addr}")]).unwrap();
    let view = peers
        .lock(&peers.urls()[0], &format!("0x{}", hex::encode(lock_id)))
        .await
        .unwrap();
    assert_eq!(view.state, "MINTED");
    let sig = hex::decode(view.signature.unwrap().trim_start_matches("0x")).unwrap();
    let digest = hawkeye_core::eip712::Domain::new(31337, EthAddress(env.dep.bridge.0.0))
        .mint_digest(&lock_id, 1_000_000_000, &env.holder.eth_address());
    assert_eq!(
        hawkeye_core::eth::recover_address(&digest, &sig).unwrap(),
        env.keys[0].eth_address()
    );
    // a removal for a fault this attestor cannot re-derive (the lock is minted here) is refused
    let act = env
        .mock
        .client()
        .set_buildact(&BuildAct::Remove {
            setid: env.set,
            memberkey: PubKey(env.keys[1].public_key()),
            burn: true,
        })
        .await
        .unwrap();
    let sig1 = engines[1]
        .ctx()
        .db(|t| t.mint_signature(&lock_id))
        .unwrap()
        .unwrap();
    queue_remove_decode(&env, env.keys[1].public_key());
    let refused = peers
        .slash_sign(
            &peers.urls()[0],
            &hawkeye::peers::SlashSignRequest {
                evidence: serde_json::json!({"fault": "FRAUDULENT_MINT",
                    "target": hex::encode(env.keys[1].public_key()),
                    "lock_id": format!("0x{}", hex::encode(lock_id)),
                    "amount": 1_000_000_000u64,
                    "to": env.holder.eth_address().to_checksum(),
                    "signature": format!("0x{}", hex::encode(sig1.signature))}),
                act: act.hex.to_string(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("is MINTED here: not a fault"), "{refused}");
}

/// Drive a burn of 4 YEC to completion; returns the nonce.
async fn burn_and_release(env: &Env, engines: &mut [Engine], ticking: &[usize]) -> u64 {
    let r = YcashRecipient::p2pkh([0x77; 20]);
    let nonce = env.burn(400_000_000, &r).await;
    env.eth_mine(3).await;
    for &i in ticking {
        engines[i].tick().await;
    }
    nonce
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_burn_unlock_memo_release() {
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    let nonce = burn_and_release(&env, &mut engines, &[0, 1, 2]).await;
    tick_all(&mut engines).await;
    // exactly one unlock in the mempool, with the HKB1 memo naming the burn
    let (memo, unlocks) = {
        let st = env.mock.state();
        let txs: Vec<Transaction> = st
            .mempool
            .iter()
            .map(|t| Transaction::decode(&st.txs[t].0).unwrap())
            .filter(|t| t.op_returns().count() == 1)
            .collect();
        let memo = txs.iter().find_map(|t| {
            t.outputs
                .iter()
                .find_map(|o| parse_memo_script(&o.script_pubkey).ok().flatten())
        });
        (memo, txs.len())
    };
    assert_eq!(unlocks, 1, "one leader, one unlock");
    let memo = memo.expect("HKB1 memo");
    assert_eq!(memo.reference, nonce);
    assert_eq!(memo.deployment, dep_of(&engines[0]));
    env.mine(1);
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::IntentConfirmed);
    }
    for _ in 0..u32::from(DELAY) {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    env.mine(1);
    tick_all(&mut engines).await;
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::Released, "released after the delay");
        let released = e
            .ctx()
            .db(|t| t.intents_in_state(IntentState::Released))
            .unwrap();
        assert_eq!(released.len(), 1);
    }
    assert!(
        env.mock
            .state()
            .calls_to("vault_release")
            .iter()
            .any(|c| c.error.is_none()),
        "a release was broadcast"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c_rogue_intent_cancelled_and_slashed() {
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    // a member signs an unlock with no burn and no memo (straight through the node)
    let rogue_key = {
        let client = env.mock.client();
        let vault = env.mock.state().templates.keys().copied().next().unwrap();
        let built = client
            .vault_buildunlock(
                &vault,
                &[hawkeye_ycash::types::Recipient::script(
                    YcashRecipient::p2pkh([0x66; 20]).script(),
                    Amount(100_000_000),
                )],
            )
            .await
            .unwrap();
        let signed = client.set_signunlock(&built.hex).await.unwrap();
        client.vault_send(&signed.hex).await.unwrap();
        signed.setsigs[0].key.0
    };
    let rogue_idx = (0..3).find(|i| env.key_of_index(*i) == rogue_key).unwrap();
    tick_all(&mut engines).await;
    // the first watcher cancelled it; the others saw that cancel in the mempool; every other
    // attestor opened a case against the signer
    let sent: usize = engines
        .iter()
        .map(|e| {
            e.ctx()
                .db(|t| t.intents_in_state(IntentState::CancelSent))
                .unwrap()
                .len()
        })
        .sum();
    assert_eq!(sent, 1, "one cancel");
    for (i, e) in engines.iter().enumerate() {
        let cases = e
            .ctx()
            .db(|t| {
                let mut v = t.slash_cases_in_state(SlashState::Opened)?;
                v.extend(t.slash_cases_in_state(SlashState::Voted)?);
                v.extend(t.slash_cases_in_state(SlashState::Submitted)?);
                Ok(v)
            })
            .unwrap();
        if i == rogue_idx {
            assert!(cases.is_empty(), "no case against oneself");
        } else {
            assert_eq!(cases.len(), 1);
            assert_eq!(cases[0].target_key, rogue_key);
        }
    }
    // the cancel is mined; the case owner's SET_REMOVE goes out and is mined
    for _ in 0..4 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    let st = env.mock.state();
    let member = st.sets[&env.set]
        .memberlist
        .iter()
        .find(|m| m.key.0 == rogue_key)
        .unwrap()
        .clone();
    drop(st);
    assert_eq!(member.status, MemberStatus::Removed);
    assert!(member.bondfrozen, "SET_REMOVE burn=1");
    for (i, e) in engines.iter().enumerate() {
        let cancelled = e
            .ctx()
            .db(|t| t.intents_in_state(IntentState::Cancelled))
            .unwrap();
        assert_eq!(cancelled.len(), 1, "attestor {i} sees the cancel mined");
        if i != rogue_idx {
            let slashed = e
                .ctx()
                .db(|t| t.slash_cases_in_state(SlashState::Slashed))
                .unwrap();
            assert_eq!(slashed.len(), 1, "attestor {i} records the removal");
        }
    }
    // one set_signcancel per watcher, never a re-funded second cancel
    assert!(env.mock.state().calls_to("set_signcancel").len() <= 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d_restart_mid_flow_signs_once() {
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    let lock_id = lock_and_mint(&env, &mut engines).await;
    let before: Vec<_> = engines
        .iter()
        .map(|e| e.ctx().db(|t| t.mint_signature(&lock_id)).unwrap().unwrap())
        .collect();
    let nonce = burn_and_release(&env, &mut engines, &[0, 1, 2]).await;
    tick_all(&mut engines).await;
    let unlock_signs = env.mock.state().calls_to("set_signunlock").len();
    assert_eq!(unlock_signs, 1);
    // crash: drop every engine with the intent in the mempool, restart from the ledger files
    drop(engines);
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    for _ in 0..3 {
        tick_all(&mut engines).await;
    }
    for (e, b) in engines.iter().zip(&before) {
        let after = e.ctx().db(|t| t.mint_signature(&lock_id)).unwrap().unwrap();
        assert_eq!(
            &after, b,
            "the stored EIP-712 signature is reused, not remade"
        );
    }
    assert_eq!(
        env.mock.state().calls_to("set_signunlock").len(),
        unlock_signs,
        "no second unlock signature after the restart"
    );
    env.mine(1);
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[0].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    assert_eq!(b.state, BurnState::IntentConfirmed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e_leader_takeover() {
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x55; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    // who leads nonce n: live members sorted by key, n mod 3
    let mut live: Vec<[u8; 33]> = (0..3).map(|i| env.key_of_index(i)).collect();
    hawkeye_core::keys::sort_members(&mut live);
    let leader = live[(nonce % 3) as usize];
    let leader_idx = (0..3).find(|i| env.key_of_index(*i) == leader).unwrap();
    let others: Vec<usize> = (0..3).filter(|i| *i != leader_idx).collect();
    // the leader is down: only the others tick
    for &i in &others {
        engines[i].tick().await;
    }
    assert!(env.mock.state().calls_to("set_signunlock").is_empty());
    for _ in 0..TAKEOVER {
        env.mine(1);
        for &i in &others {
            engines[i].tick().await;
        }
    }
    let signs = env.mock.state().calls_to("set_signunlock").len();
    assert_eq!(signs, 1, "exactly one takeover unlock");
    env.mine(1);
    for &i in &others {
        engines[i].tick().await;
    }
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    for &i in &others {
        let b = engines[i].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::IntentConfirmed);
        let intent = engines[i]
            .ctx()
            .db(|t| t.intent(&b.intent.unwrap()))
            .unwrap()
            .unwrap();
        assert!(intent.signer_key.is_some());
        assert_ne!(
            intent.signer_key,
            Some(leader),
            "the next attestor took over"
        );
    }
    // the leader comes back: it adopts the intent, posts nothing
    engines[leader_idx].tick().await;
    engines[leader_idx].tick().await;
    assert_eq!(env.mock.state().calls_to("set_signunlock").len(), 1);
    let b = engines[leader_idx]
        .ctx()
        .db(|t| t.burn(&k))
        .unwrap()
        .unwrap();
    assert_eq!(b.state, BurnState::IntentConfirmed);
    let live_vaults = engines[0]
        .ctx()
        .db(|t| t.vaults_in_state(VaultState::Live))
        .unwrap();
    assert_eq!(live_vaults.len(), 1, "the re-lock remainder");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2_leader_back_after_the_release_adopts_it() {
    // Devnet drill D-7 found this: the leader is down while another attestor takes the burn over
    // AND the intent is released. On restart it follows those Ycash blocks before it scans the
    // burn on Ethereum, so the intent first looks unmatched (unknown burn) and its release
    // "matured unmatched"; once the burn is scanned the leader must adopt that release, not
    // assign the burn to itself and post a second unlock.
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x56; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let mut live: Vec<[u8; 33]> = (0..3).map(|i| env.key_of_index(i)).collect();
    hawkeye_core::keys::sort_members(&mut live);
    let leader = live[(nonce % 3) as usize];
    let leader_idx = (0..3).find(|i| env.key_of_index(*i) == leader).unwrap();
    let others: Vec<usize> = (0..3).filter(|i| *i != leader_idx).collect();
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    // the leader is down through the takeover, the intent's delay and its release
    for _ in 0..(TAKEOVER + u32::from(DELAY) + 4) {
        for &i in &others {
            engines[i].tick().await;
        }
        env.mine(1);
    }
    for &i in &others {
        engines[i].tick().await;
        let b = engines[i].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::Released, "released by the takeover");
    }
    assert_eq!(env.mock.state().calls_to("set_signunlock").len(), 1);
    // the leader comes back
    for _ in 0..(3 * TAKEOVER) {
        let rep = engines[leader_idx].tick().await;
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        env.mine(1);
    }
    assert_eq!(
        env.mock.state().calls_to("set_signunlock").len(),
        1,
        "the returning leader posted the burn again"
    );
    let e = &engines[leader_idx];
    let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    assert_eq!(b.state, BurnState::Released, "the release is adopted");
    let intent = e
        .ctx()
        .db(|t| t.intent(&b.intent.unwrap()))
        .unwrap()
        .unwrap();
    assert_eq!(intent.state, IntentState::Released);
    assert_eq!(intent.classification.as_deref(), Some("matched-burn"));
    assert!(intent.released_txid.is_some());
    assert!(open_cases(e).is_empty(), "nobody to blame");
}

// ------------------------------------------------------------------------------------------
// helpers for (f)–(k)

async fn three(env: &Env) -> Vec<Engine> {
    vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ]
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

fn index_of(env: &Env, key: &[u8; 33]) -> usize {
    (0..3).find(|i| env.key_of_index(*i) == *key).unwrap()
}

/// A member signs an unlock with no burn and no memo straight through the node; returns the
/// intent and the signer.
async fn rogue_unlock(env: &Env) -> (CoreOutPoint, [u8; 33]) {
    let client = env.mock.client();
    let vault = {
        let st = env.mock.state();
        *st.templates
            .iter()
            .find(|(_, t)| t.valuezat() >= 100_000_000 && t.as_vault().is_some())
            .map(|(op, _)| op)
            .unwrap()
    };
    let built = client
        .vault_buildunlock(
            &vault,
            &[hawkeye_ycash::types::Recipient::script(
                YcashRecipient::p2pkh([0x66; 20]).script(),
                Amount(100_000_000),
            )],
        )
        .await
        .unwrap();
    let signed = client.set_signunlock(&built.hex).await.unwrap();
    let txid = client.vault_send(&signed.hex).await.unwrap();
    (
        CoreOutPoint::new(txid.0, built.intents[0].vout),
        signed.setsigs[0].key.0,
    )
}

/// The mock's `vault_decodescript` does not decode acts: answer the next call as the node would
/// for a `SET_REMOVE burn=1` of `key` (what `POST /slash/sign` checks the act against).
fn queue_remove_decode(env: &Env, key: [u8; 33]) {
    use hawkeye_ycash::types::{ActBody, DecodedAct, DecodedScript};
    let d = DecodedScript::Act(DecodedAct::Act {
        body: Box::new(ActBody::Remove {
            setid: env.set,
            memberkey: PubKey(key),
            burn: 1,
        }),
        signatures: vec![],
        payload: HexBytes(vec![]),
    });
    env.mock
        .state()
        .queue_result("vault_decodescript", serde_json::to_value(&d).unwrap());
}

async fn remove_act(env: &Env, key: [u8; 33]) -> String {
    queue_remove_decode(env, key);
    env.mock
        .client()
        .set_buildact(&BuildAct::Remove {
            setid: env.set,
            memberkey: PubKey(key),
            burn: true,
        })
        .await
        .unwrap()
        .hex
        .to_string()
}

fn mempool_txs(env: &Env) -> Vec<Transaction> {
    let st = env.mock.state();
    st.mempool
        .iter()
        .map(|t| Transaction::decode(&st.txs[t].0).unwrap())
        .collect()
}

// ------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f_slash_votes_verified_independently() {
    use hawkeye::engine::slash::verify_and_sign;
    use hawkeye::peers::SlashSignRequest;
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    // a legitimate intent, matched to its burn
    let nonce = burn_and_release(&env, &mut engines, &[0, 1, 2]).await;
    tick_all(&mut engines).await;
    env.mine(1);
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let legit = engines[0]
        .ctx()
        .db(|t| t.burn(&k))
        .unwrap()
        .unwrap()
        .intent
        .unwrap();
    let legit_signer = engines[0]
        .ctx()
        .db(|t| t.intent(&legit))
        .unwrap()
        .unwrap()
        .signer_key
        .unwrap();
    // a rogue intent
    let (rogue_intent, rogue_key) = rogue_unlock(&env).await;
    tick_all(&mut engines).await;
    let rogue = index_of(&env, &rogue_key);
    let peer = (rogue + 1) % 3;
    let other = (rogue + 2) % 3;
    let case = open_cases(&engines[other])
        .into_iter()
        .find(|c| c.target_key == rogue_key)
        .expect("a case against the rogue");
    let evidence: serde_json::Value = serde_json::from_str(&case.evidence_json).unwrap();
    assert_eq!(evidence["intent"], rogue_intent.to_string());

    // 1. a peer re-derives the fault on its own node and signs
    let req = SlashSignRequest {
        evidence: evidence.clone(),
        act: remove_act(&env, rogue_key).await,
    };
    let r = verify_and_sign(engines[peer].ctx(), &req).await.unwrap();
    assert!(r.signatures >= 1, "{r:?}");
    // a repeat is answered from the recorded vote: no second set_signact
    let n = env.mock.state().calls_to("set_signact").len();
    let again = verify_and_sign(engines[peer].ctx(), &req).await.unwrap();
    assert_eq!(again, r);
    assert_eq!(env.mock.state().calls_to("set_signact").len(), n);

    let refused = |e: anyhow::Error| format!("{e:#}");
    // 2. never one's own removal
    let own = SlashSignRequest {
        evidence: evidence.clone(),
        act: remove_act(&env, rogue_key).await,
    };
    let e = refused(
        verify_and_sign(engines[rogue].ctx(), &own)
            .await
            .unwrap_err(),
    );
    assert!(e.contains("my own removal"), "{e}");
    // 3. the evidence accuses someone who did not sign the unlock
    let mut wrong = evidence.clone();
    wrong["target"] = hex::encode(env.key_of_index(other)).into();
    let e = refused(
        verify_and_sign(
            engines[peer].ctx(),
            &SlashSignRequest {
                evidence: wrong,
                act: remove_act(&env, env.key_of_index(other)).await,
            },
        )
        .await
        .unwrap_err(),
    );
    assert!(e.contains("not by the accused"), "{e}");
    // 4. the act removes someone else than the evidence accuses
    let e = refused(
        verify_and_sign(
            engines[peer].ctx(),
            &SlashSignRequest {
                evidence: evidence.clone(),
                act: remove_act(&env, env.key_of_index(other)).await,
            },
        )
        .await
        .unwrap_err(),
    );
    assert!(e.contains("the act removes"), "{e}");
    // 5. an intent that matches a finalized burn here is no fault
    let e = refused(
        verify_and_sign(
            engines[peer].ctx(),
            &SlashSignRequest {
                evidence: serde_json::json!({"fault": "FRAUDULENT_INTENT",
                    "intent": legit.to_string(), "target": hex::encode(legit_signer)}),
                act: remove_act(&env, legit_signer).await,
            },
        )
        .await
        .unwrap_err(),
    );
    assert!(e.contains("matches finalized burn"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f2_benign_race_cancelled_never_slashed() {
    use hawkeye::engine::slash::verify_and_sign;
    use hawkeye::peers::SlashSignRequest;
    use hawkeye_core::memo::HawkeyeMemo;
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x77; 20]);
    let nonce = burn_and_release(&env, &mut engines, &[0, 1, 2]).await;
    tick_all(&mut engines).await;
    env.mine(1);
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[0].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    let first = b.intent.unwrap();
    // a second intent for the same burn inside TAKEOVER (a slow leader's), from the re-lock
    let relock = {
        let st = env.mock.state();
        *st.templates
            .iter()
            .find(|(op, t)| op.txid.0 == first.txid && t.as_vault().is_some())
            .expect("the re-lock remainder")
            .0
    };
    let client = env.mock.client();
    let built = client
        .vault_buildunlock(
            &relock,
            &[hawkeye_ycash::types::Recipient::script(
                r.script(),
                Amount(400_000_000),
            )],
        )
        .await
        .unwrap();
    let memo = HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let with = hawkeye_ycash::tx::insert_op_return(&built.hex.to_string(), &memo.encode()).unwrap();
    let signed = client.set_signunlock(&with.parse().unwrap()).await.unwrap();
    let txid = client.vault_send(&signed.hex).await.unwrap();
    let second = CoreOutPoint::new(txid.0, built.intents[0].vout);
    tick_all(&mut engines).await;
    for e in &engines {
        let i = e.ctx().db(|t| t.intent(&second)).unwrap().unwrap();
        assert_eq!(
            i.classification.as_deref(),
            Some("unmatched:consumed-burn:benign-race")
        );
        assert!(
            open_cases(e).is_empty(),
            "a benign race opens no slash case"
        );
    }
    assert!(
        mempool_txs(&env)
            .iter()
            .any(|t| t.inputs.iter().any(|i| i.prevout.txid.0 == second.txid)),
        "the second intent is cancelled"
    );
    // a slash vote for it is refused by every peer
    let signer = signed.setsigs[0].key.0;
    let peer = (index_of(&env, &signer) + 1) % 3;
    let e = verify_and_sign(
        engines[peer].ctx(),
        &SlashSignRequest {
            evidence: serde_json::json!({"fault": "FRAUDULENT_INTENT",
                "intent": second.to_string(), "target": hex::encode(signer)}),
            act: remove_act(&env, signer).await,
        },
    )
    .await
    .unwrap_err();
    assert!(format!("{e:#}").contains("benign race"), "{e:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g_restart_resumes_deferred_mint_check() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    // a member mints (k = 1) for a lockId no lock is behind
    let r = 2;
    let fake = [0xab; 32];
    let to = env.holder.eth_address();
    let digest = hawkeye_core::eip712::Domain::new(31337, EthAddress(env.dep.bridge.0.0))
        .mint_digest(&fake, 500_000_000, &to);
    let sig = hawkeye_core::eth::sign_digest(&env.keys[r], &digest).unwrap();
    env.eth(&env.keys[r])
        .await
        .mint(
            B256::from(fake),
            U256::from(500_000_000u64),
            hawkeye::convert::addr(&to),
            &[sig],
        )
        .await
        .unwrap();
    env.eth_mine(3).await;
    tick_all(&mut engines).await;
    for e in &engines {
        let p = e.ctx().db(|t| t.pending_mints()).unwrap();
        assert_eq!(p.len(), 1, "deferred, not judged yet");
        assert!(open_cases(e).is_empty());
    }
    // crash before the grace period ends; the restarted engines resume the check
    drop(engines);
    let mut engines = three(&env).await;
    for _ in 0..25 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for (i, e) in engines.iter().enumerate() {
        assert!(e.ctx().db(|t| t.pending_mints()).unwrap().is_empty());
        let cases = open_cases(e);
        if i == r {
            assert!(cases.is_empty(), "no case against oneself");
        } else {
            assert!(
                cases
                    .iter()
                    .any(|c| c.fault == hawkeye_store::FaultKind::FraudulentMint
                        && c.target_key == env.key_of_index(r)),
                "attestor {i}: {cases:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g2_restart_resumes_slash_case_without_re_signing() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let (_, rogue_key) = rogue_unlock(&env).await;
    // the owner gathers the signatures, then set_sendact fails
    env.mock
        .state()
        .inject_error("set_sendact", -26, "16: injected for the test");
    tick_all(&mut engines).await;
    let signacts = env.mock.state().calls_to("set_signact").len();
    assert!(signacts >= 1);
    let voted: Vec<_> = engines
        .iter()
        .flat_map(|e| {
            e.ctx()
                .db(|t| t.slash_cases_in_state(SlashState::Voted))
                .unwrap()
                .into_iter()
                .map(|c| (e.ctx().db(|t| t.slash_progress(c.id)).unwrap(), c))
        })
        .collect();
    assert_eq!(voted.len(), 1, "one owner holds the act");
    assert!(voted[0].0.as_ref().unwrap().complete, "complete, not sent");
    // crash; the restarted owner sends the stored act: no new signature anywhere
    drop(engines);
    let mut engines = three(&env).await;
    tick_all(&mut engines).await;
    assert_eq!(
        env.mock.state().calls_to("set_signact").len(),
        signacts,
        "no act re-signed after the restart"
    );
    env.mine(1);
    tick_all(&mut engines).await;
    let st = env.mock.state();
    let m = st.sets[&env.set]
        .memberlist
        .iter()
        .find(|m| m.key.0 == rogue_key)
        .unwrap()
        .clone();
    drop(st);
    assert_eq!(m.status, MemberStatus::Removed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h_cancel_equivocation_detected() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let (intent, rogue_key) = rogue_unlock(&env).await;
    let cheat = env.key_of_index((index_of(&env, &rogue_key) + 1) % 3);
    let vault_spk = {
        let st = env.mock.state();
        let raw = &st.txs[&Hash256(intent.txid)].0;
        let tx = Transaction::decode(raw).unwrap();
        let v = tx.inputs[0].prevout;
        let prev = Transaction::decode(&st.txs[&v.txid].0).unwrap();
        prev.outputs[v.vout as usize].script_pubkey.clone()
    };
    // two different cancels of one intent, both signed by `cheat`
    let cancel = |sighash: u8, value: i64| {
        let sig = hawkeye_ycash::mock::mock_set_sig(
            &PubKey(cheat),
            &hawkeye_ycash::Bytes32([sighash; 32]),
        );
        let mut ss = vec![sig.len() as u8];
        ss.extend(&sig);
        ss.push(0x52);
        Transaction::new_v4(
            vec![TxIn {
                prevout: OutPoint::new(Hash256(intent.txid), intent.vout),
                script_sig: ss,
                sequence: u32::MAX,
            }],
            vec![TxOut {
                value,
                script_pubkey: vault_spk.clone(),
            }],
            0,
            0,
        )
    };
    let first = env
        .mock
        .state()
        .submit(cancel(1, 100_000_000).encode())
        .unwrap();
    tick_all(&mut engines).await;
    assert!(env.mock.state().calls_to("set_equivocation").is_empty());
    {
        let mut st = env.mock.state();
        st.mempool.retain(|t| *t != first);
        st.submit(cancel(2, 99_000_000).encode()).unwrap();
    }
    tick_all(&mut engines).await;
    let n = env.mock.state().calls_to("set_equivocation").len();
    assert!((1..=3).contains(&n), "{n} equivocation proofs");
    // each attestor submits at most once, also after a restart
    drop(engines);
    let mut engines = three(&env).await;
    tick_all(&mut engines).await;
    assert_eq!(env.mock.state().calls_to("set_equivocation").len(), n);
    env.mine(1);
    tick_all(&mut engines).await;
    let st = env.mock.state();
    let m = st.sets[&env.set]
        .memberlist
        .iter()
        .find(|m| m.key.0 == cheat)
        .unwrap()
        .clone();
    drop(st);
    assert_eq!(m.status, MemberStatus::Ejected);
    for e in &engines {
        assert!(
            open_cases(e)
                .iter()
                .any(|c| c.fault == hawkeye_store::FaultKind::Equivocation && c.target_key == cheat)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i_rolls_valid_and_invalid() {
    use hawkeye_core::memo::{HawkeyeMemo, MemoKind};
    let opts = Opts {
        min_owner_age: 20,
        roll_margin: 50,
        ..Opts::default()
    };
    let Some(env) = setup_with(opts).await else {
        return;
    };
    let mut engines = three(&env).await;
    // ownerHeight 40 above the tip: policy-OK (≥ 20) and already within ROLL_MARGIN
    let (op, vp) = env.lock_aged(1_000_000_000, &env.holder.eth_address(), 40);
    drive_mint(&env, &mut engines, &op).await;
    let rolls: Vec<_> = mempool_txs(&env)
        .into_iter()
        .filter_map(|t| {
            t.outputs.iter().find_map(|o| {
                parse_memo_script(&o.script_pubkey)
                    .ok()
                    .flatten()
                    .filter(|m| m.kind == MemoKind::Roll)
            })
        })
        .collect();
    assert_eq!(rolls.len(), 1, "one leader, one roll");
    let new = rolls[0].rolled_vault(&vp).unwrap();
    assert!(new.owner_height > vp.owner_height + 40);
    env.register_vault(&new);
    env.mine(1);
    tick_all(&mut engines).await;
    for e in &engines {
        let m = e
            .ctx()
            .db(|t| t.intents_in_state(IntentState::Matched))
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].classification.as_deref(), Some("matched-roll"));
        let v = e.ctx().db(|t| t.vault(&op)).unwrap().unwrap();
        assert_eq!(v.state, VaultState::Rolled);
    }
    for _ in 0..=u32::from(DELAY) {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for e in &engines {
        let live = e.ctx().db(|t| t.vaults_in_state(VaultState::Live)).unwrap();
        assert_eq!(live.len(), 1, "the new vault");
        assert_eq!(live[0].owner_height, new.owner_height);
        assert_eq!(live[0].value_zat, 1_000_000_000);
        assert_eq!(
            e.ctx()
                .db(|t| t.intents_in_state(IntentState::Released))
                .unwrap()
                .len(),
            1
        );
        assert!(open_cases(e).is_empty());
        assert!(e.alarms().is_empty(), "{:?}", e.alarms());
    }
    assert!(
        env.mock.state().calls_to("set_signcancel").is_empty(),
        "a valid roll is not cancelled"
    );
    // an invalid roll: the memo names one vault, the intent pays another
    let new_op = engines[0]
        .ctx()
        .db(|t| t.vaults_in_state(VaultState::Live))
        .unwrap()[0]
        .outpoint;
    let named = VaultParams {
        owner_height: new.owner_height + 100,
        ..new
    };
    let thief = VaultParams {
        owner_key: env.key_of_index(0),
        ..named
    };
    let client = env.mock.client();
    let built = client
        .vault_buildunlock(
            &OutPoint::new(Hash256(new_op.txid), new_op.vout),
            &[hawkeye_ycash::types::Recipient::script(
                thief.script().unwrap(),
                Amount(1_000_000_000),
            )],
        )
        .await
        .unwrap();
    let memo = HawkeyeMemo::roll(dep_of(&engines[0]), &named).unwrap();
    let with = hawkeye_ycash::tx::insert_op_return(&built.hex.to_string(), &memo.encode()).unwrap();
    let signed = client.set_signunlock(&with.parse().unwrap()).await.unwrap();
    client.vault_send(&signed.hex).await.unwrap();
    let rogue = signed.setsigs[0].key.0;
    tick_all(&mut engines).await;
    let sent: usize = engines
        .iter()
        .map(|e| {
            e.ctx()
                .db(|t| t.intents_in_state(IntentState::CancelSent))
                .unwrap()
                .len()
        })
        .sum();
    assert_eq!(sent, 1, "the bad roll is cancelled once");
    for (i, e) in engines.iter().enumerate() {
        if i == index_of(&env, &rogue) {
            continue;
        }
        let c = open_cases(e);
        assert_eq!(c.len(), 1, "attestor {i}");
        assert_eq!(c[0].target_key, rogue);
        assert!(c[0].evidence_json.contains("unmatched:bad-roll"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn j_optimistic_proposal_without_lock_challenged() {
    let opts = Opts {
        mode: MintMode::Optimistic,
        ..Opts::default()
    };
    let Some(env) = setup_with(opts).await else {
        return;
    };
    let mut engines = three(&env).await;
    let r = 1;
    let fake = [0xcd; 32];
    let to = env.holder.eth_address();
    let digest = hawkeye_core::eip712::Domain::new(31337, EthAddress(env.dep.bridge.0.0))
        .mint_digest(&fake, 700_000_000, &to);
    let sig = hawkeye_core::eth::sign_digest(&env.keys[r], &digest).unwrap();
    let rogue = env.eth(&env.keys[r]).await;
    rogue
        .propose_mint(
            B256::from(fake),
            U256::from(700_000_000u64),
            hawkeye::convert::addr(&to),
            &sig,
        )
        .await
        .unwrap();
    assert!(rogue.proposal(B256::from(fake)).await.unwrap().is_some());
    env.eth_mine(3).await;
    tick_all(&mut engines).await;
    for _ in 0..25 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    assert!(
        rogue.proposal(B256::from(fake)).await.unwrap().is_none(),
        "challenged before its window ends"
    );
    for (i, e) in engines.iter().enumerate() {
        if i == r {
            continue;
        }
        let c = open_cases(e);
        assert!(
            c.iter()
                .any(|c| c.fault == hawkeye_store::FaultKind::FraudulentMint
                    && c.target_key == env.key_of_index(r)),
            "attestor {i}: {c:?}"
        );
    }
    // the challenge is observed as a MintChallenged event, and no wYEC exists
    let c = env.eth(&env.holder).await;
    assert_eq!(c.total_supply().await.unwrap(), U256::ZERO);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k_unlock_cosign_endpoint() {
    use hawkeye::engine::burn::verify_and_sign_unlock;
    use hawkeye::peers::UnlockSignRequest;
    use hawkeye_core::memo::HawkeyeMemo;
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x44; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let mut live: Vec<[u8; 33]> = (0..3).map(|i| env.key_of_index(i)).collect();
    hawkeye_core::keys::sort_members(&mut live);
    let leader = index_of(&env, &live[(nonce % 3) as usize]);
    let peer = (leader + 1) % 3;
    // only the peer ticks: it holds the finalized burn and posts nothing
    engines[peer].tick().await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[peer].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    assert_eq!(b.state, BurnState::Assigned);
    let vault = {
        let st = env.mock.state();
        *st.templates.keys().next().unwrap()
    };
    let client = env.mock.client();
    let unlock = || async {
        client
            .vault_buildunlock(
                &vault,
                &[hawkeye_ycash::types::Recipient::script(
                    r.script(),
                    Amount(300_000_000),
                )],
            )
            .await
            .unwrap()
            .hex
            .to_string()
    };
    // no memo: refused
    let e = verify_and_sign_unlock(
        engines[peer].ctx(),
        &UnlockSignRequest {
            hex: unlock().await,
        },
    )
    .await
    .unwrap_err();
    assert!(format!("{e:#}").contains("does not match"), "{e:#}");
    // the burn's memo: co-signed, once
    let memo = HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let with = hawkeye_ycash::tx::insert_op_return(&unlock().await, &memo.encode()).unwrap();
    let ok = verify_and_sign_unlock(
        engines[peer].ctx(),
        &UnlockSignRequest { hex: with.clone() },
    )
    .await
    .unwrap();
    assert_eq!(ok.matched, format!("burn {nonce}"));
    assert!(ok.complete);
    let signs = env.mock.state().calls_to("set_signunlock").len();
    let again = verify_and_sign_unlock(engines[peer].ctx(), &UnlockSignRequest { hex: with })
        .await
        .unwrap();
    assert_eq!(again.hex, ok.hex);
    assert_eq!(env.mock.state().calls_to("set_signunlock").len(), signs);
    // another spend of the same vault is never co-signed
    let other = hawkeye_ycash::tx::insert_op_return(&unlock().await, &memo.encode()).unwrap();
    let e = verify_and_sign_unlock(engines[peer].ctx(), &UnlockSignRequest { hex: other })
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("sign-once conflict"), "{e:#}");
}

// ------------------------------------------------------------------------------------------
// optimistic mode (wyec @ cad126a, plan §3.3)

fn opt() -> Opts {
    Opts {
        mode: MintMode::Optimistic,
        ..Opts::default()
    }
}

fn challenges(e: &Engine) -> Vec<hawkeye_store::ChallengeSignRecord> {
    e.ctx().db(|t| t.challenge_signatures()).unwrap()
}

/// Ticks with Ethereum blocks mined in between (finality = latest − 2), no Ycash blocks.
async fn eth_rounds(env: &Env, engines: &mut [Engine], n: usize) {
    for _ in 0..n {
        tick_all(engines).await;
        env.eth_mine(3).await;
    }
    tick_all(engines).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l_optimistic_propose_window_execute() {
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let mut engines = three(&env).await;
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let lock_id = drive_mint(&env, &mut engines, &op).await;
    let c = env.eth(&env.holder).await;
    let p = c
        .proposal(B256::from(lock_id))
        .await
        .unwrap()
        .expect("proposed");
    assert_eq!(
        (p.id, p.amount, p.to),
        (1, U256::from(1_000_000_000u64), hawkeye::convert::addr(&to))
    );
    assert!(
        (0..3).any(|i| hawkeye::convert::addr(&env.keys[i].eth_address()) == p.proposer),
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
    eth_rounds(&env, &mut engines, 2).await;
    assert_eq!(c.total_supply().await.unwrap(), U256::ZERO);
    // after it, the leader executes and everyone observes the Minted event
    env.warp(WINDOW).await;
    eth_rounds(&env, &mut engines, 3).await;
    assert_eq!(
        c.balance_of(hawkeye::convert::addr(&to)).await.unwrap(),
        U256::from(1_000_000_000u64)
    );
    assert_eq!(c.proposal_count().await.unwrap(), 1, "proposed once");
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
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let mut engines = three(&env).await;
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let lock_id = drive_mint(&env, &mut engines, &op).await;
    let c = env.eth(&env.holder).await;
    let first = c.proposal(B256::from(lock_id)).await.unwrap().unwrap();
    // one guardian challenges the correct proposal anyway (griefing); the holder submits it
    let griefer = (0..3)
        .find(|i| hawkeye::convert::addr(&env.keys[*i].eth_address()) != first.proposer)
        .unwrap();
    let digest = hawkeye_core::eip712::Domain::new(31337, EthAddress(env.dep.bridge.0.0))
        .challenge_digest(&lock_id, first.id);
    let sig = hawkeye_core::eth::sign_digest(&env.keys[griefer], &digest).unwrap();
    c.challenge_mint(B256::from(lock_id), first.id, &sig)
        .await
        .unwrap();
    assert!(c.vetoed(B256::from(lock_id), first.proposer).await.unwrap());
    eth_rounds(&env, &mut engines, 3).await;
    let second = c
        .proposal(B256::from(lock_id))
        .await
        .unwrap()
        .expect("re-proposed");
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
    env.warp(WINDOW).await;
    eth_rounds(&env, &mut engines, 3).await;
    assert_eq!(
        c.balance_of(hawkeye::convert::addr(&to)).await.unwrap(),
        U256::from(1_000_000_000u64)
    );
    for e in &engines {
        assert_eq!(
            e.ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap().state,
            LockState::Minted
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_wrong_amount_proposal_on_a_real_lock_challenged() {
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let mut engines = three(&env).await;
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let lock_id = hawkeye_core::lock::lock_id(&op);
    env.mine(C_Y);
    // before any attestor acts, member r proposes the real lockId with a wrong amount
    let r = 1;
    let digest = hawkeye_core::eip712::Domain::new(31337, EthAddress(env.dep.bridge.0.0))
        .mint_digest(&lock_id, 9_000_000_000, &to);
    let sig = hawkeye_core::eth::sign_digest(&env.keys[r], &digest).unwrap();
    let c = env.eth(&env.holder).await;
    c.propose_mint(
        B256::from(lock_id),
        U256::from(9_000_000_000u64),
        hawkeye::convert::addr(&to),
        &sig,
    )
    .await
    .unwrap();
    env.eth_mine(3).await;
    eth_rounds(&env, &mut engines, 4).await;
    // challenged (by someone), a correct proposal follows from an attestor other than r
    let p = c
        .proposal(B256::from(lock_id))
        .await
        .unwrap()
        .expect("the correct proposal");
    assert_eq!(p.amount, U256::from(1_000_000_000u64));
    assert_ne!(
        p.proposer,
        hawkeye::convert::addr(&env.keys[r].eth_address())
    );
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
    env.warp(WINDOW).await;
    eth_rounds(&env, &mut engines, 3).await;
    assert_eq!(
        c.total_supply().await.unwrap(),
        U256::from(1_000_000_000u64)
    );
}

/// The contract's optimistic path cannot be switched off: in threshold mode the watchers still
/// challenge a one-key proposal with no lock behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn j2_threshold_mode_watchers_still_challenge_proposals() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    let r = 0;
    let fake = [0xce; 32];
    let to = env.holder.eth_address();
    let digest = hawkeye_core::eip712::Domain::new(31337, EthAddress(env.dep.bridge.0.0))
        .mint_digest(&fake, 300_000_000, &to);
    let sig = hawkeye_core::eth::sign_digest(&env.keys[r], &digest).unwrap();
    let rogue = env.eth(&env.keys[r]).await;
    rogue
        .propose_mint(
            B256::from(fake),
            U256::from(300_000_000u64),
            hawkeye::convert::addr(&to),
            &sig,
        )
        .await
        .unwrap();
    env.eth_mine(3).await;
    for _ in 0..C_Y + 1 {
        tick_all(&mut engines).await;
        env.mine(1);
    }
    tick_all(&mut engines).await;
    assert!(
        rogue.proposal(B256::from(fake)).await.unwrap().is_none(),
        "challenged C_Y blocks after it was judged, long before the window ends"
    );
    env.warp(WINDOW).await;
    tick_all(&mut engines).await;
    assert_eq!(rogue.total_supply().await.unwrap(), U256::ZERO);
}
