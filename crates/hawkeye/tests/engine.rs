//! Engine tests (plan §9 H4/H5): three Hawkeye engines against one mock ycashd (hawkeye-ycash
//! feature `mock`) and a local anvil with wYEC deployed. Ticks are driven by hand, blocks are
//! mined by hand on both chains, so every run is deterministic.
//!
//! (a) lock → sign → mint observed; (b) burn → unlock with the HKB1 memo → release after the
//! delay; (b2) a burn to a post-quantum `sq…` recipient releases to the `TX_PQPKH` script, (b3) a
//! malformed recipient is refused by the contract (§4.2 revision 2); (c) rogue intent → cancelled + slash case → SET_REMOVE; (d) restart mid-flow: no second
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
    Address, B256, Bytes, DeployParams, Deployment, EthClient, EthConfig, MintMode,
    PrivateKeySigner, U256, deploy, wallet_provider,
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
    /// The set's `ratelimitbps` (0: no rate limit).
    ratelimitbps: u32,
    /// anvil's `--slots-in-an-epoch`: finalized = latest − 2 × slots (audit 05/T-3: 32 pins
    /// finality 64 blocks behind the head, as on mainnet).
    slots: u64,
    /// The bridge's challenge window, seconds.
    window: u64,
    /// The bridge's `mintCap` per day (0: no limit; mainnet semantics then pause own mints).
    mint_cap: u128,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            mode: MintMode::Threshold { k: 1 },
            min_owner_age: 400,
            roll_margin: 50,
            ratelimitbps: 0,
            slots: 1,
            window: WINDOW,
            mint_cap: 0,
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
        eprintln!(
            "SKIPPED (anvil not on PATH): this test passed vacuously; `make test` or HAWKEYE_REQUIRE_ANVIL=1 turns a missing anvil into a failure"
        );
        return None;
    }
    let anvil = Anvil::new()
        .args(["--slots-in-an-epoch", &opts.slots.to_string()])
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
    let dep = deploy(&provider, deployer.address(), &{
        let mut p = DeployParams::new(&guardians, threshold, opts.window, opts.mode);
        if opts.mint_cap > 0 {
            p.mint_cap = opts.mint_cap;
            p.cap_window = 86_400;
        }
        p
    })
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
        ratelimitbps: opts.ratelimitbps,
        ratewindow: 20,
        livenesswindow: 1000,
        bondmin: Amount(100_000_000),
        bondlockmin: 0,
        maturity: 2,
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
            bridge_kind: hawkeye_core::BridgeKind::Ethereum,
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
            fallback_to_threshold: true,
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
        self.engine_with(i, vec![], |_| {}).await
    }

    /// Attestor `i`'s engine with peer API URLs and adjusted parameters.
    async fn engine_with(
        &self,
        i: usize,
        peers: Vec<String>,
        adjust: impl FnOnce(&mut Params),
    ) -> Engine {
        let foreign = Arc::new(hawkeye::foreign::EthereumChain::new(
            self.eth(&self.keys[i]).await,
        ));
        self.engine_on(i, peers, foreign, adjust)
    }

    /// Attestor `i`'s engine over a given foreign-chain adapter (a test wrapper).
    fn engine_on(
        &self,
        i: usize,
        peers: Vec<String>,
        foreign: Arc<dyn hawkeye::foreign::ForeignChain>,
        adjust: impl FnOnce(&mut Params),
    ) -> Engine {
        let key = self.keys[i].clone();
        let store = Store::open(self.dir.path().join(format!("attestor{i}.db"))).unwrap();
        let mut params = self.params();
        adjust(&mut params);
        Engine::new(Ctx {
            params: Arc::new(params),
            me: key.public_key(),
            foreign,
            key,
            ycash: Arc::new(self.mock.client()),
            store: Arc::new(Mutex::new(store)),
            attributor: Arc::new(MockAttributor { set: self.set.0 }),
            peers: Peers::new(peers).unwrap(),
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
                owner: hawkeye_ycash::PqKeyId(vp.owner.to_bytes()),
                ownerscheme: vp.owner.scheme,
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
            (st.new_wallet_owner(), st.tip_height())
        };
        let vp = VaultParams {
            tag: TAG_WYEC,
            set_id: self.set.0,
            cancel_set_id: self.set.0,
            delay: DELAY,
            owner_height: tip + owner_age,
            app_height: 0,
            owner: hawkeye_core::PqKeyId::from_bytes(&owner.0).unwrap(),
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
            .burn(U256::from(amount), Bytes::from(recipient.to_bytes()))
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

/// (b2) Plan §4.2 revision 2, phase R4: a burn to a plain-YEC post-quantum recipient (kind 2,
/// scheme 1) is released to the node's `TX_PQPKH` script `20 <keyHash> OP_1 OP_CHECKPQSIG`: the
/// `HKB1` intent commits `recipienthash = SHA256(that 35-byte script)`, `vault_release` is passed
/// the script, and the release transaction pays it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2_burn_to_pq_recipient_releases_tx_pqpkh() {
    use hawkeye_core::bytes::sha256;
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::pqpkh(1, [0xc5; 32]).unwrap();
    let script = r.script();
    assert_eq!(script.len(), 35);
    assert_eq!(script[0], 32);
    assert_eq!(&script[33..], &[0x51, 0xc2]);
    let nonce = env.burn(400_000_000, &r).await;
    env.eth_mine(3).await;
    tick_all(&mut engines).await;
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[0].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    assert_eq!(b.recipient, r.to_bytes());
    assert_eq!(b.recipient.len(), 35);
    env.mine(1);
    tick_all(&mut engines).await;
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::IntentConfirmed);
        let intent = b.intent.expect("the burn names its intent");
        let i = e.ctx().db(|t| t.intent(&intent)).unwrap().unwrap();
        assert_eq!(
            i.recipient_hash,
            sha256(&script),
            "recipienthash = SHA256(TX_PQPKH)"
        );
        assert_eq!(i.classification.as_deref(), Some("matched-burn"));
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
    }
    let st = env.mock.state();
    let releases: Vec<_> = st
        .calls_to("vault_release")
        .into_iter()
        .filter(|c| c.error.is_none())
        .collect();
    assert!(!releases.is_empty(), "a release was broadcast");
    for c in &releases {
        assert_eq!(
            c.params[1].as_str(),
            Some(hex::encode(&script).as_str()),
            "vault_release is passed the 35-byte TX_PQPKH script"
        );
    }
    let pays = st
        .txs
        .values()
        .filter(|(_, block)| block.is_some())
        .map(|(raw, _)| Transaction::decode(raw).unwrap())
        .any(|t| {
            t.outputs
                .iter()
                .any(|o| o.script_pubkey == script && o.value == 400_000_000)
        });
    assert!(
        pays,
        "a mined transaction pays 4 YEC to the TX_PQPKH script"
    );
}

/// (b3) A malformed recipient never reaches the ledger from this contract: `burn` reverts
/// `InvalidRecipient()` (revision 1's 32 bytes, a wrong scheme, a wrong length), spends no nonce,
/// and the engines see no burn. (A burn the contract did accept but the engine cannot decode is
/// the orphaned path of plan §3.4; with a validating contract only a zero amount takes it.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b3_malformed_recipient_burn_is_refused_by_the_contract() {
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    let c = env.eth(&env.holder).await;
    let before = c.burn_nonce().await.unwrap();
    let mut v1 = vec![0x01u8, 0x00];
    v1.extend([0u8; 10]);
    v1.extend([0x77u8; 20]);
    let mut scheme3 = YcashRecipient::pqpkh(1, [0xc5; 32]).unwrap().to_bytes();
    scheme3[2] = 3;
    let mut short = YcashRecipient::p2pkh([0x77; 20]).to_bytes();
    short.pop();
    for bad in [v1, scheme3, short, Vec::new()] {
        let e = c
            .burn(U256::from(1), Bytes::from(bad.clone()))
            .await
            .unwrap_err();
        assert!(
            e.to_string().contains("InvalidRecipient"),
            "{}: {e}",
            hex::encode(&bad)
        );
    }
    assert_eq!(c.burn_nonce().await.unwrap(), before, "no nonce spent");
    env.eth_mine(3).await;
    tick_all(&mut engines).await;
    let burns = engines[0]
        .ctx()
        .db(|t| t.burns_in_state(&dep_of(&engines[0]), BurnState::Finalized))
        .unwrap();
    assert!(burns.is_empty(), "no burn reached the ledger");
    // the well-formed form of the same recipient goes through
    let nonce = env
        .burn(1, &YcashRecipient::pqpkh(1, [0xc5; 32]).unwrap())
        .await;
    assert_eq!(U256::from(nonce), before);
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

/// The bond exit delay (owner 2026-10-11, D-Q-31): a member that signs a fraudulent unlock and
/// leaves the set at once (`set_leave`, its bond now in the exit delay) is still attributed,
/// voted on and slashed: the cosigned `SET_REMOVE burn=1` freezes the bond in its delay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f3_a_signer_that_leaves_is_still_slashed() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let (_intent, rogue) = rogue_unlock(&env).await;
    let left = env
        .mock
        .client()
        .set_leave(&env.set, Some(&PubKey(rogue)))
        .await
        .unwrap();
    env.mine(1);
    let rogue_idx = index_of(&env, &rogue);
    {
        let st = env.mock.state();
        let m = st.sets[&env.set]
            .memberlist
            .iter()
            .find(|m| m.key.0 == rogue)
            .unwrap();
        assert_eq!((m.status, m.bondfrozen), (MemberStatus::Removed, false));
        assert!(
            st.next_height() < left.bondspendableat,
            "still in the exit delay"
        );
    }
    for _ in 0..4 {
        tick_all(&mut engines).await;
        env.mine(1);
    }
    tick_all(&mut engines).await;
    let st = env.mock.state();
    let m = st.sets[&env.set]
        .memberlist
        .iter()
        .find(|m| m.key.0 == rogue)
        .unwrap()
        .clone();
    drop(st);
    assert_eq!(m.status, MemberStatus::Removed);
    assert!(m.bondfrozen, "the slash reached the bond in its exit delay");
    for (i, e) in engines.iter().enumerate() {
        if i == rogue_idx {
            continue;
        }
        let slashed = e
            .ctx()
            .db(|t| t.slash_cases_in_state(SlashState::Slashed))
            .unwrap();
        assert_eq!(slashed.len(), 1, "attestor {i} records the slash");
        assert_eq!(slashed[0].target_key, rogue);
    }
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
    // the thief's owner: a key hash derived from a member key
    let thief = VaultParams {
        owner: hawkeye_core::PqKeyId::new(1, env.key_of_index(0)[1..].try_into().unwrap()).unwrap(),
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
        assert!(
            !open_cases(e)
                .iter()
                .any(|c| c.fault == hawkeye_store::FaultKind::Griefing),
            "an honest challenge is never griefing (attestor {i})"
        );
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

/// GET `/burns/<nonce>` from `e`'s API.
async fn burn_view(e: &Engine, nonce: u64) -> hawkeye::peers::BurnView {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = hawkeye::api::router(e.ctx().clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    reqwest::get(format!("http://{addr}/burns/{nonce}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// (p) Audit 05/M-2: a burn above the set's whole per-window cap never stalls later nonces. With
/// `ratelimitbps` 5000 over 10 YEC locked (cap 5 YEC), burns of 8, 1 and 1 YEC: the 8 is parked
/// `WAITING_CAP` (reason `over-cap`, alarm `burn-over-cap`, `/status`, `/metrics`, `/burns`) on
/// every attestor while the two 1-YEC burns are unlocked; raising the set's rate limit releases it
/// without a restart and clears the alarm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p_over_cap_burn_does_not_block_later_burns() {
    let Some(env) = setup_with(Opts {
        ratelimitbps: 5_000,
        ..Opts::default()
    })
    .await
    else {
        return;
    };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    // into the next rate-limit epoch: its basis is the 10 YEC locked
    env.mine(20);
    tick_all(&mut engines).await;
    let r = YcashRecipient::p2pkh([0x77; 20]);
    let big = env.burn(800_000_000, &r).await;
    let small = [
        env.burn(100_000_000, &r).await,
        env.burn(100_000_000, &r).await,
    ];
    env.eth_mine(3).await;
    tick_all(&mut engines).await;
    let dep = dep_of(&engines[0]);
    let kb = BurnKey::new(dep, big);
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&kb)).unwrap().unwrap();
        assert!(b.over_cap(), "parked over cap on every ledger: {b:?}");
        assert!(
            e.alarms().iter().any(|a| a.name == "burn-over-cap"),
            "{:?}",
            e.alarms()
        );
    }
    // the later burns go on
    for _ in 0..6 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for n in small {
        let k = BurnKey::new(dep, n);
        for e in &engines {
            let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
            assert!(
                matches!(b.state, BurnState::IntentConfirmed | BurnState::Released),
                "burn {n} is served past the over-cap one: {:?}",
                b.state
            );
        }
    }
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&kb)).unwrap().unwrap();
        assert!(b.over_cap(), "still parked: {b:?}");
        let st = e.ctx().status.read().unwrap().clone();
        assert_eq!(st.burns_over_cap, 1);
        let m = hawkeye::status::render_metrics(&st);
        assert!(m.contains("hawkeye_burn_over_cap 1"), "{m}");
        assert!(m.contains("hawkeye_alarm{name=\"burn-over-cap\"} 1"), "{m}");
    }
    let view = burn_view(&engines[0], big).await;
    assert_eq!(view.state, "WAITING_CAP");
    assert_eq!(view.reason.as_deref(), Some("over-cap"));
    // governance raises the rate limit: released at the next tick, no restart
    env.mock
        .state()
        .sets
        .get_mut(&env.set)
        .unwrap()
        .set
        .params
        .ratelimitbps = 10_000;
    tick_all(&mut engines).await;
    for e in &engines {
        assert!(
            !e.alarms().iter().any(|a| a.name == "burn-over-cap"),
            "the alarm clears: {:?}",
            e.alarms()
        );
    }
    for _ in 0..3 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&kb)).unwrap().unwrap();
        assert!(
            matches!(
                b.state,
                BurnState::IntentPending | BurnState::IntentConfirmed | BurnState::Released
            ),
            "released after the cap raise: {:?}",
            b.state
        );
        assert_eq!(e.ctx().status.read().unwrap().burns_over_cap, 0);
    }
    assert_eq!(burn_view(&engines[0], big).await.reason, None);
}

/// Attestors `idx` with their APIs served and wired to each other as peers (`GET /locks/<id>`
/// for the threshold path), parameters adjusted by `adjust`.
async fn wired(env: &Env, idx: &[usize], adjust: impl Fn(&mut Params)) -> Vec<Engine> {
    let mut listeners = vec![];
    let mut urls = vec![];
    for _ in idx {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}", l.local_addr().unwrap()));
        listeners.push(l);
    }
    let mut engines = vec![];
    for (n, (&i, l)) in idx.iter().zip(listeners).enumerate() {
        let peers = urls
            .iter()
            .enumerate()
            .filter(|(m, _)| *m != n)
            .map(|(_, u)| u.clone())
            .collect();
        let e = env.engine_with(i, peers, &adjust).await;
        let app = hawkeye::api::router(e.ctx().clone());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        engines.push(e);
    }
    engines
}

/// One griefing round: member `griefer` challenges whatever proposal is live for `lock_id`
/// (every honest re-proposal, its own included), then one Ycash block and one foreign round.
async fn grief_round(env: &Env, engines: &mut [Engine], lock_id: [u8; 32], griefer: usize) {
    let c = env.eth(&env.holder).await;
    if let Some(p) = c.proposal(B256::from(lock_id)).await.unwrap() {
        let digest = hawkeye_core::eip712::Domain::new(31337, EthAddress(env.dep.bridge.0.0))
            .challenge_digest(&lock_id, p.id);
        let sig = hawkeye_core::eth::sign_digest(&env.keys[griefer], &digest).unwrap();
        c.challenge_mint(B256::from(lock_id), p.id, &sig)
            .await
            .unwrap();
    }
    env.mine(1);
    eth_rounds(env, engines, 1).await;
}

fn griefing_cases(e: &Engine, target: [u8; 33]) -> Vec<hawkeye_store::SlashCaseRecord> {
    open_cases(e)
        .into_iter()
        .filter(|c| c.fault == hawkeye_store::FaultKind::Griefing && c.target_key == target)
        .collect()
}

/// (t) Audit 05/L-4, HK-15: member 2 challenges every honest proposal of a policy-OK lock (each
/// challenged proposer is `vetoed` for it). Once no live member may propose, the lock is minted
/// by the threshold path (`mint`, the contract's threshold of `Mint` signatures gathered over
/// `GET /locks/<id>`) without operator action and without the window ever passing; the honest
/// attestors hold a verifiable `GRIEFING` case against member 2, which opens none against itself;
/// (t2) a griefing vote for a proposal that matches no policy-OK lock here is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t_all_proposers_vetoed_falls_back_to_threshold() {
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let mut engines = wired(&env, &[0, 1, 2], |_| {}).await;
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let lock_id = drive_mint(&env, &mut engines, &op).await;
    let c = env.eth(&env.holder).await;
    assert!(c.proposal(B256::from(lock_id)).await.unwrap().is_some());
    let holder = hawkeye::convert::addr(&to);
    let mut rounds = 0;
    while c.balance_of(holder).await.unwrap() == U256::ZERO {
        rounds += 1;
        assert!(rounds <= 40, "no threshold fallback after {rounds} rounds");
        grief_round(&env, &mut engines, lock_id, 2).await;
    }
    assert_eq!(
        c.balance_of(holder).await.unwrap(),
        U256::from(1_000_000_000u64)
    );
    // every honest proposer was barred: the optimistic path could not have minted it
    for i in [0, 1] {
        assert!(
            c.vetoed(
                B256::from(lock_id),
                hawkeye::convert::addr(&env.keys[i].eth_address())
            )
            .await
            .unwrap(),
            "attestor {i} vetoed"
        );
    }
    eth_rounds(&env, &mut engines, 2).await;
    let key2 = env.key_of_index(2);
    for (i, e) in engines.iter().enumerate() {
        assert_eq!(
            e.ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap().state,
            LockState::Minted,
            "attestor {i}"
        );
        let cases = griefing_cases(e, key2);
        if i == 2 {
            assert!(cases.is_empty(), "no case against itself: {cases:?}");
            continue;
        }
        assert!(!cases.is_empty(), "attestor {i} holds a GRIEFING case");
        for case in &cases {
            assert_eq!(&case.subject[..32], lock_id.as_slice());
            let ev: serde_json::Value = serde_json::from_str(&case.evidence_json).unwrap();
            assert_eq!(ev["fault"], "GRIEFING");
            assert!(ev["challenge_tx"].as_str().unwrap().starts_with("0x"));
            // verifiable by the other honest attestor, on its own ledger
            let other = &engines[1 - i];
            let v = hawkeye::engine::slash::verify_evidence(other.ctx(), &ev)
                .await
                .unwrap();
            assert_eq!(v.fault, hawkeye_store::FaultKind::Griefing);
            assert_eq!(v.target, key2);
        }
    }
    // (t2) a challenge of a proposal with no policy-OK lock behind it is not griefing here
    let ev = serde_json::json!({
        "fault": "GRIEFING",
        "target": hex::encode(key2),
        "lock_id": format!("0x{}", hex::encode([0xab; 32])),
        "proposal_id": "9",
        "challenger": env.keys[2].eth_address().to_checksum(),
        "amount": 1_000_000_000u64,
        "to": to.to_checksum(),
    });
    let refused = hawkeye::engine::slash::verify_evidence(engines[0].ctx(), &ev)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("not griefing here: the proposal does not match a policy-OK lock"),
        "{refused}"
    );
    // nor one of the real lock with another amount
    let mut wrong = ev.clone();
    wrong["lock_id"] = format!("0x{}", hex::encode(lock_id)).into();
    wrong["amount"] = 9_000_000_000u64.into();
    let refused = hawkeye::engine::slash::verify_evidence(engines[0].ctx(), &wrong)
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("not griefing here"), "{refused}");
}

/// (t3) The threshold fallback is a submission like any other: guardian drift on mainnet
/// semantics (`signing_paused`) holds it; once the drift is gone it mints.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t3_threshold_fallback_respects_signing_pause() {
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    // the vetoes first, with the fallback off
    let mut engines = wired(&env, &[0, 1, 2], |p| p.fallback_to_threshold = false).await;
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let lock_id = drive_mint(&env, &mut engines, &op).await;
    let c = env.eth(&env.holder).await;
    let vetoed = |i: usize| {
        let c = &c;
        let a = hawkeye::convert::addr(&env.keys[i].eth_address());
        async move { c.vetoed(B256::from(lock_id), a).await.unwrap() }
    };
    let mut rounds = 0;
    while !(vetoed(0).await && vetoed(1).await) {
        rounds += 1;
        assert!(
            rounds <= 40,
            "proposers not all vetoed after {rounds} rounds"
        );
        grief_round(&env, &mut engines, lock_id, 2).await;
    }
    for _ in 0..3 {
        grief_round(&env, &mut engines, lock_id, 2).await;
    }
    let holder = hawkeye::convert::addr(&to);
    assert_eq!(
        c.balance_of(holder).await.unwrap(),
        U256::ZERO,
        "fallback off"
    );
    drop(engines);
    // member 2 leaves the set (its griefing case's outcome): guardians {0,1,2} ≠ members {0,1}
    {
        let mut st = env.mock.state();
        let info = st.sets.get_mut(&env.set).unwrap();
        let m = info
            .memberlist
            .iter_mut()
            .find(|m| m.key.0 == env.key_of_index(2))
            .unwrap();
        m.status = MemberStatus::Removed;
    }
    let mut paused = wired(&env, &[0, 1], |p| {
        p.mainnet = true;
        p.drills = false;
        p.fallback_to_threshold = true;
    })
    .await;
    for _ in 0..6 {
        env.mine(1);
        eth_rounds(&env, &mut paused, 1).await;
    }
    for e in &paused {
        assert!(
            e.alarms().iter().any(|a| a.name == "guardian-drift"),
            "{:?}",
            e.alarms()
        );
    }
    assert_eq!(
        c.balance_of(holder).await.unwrap(),
        U256::ZERO,
        "signing paused: no threshold fallback"
    );
    drop(paused);
    // the drift resolved (here: off mainnet semantics, the alarm stays an alarm): it mints
    let mut engines = wired(&env, &[0, 1], |p| p.fallback_to_threshold = true).await;
    let mut rounds = 0;
    while c.balance_of(holder).await.unwrap() == U256::ZERO {
        rounds += 1;
        assert!(rounds <= 20, "no fallback after {rounds} rounds");
        env.mine(1);
        eth_rounds(&env, &mut engines, 1).await;
    }
    assert_eq!(
        c.balance_of(holder).await.unwrap(),
        U256::from(1_000_000_000u64)
    );
}

// ------------------------------------------------------------------------------------------
// audit 05/H-2, 05/T-3: proposals watched at `latest`, the finality stall, pinned finality

/// An Ethereum adapter whose `finalized` can be pinned (a finality stall), which can inject
/// `MintProposed` events into the head-of-chain scan (a proposal later reorged out), and which
/// counts this attestor's own `proposeMint` submissions.
struct TestChain {
    inner: hawkeye::foreign::EthereumChain,
    pinned: Mutex<Option<u64>>,
    inject: Mutex<Vec<hawkeye::foreign::Scanned>>,
    proposes: std::sync::atomic::AtomicUsize,
}

mod test_chain {
    use super::TestChain;
    use hawkeye::foreign::*;
    use hawkeye_core::bytes::Hash32;
    use hawkeye_core::{Deployment, PubKey33, SecretKey};
    use std::sync::atomic::Ordering;

    impl AttestationScheme for TestChain {
        fn guardian_of(&self, m: &PubKey33) -> ForeignResult<Guardian> {
            self.inner.guardian_of(m)
        }
        fn mint_digest(&self, l: &Hash32, a: u64, to: &Account) -> ForeignResult<Hash32> {
            self.inner.mint_digest(l, a, to)
        }
        fn challenge_digest(&self, l: &Hash32, id: u128) -> Hash32 {
            self.inner.challenge_digest(l, id)
        }
        fn sign(&self, k: &SecretKey, d: &Hash32) -> ForeignResult<[u8; 65]> {
            self.inner.sign(k, d)
        }
        fn recover(&self, d: &Hash32, s: &[u8]) -> ForeignResult<Guardian> {
            self.inner.recover(d, s)
        }
        fn parse_account(&self, t: &str) -> ForeignResult<Account> {
            self.inner.parse_account(t)
        }
    }

    impl ForeignChain for TestChain {
        fn kind(&self) -> BridgeKind {
            self.inner.kind()
        }
        fn deployment(&self) -> Deployment {
            self.inner.deployment()
        }
        fn check_bridge(&self, mainnet: bool) -> BoxFut<'_, BridgeInfo> {
            self.inner.check_bridge(mainnet)
        }
        fn finalized_height(&self) -> BoxFut<'_, u64> {
            Box::pin(async move {
                let pinned = *self.pinned.lock().unwrap();
                match pinned {
                    Some(h) => Ok(h),
                    None => self.inner.finalized_height().await,
                }
            })
        }
        fn latest_height(&self) -> BoxFut<'_, u64> {
            self.inner.latest_height()
        }
        fn scan(&self, from: u64, to: u64) -> BoxFut<'_, ScanBatch> {
            self.inner.scan(from, to)
        }
        fn scan_proposals(&self, from: u64, to: u64) -> BoxFut<'_, ScanBatch> {
            Box::pin(async move {
                let mut b = self.inner.scan_proposals(from, to).await?;
                for e in self.inject.lock().unwrap().iter() {
                    if (from..=to).contains(&e.meta.height) {
                        b.events.push(e.clone());
                    }
                }
                Ok(b)
            })
        }
        fn now(&self) -> BoxFut<'_, u64> {
            self.inner.now()
        }
        fn guardians(&self) -> BoxFut<'_, Vec<Guardian>> {
            self.inner.guardians()
        }
        fn threshold(&self) -> BoxFut<'_, u8> {
            self.inner.threshold()
        }
        fn challenge_window(&self) -> BoxFut<'_, u64> {
            self.inner.challenge_window()
        }
        fn consumed(&self, l: Hash32) -> BoxFut<'_, bool> {
            self.inner.consumed(l)
        }
        fn proposal(&self, l: Hash32) -> BoxFut<'_, Option<Proposal>> {
            self.inner.proposal(l)
        }
        fn proposal_status(&self, l: Hash32) -> BoxFut<'_, ProposalStatus> {
            self.inner.proposal_status(l)
        }
        fn vetoed(&self, l: Hash32, who: Guardian) -> BoxFut<'_, bool> {
            self.inner.vetoed(l, who)
        }
        fn mint_available(&self) -> BoxFut<'_, u128> {
            self.inner.mint_available()
        }
        fn total_supply(&self) -> BoxFut<'_, u128> {
            self.inner.total_supply()
        }
        fn paused(&self) -> BoxFut<'_, bool> {
            self.inner.paused()
        }
        fn mint_signatures(&self, tx: TxId) -> BoxFut<'_, Vec<Vec<u8>>> {
            self.inner.mint_signatures(tx)
        }
        fn threshold_mint(
            &self,
            k: u8,
            l: Hash32,
            a: u64,
            to: Account,
            sigs: Vec<[u8; 65]>,
        ) -> BoxFut<'_, Mined> {
            self.inner.threshold_mint(k, l, a, to, sigs)
        }
        fn propose_mint(
            &self,
            l: Hash32,
            a: u64,
            to: Account,
            sig: [u8; 65],
        ) -> BoxFut<'_, Proposed> {
            self.proposes.fetch_add(1, Ordering::SeqCst);
            self.inner.propose_mint(l, a, to, sig)
        }
        fn challenge_mint(&self, l: Hash32, id: u128, sig: [u8; 65]) -> BoxFut<'_, Mined> {
            self.inner.challenge_mint(l, id, sig)
        }
        fn execute_mint(&self, l: Hash32) -> BoxFut<'_, Mined> {
            self.inner.execute_mint(l)
        }
        fn burn(&self, amount: u64, r: Vec<u8>) -> BoxFut<'_, Burned> {
            self.inner.burn(amount, r)
        }
    }
}

impl Env {
    async fn test_chain(&self, i: usize) -> Arc<TestChain> {
        Arc::new(TestChain {
            inner: hawkeye::foreign::EthereumChain::new(self.eth(&self.keys[i]).await),
            pinned: Mutex::new(None),
            inject: Mutex::new(vec![]),
            proposes: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    async fn finalized(&self) -> u64 {
        self.eth(&self.holder)
            .await
            .finalized_block_number()
            .await
            .unwrap()
    }

    async fn latest(&self) -> u64 {
        self.provider.get_block_number().await.unwrap()
    }
}

fn pending_provisional(e: &Engine, lock_id: &[u8; 32]) -> Vec<bool> {
    e.ctx()
        .db(|t| t.pending_mints())
        .unwrap()
        .into_iter()
        .filter(|p| &p.lock_id == lock_id)
        .map(|p| p.provisional)
        .collect()
}

fn fraud_cases(e: &Engine, target: [u8; 33]) -> usize {
    open_cases(e)
        .iter()
        .filter(|c| c.fault == hawkeye_store::FaultKind::FraudulentMint && c.target_key == target)
        .count()
}

/// A rogue proposal by guardian `r` over an invented lockId; returns (lockId, its block).
async fn rogue_proposal(env: &Env, r: usize, fake: [u8; 32]) -> u64 {
    let to = env.holder.eth_address();
    let digest = hawkeye_core::eip712::Domain::new(31337, EthAddress(env.dep.bridge.0.0))
        .mint_digest(&fake, 700_000_000, &to);
    let sig = hawkeye_core::eth::sign_digest(&env.keys[r], &digest).unwrap();
    let p = env
        .eth(&env.keys[r])
        .await
        .propose_mint(
            B256::from(fake),
            U256::from(700_000_000u64),
            hawkeye::convert::addr(&to),
            &sig,
        )
        .await
        .unwrap();
    match p {
        hawkeye_eth::MintSubmitted::Proposed { mined, .. } => mined.block_number,
        other => panic!("not a proposal: {other:?}"),
    }
}

/// Acceptance 1 (both fixtures): a proposal mined at `latest` is a provisional deferred check
/// within one tick of its block, before that block is final.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn o1_proposal_recorded_within_a_tick_before_finality() {
    for slots in [1u64, 32] {
        let Some(env) = setup_with(Opts { slots, ..opt() }).await else {
            return;
        };
        let mut engines = three(&env).await;
        tick_all(&mut engines).await;
        let fake = [0xa1; 32];
        let block = rogue_proposal(&env, 1, fake).await;
        assert!(
            env.finalized().await < block,
            "slots {slots}: not final yet"
        );
        tick_all(&mut engines).await;
        for (i, e) in engines.iter().enumerate() {
            assert_eq!(
                pending_provisional(e, &fake),
                vec![true],
                "slots {slots}: attestor {i} records it provisionally"
            );
        }
    }
}

/// The H-2 test (05/T-3): finality pinned 64 blocks behind the head (`--slots-in-an-epoch 32`,
/// 12 s blocks) and a 60 s window — a finalized-only watcher could never see the proposal in
/// time. Watchers challenge it while its block is unfinalized, `executeMint` after `eta` finds
/// nothing, and the FRAUDULENT_MINT case opens only once the proposal's block is final.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn o_proposal_seen_at_latest_challenged_before_eta() {
    let Some(env) = setup_with(Opts {
        slots: 32,
        window: 60,
        ..opt()
    })
    .await
    else {
        return;
    };
    let _: serde_json::Value = env
        .provider
        .raw_request(Cow::Borrowed("anvil_setBlockTimestampInterval"), (12u64,))
        .await
        .unwrap();
    let mut engines = three(&env).await;
    tick_all(&mut engines).await;
    let (r, fake) = (1, [0xcd; 32]);
    let block = rogue_proposal(&env, r, fake).await;
    let rogue = env.eth(&env.keys[r]).await;
    let mut rounds = 0;
    while rogue.proposal(B256::from(fake)).await.unwrap().is_some() {
        rounds += 1;
        assert!(rounds <= 4, "not challenged after {rounds} rounds");
        env.mine(1); // Ycash: the lock-absent rule counts C_Y blocks
        tick_all(&mut engines).await;
        env.eth_mine(1).await;
    }
    let fin = env.finalized().await;
    assert!(
        fin < block,
        "challenged while the proposal's block {block} is unfinalized (finalized {fin})"
    );
    // after eta nothing executes: the proposal is gone
    env.warp(120).await;
    let e = rogue.execute_mint(B256::from(fake)).await.unwrap_err();
    assert!(e.is_revert("NoProposal"), "{e}");
    for (i, e) in engines.iter().enumerate() {
        assert_eq!(
            fraud_cases(e, env.key_of_index(r)),
            0,
            "attestor {i}: no slash case from an unfinalized proposal"
        );
        assert!(
            !e.alarms().iter().any(|a| a.name == "fraudulent-mint"),
            "attestor {i}: {:?}",
            e.alarms()
        );
    }
    // the proposal's block finalizes: the finalized scan opens the case
    env.eth_mine(70).await;
    assert!(env.finalized().await >= block);
    for _ in 0..25 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for (i, e) in engines.iter().enumerate() {
        if i == r {
            continue;
        }
        assert_eq!(fraud_cases(e, env.key_of_index(r)), 1, "attestor {i}");
    }
    assert_eq!(rogue.total_supply().await.unwrap(), U256::ZERO);
}

/// A pinned `finalized` (finality stall) on mainnet semantics: `eth-finality-stall` within the
/// stall threshold, no own `Mint` signature or proposal, challenges continue; unpinned, the
/// alarm clears and the proposal goes out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn o2_stalled_finality_pauses_own_mints() {
    let Some(env) = setup_with(Opts {
        mint_cap: 100_000_000_000,
        ..opt()
    })
    .await
    else {
        return;
    };
    let chains: Vec<Arc<TestChain>> = vec![
        env.test_chain(0).await,
        env.test_chain(1).await,
        env.test_chain(2).await,
    ];
    let mut engines: Vec<Engine> = (0..3)
        .map(|i| {
            env.engine_on(i, vec![], chains[i].clone(), |p| {
                p.mainnet = true;
                p.drills = false;
            })
        })
        .collect();
    tick_all(&mut engines).await;
    let fin = env.finalized().await;
    for c in &chains {
        *c.pinned.lock().unwrap() = Some(fin);
    }
    tick_all(&mut engines).await;
    env.eth_mine(3).await;
    for e in engines.iter_mut() {
        e.advance_clock(std::time::Duration::from_secs(
            hawkeye_eth::mode::ETH_FINALITY_STALL_SECS,
        ));
    }
    tick_all(&mut engines).await;
    for e in &engines {
        assert!(e.finality_stalled());
        assert!(
            e.alarms().iter().any(|a| a.name == "eth-finality-stall"),
            "{:?}",
            e.alarms()
        );
    }
    // a policy-OK lock: neither signed nor proposed while stalled
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let lock_id = hawkeye_core::lock::lock_id(&op);
    env.mine(C_Y);
    for _ in 0..4 {
        tick_all(&mut engines).await;
        env.eth_mine(3).await;
    }
    for (i, e) in engines.iter().enumerate() {
        let l = e.ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap();
        assert_eq!(
            l.state,
            LockState::PolicyOk,
            "attestor {i}: no Mint signature"
        );
        assert_eq!(
            chains[i].proposes.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
    // challenges continue: a rogue proposal seen at `latest` is challenged during the stall
    let fake = [0xee; 32];
    rogue_proposal(&env, 1, fake).await;
    let rogue = env.eth(&env.keys[1]).await;
    let mut rounds = 0;
    while rogue.proposal(B256::from(fake)).await.unwrap().is_some() {
        rounds += 1;
        assert!(rounds <= 6, "not challenged during the stall");
        env.mine(1);
        tick_all(&mut engines).await;
        env.eth_mine(1).await;
    }
    // finality resumes: the alarm clears and the lock is proposed
    for c in &chains {
        *c.pinned.lock().unwrap() = None;
    }
    for _ in 0..4 {
        tick_all(&mut engines).await;
        env.eth_mine(3).await;
    }
    for e in &engines {
        assert!(!e.finality_stalled());
        assert!(!e.alarms().iter().any(|a| a.name == "eth-finality-stall"));
    }
    let c = env.eth(&env.holder).await;
    let states: Vec<_> = engines
        .iter()
        .map(|e| e.ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap().state)
        .collect();
    assert!(
        c.proposal(B256::from(lock_id)).await.unwrap().is_some(),
        "proposed once finality resumed: {states:?} {:?}",
        chains
            .iter()
            .map(|c| c.proposes.load(std::sync::atomic::Ordering::SeqCst))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        chains
            .iter()
            .map(|c| c.proposes.load(std::sync::atomic::Ordering::SeqCst))
            .sum::<usize>(),
        1
    );
}

/// A proposal seen at `latest` that is gone by the time it is due (reorged out) is never
/// challenged with a stale id; when its block finalizes without it, the provisional record is
/// dropped and no case opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn o3_reorged_proposal_never_challenged_with_stale_id() {
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let chain = env.test_chain(0).await;
    let mut e = vec![env.engine_on(0, vec![], chain.clone(), |_| {})];
    tick_all(&mut e).await;
    let fake = [0x77; 32];
    let block = env.latest().await + 1;
    env.eth_mine(1).await;
    chain
        .inject
        .lock()
        .unwrap()
        .push(hawkeye::foreign::Scanned {
            meta: hawkeye::foreign::EventMeta {
                height: block,
                block_hash: [0x55; 32],
                tx: hawkeye::foreign::TxId([0x66; 32]),
                index: 0,
            },
            event: hawkeye::foreign::ForeignEvent::MintProposed {
                lock_id: fake,
                proposal_id: 7,
                proposer: hawkeye::foreign::Guardian::Ethereum(env.keys[1].eth_address()),
                to: hawkeye::foreign::Account::Ethereum(env.holder.eth_address()),
                amount: 700_000_000,
                eta: u64::MAX,
            },
        });
    tick_all(&mut e).await;
    assert_eq!(pending_provisional(&e[0], &fake), vec![true]);
    // due by the lock-absent rule; the live proposal is absent: nothing is signed
    for _ in 0..4 {
        env.mine(1);
        tick_all(&mut e).await;
    }
    assert!(challenges(&e[0]).is_empty());
    // its block finalizes without it (the finalized scan never saw it): dropped, no case
    chain.inject.lock().unwrap().clear();
    env.eth_mine(5).await;
    for _ in 0..25 {
        env.mine(1);
        tick_all(&mut e).await;
    }
    assert!(pending_provisional(&e[0], &fake).is_empty());
    assert!(challenges(&e[0]).is_empty());
    assert_eq!(fraud_cases(&e[0], env.key_of_index(1)), 0);
}

/// The mainnet floors through the adapter (`startup_checks` bails on its error): a 3,600 s
/// window, then an unbounded cap, then both satisfied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn o4_mint_cap_zero_refused_on_mainnet() {
    use hawkeye::foreign::ForeignChain;
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let deployer =
        PrivateKeySigner::from_bytes(&B256::from_slice(&env._anvil.keys()[0].to_bytes())).unwrap();
    let guardians: Vec<Address> = env
        .keys
        .iter()
        .map(|k| hawkeye::convert::addr(&k.eth_address()))
        .collect();
    let check = |window: u64, cap: u128| {
        let env = &env;
        let deployer = deployer.clone();
        let guardians = guardians.clone();
        async move {
            let mut p = DeployParams::new(&guardians, 2, window, MintMode::Optimistic);
            p.mint_cap = cap;
            p.cap_window = if cap == 0 { 0 } else { 86_400 };
            let dep = deploy(&env.provider, deployer.address(), &p).await.unwrap();
            let mut c = EthConfig::new(env.url.clone(), 31337, dep.bridge);
            c.token = Some(dep.token);
            let chain =
                hawkeye::foreign::EthereumChain::new(EthClient::connect(&c, None).await.unwrap());
            (
                chain.check_bridge(true).await.map_err(|e| e.to_string()),
                chain.check_bridge(false).await.map_err(|e| e.to_string()),
            )
        }
    };
    let (main, dev) = check(3_600, 1_000_000_000).await;
    assert!(main.unwrap_err().contains("challengeWindow is 3600 s"));
    assert!(dev.is_ok());
    let (main, dev) = check(7_200, 0).await;
    assert!(main.unwrap_err().contains("mintCap is 0"));
    assert_eq!(dev.unwrap().mint_cap, 0);
    let (main, _) = check(7_200, 1_000_000_000).await;
    let info = main.unwrap();
    assert_eq!(
        (info.challenge_window, info.mint_cap, info.cap_window),
        (7_200, 1_000_000_000, 86_400)
    );
}

/// Mainnet semantics with the constructor's `MintLimitChanged(0, 0)` finalized: alarm
/// `mint-cap-unbounded`, own `Mint` signatures paused (audit 05/H-2); off mainnet, only a log.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn o5_unbounded_mint_cap_pauses_own_mints_on_mainnet() {
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let mut main = vec![
        env.engine_with(0, vec![], |p| {
            p.mainnet = true;
            p.drills = false;
        })
        .await,
    ];
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let lock_id = hawkeye_core::lock::lock_id(&op);
    env.mine(C_Y);
    eth_rounds(&env, &mut main, 4).await;
    assert!(
        main[0]
            .alarms()
            .iter()
            .any(|a| a.name == "mint-cap-unbounded"),
        "{:?}",
        main[0].alarms()
    );
    let l = main[0].ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap();
    assert_eq!(l.state, LockState::PolicyOk, "no Mint signature");
    drop(main);
    let mut dev = vec![env.engine(1).await];
    eth_rounds(&env, &mut dev, 4).await;
    assert!(
        !dev[0]
            .alarms()
            .iter()
            .any(|a| a.name == "mint-cap-unbounded")
    );
    let l = dev[0].ctx().db(|t| t.lock(&lock_id)).unwrap().unwrap();
    assert_ne!(l.state, LockState::PolicyOk, "signed off mainnet");
}

// ------------------------------------------------------------------------------------------
// audit 05/M-4: live parameter floors

/// `heartbeat_blocks` (10) above `livenesswindow / 4`: refused at start-up on mainnet; on regtest
/// the engine raises `heartbeat-too-slow` once a `SET_PARAMS` shrinks the window (the 60-tick
/// re-check), and clears it when the window grows back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r_heartbeat_floor_live() {
    let Some(env) = setup().await else {
        return;
    };
    let set_window = |w: u32| {
        env.mock
            .state()
            .sets
            .get_mut(&env.set)
            .unwrap()
            .set
            .params
            .livenesswindow = w;
    };
    set_window(20);
    let main = env
        .engine_with(0, vec![], |p| {
            p.mainnet = true;
            p.drills = false;
        })
        .await;
    let e = hawkeye::daemon::startup_checks(main.ctx())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("mainnet refuses bridge.heartbeat_blocks 10") && e.contains("livenesswindow 20"),
        "{e}"
    );
    drop(main);
    set_window(1000);
    let mut e = vec![env.engine(0).await];
    hawkeye::daemon::startup_checks(e[0].ctx()).await.unwrap();
    tick_all(&mut e).await;
    assert!(!e[0].alarms().iter().any(|a| a.name == "heartbeat-too-slow"));
    set_window(20);
    for _ in 0..60 {
        tick_all(&mut e).await;
    }
    let a = e[0].alarms();
    assert!(a.iter().any(|a| a.name == "heartbeat-too-slow"), "{a:?}");
    set_window(1000);
    for _ in 0..60 {
        tick_all(&mut e).await;
    }
    assert!(!e[0].alarms().iter().any(|a| a.name == "heartbeat-too-slow"));
}

/// Vaults of the bridge's tag and set whose delay is not `bridge.delay`: counted at start-up
/// (warned) and raised by the engine as `params-drift`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_delay_mismatch_warns() {
    let Some(env) = setup().await else {
        return;
    };
    env.lock(1_000_000_000, &env.holder.eth_address());
    let mut e = vec![env.engine_with(0, vec![], |p| p.delay = 12).await];
    assert_eq!(
        hawkeye::daemon::vault_delay_mismatch(e[0].ctx())
            .await
            .unwrap(),
        (1, 1)
    );
    hawkeye::daemon::startup_checks(e[0].ctx()).await.unwrap();
    tick_all(&mut e).await;
    assert!(
        e[0].alarms().iter().any(|a| a.name == "params-drift"),
        "{:?}",
        e[0].alarms()
    );
    let same = env.engine(1).await;
    assert_eq!(
        hawkeye::daemon::vault_delay_mismatch(same.ctx())
            .await
            .unwrap(),
        (0, 1)
    );
}
