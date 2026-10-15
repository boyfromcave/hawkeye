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
use hawkeye::peer_auth::PeerSigner;
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
        branch: u32,
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
        let expect = hawkeye_ycash::mock::MockState::branch_sighash(&tx, input_index, branch);
        let mut signers = vec![];
        let mut sighash = [0u8; 32];
        for a in &spend.args {
            let sig: [u8; 65] = a.as_slice().try_into().map_err(|_| "not 65 bytes")?;
            if sig[34..] != expect.0[..31] {
                continue;
            }
            sighash[..31].copy_from_slice(&sig[34..]);
            signers.push(SetSigner {
                pubkey: sig[1..34].try_into().expect("33"),
                signature: sig,
            });
        }
        if signers.is_empty() {
            return Err("no set signature under this branch".into());
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
    /// The set's `unlockThreshold` (the §2 row: 1).
    unlock_threshold: u32,
    /// The set's `cancelThreshold` (the §2 row: 1).
    cancel_threshold: u32,
    /// Each attestor signs through its own wallet view of the shared mock (`a<i>`: its member
    /// key only), as separate nodes would; needed for thresholds above 1.
    wallet_views: bool,
    /// The set's `ratelimitbps` (0: no rate limit).
    ratelimitbps: u32,
    /// anvil's `--slots-in-an-epoch`: finalized = latest − 2 × slots (audit 05/T-3: 32 pins
    /// finality 64 blocks behind the head, as on mainnet).
    slots: u64,
    /// The bridge's challenge window, seconds.
    window: u64,
    /// The bridge's `mintCap` per day (0: no limit; mainnet semantics then pause own mints).
    mint_cap: u128,
    /// The set's members (and seats).
    members: u8,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            mode: MintMode::Threshold { k: 1 },
            min_owner_age: 400,
            roll_margin: 50,
            unlock_threshold: 1,
            cancel_threshold: 1,
            wallet_views: false,
            ratelimitbps: 0,
            slots: 1,
            window: WINDOW,
            mint_cap: 0,
            members: 3,
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
    let keys: Vec<SecretKey> = (1..=opts.members).map(secret).collect();
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
        seats: u32::from(opts.members),
        unlockthreshold: opts.unlock_threshold,
        cancelthreshold: opts.cancel_threshold,
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
    for (i, k) in keys.iter().enumerate() {
        st.add_member(&set, PubKey(k.public_key()), true);
        if opts.wallet_views {
            st.wallet_views
                .insert(format!("a{i}"), [PubKey(k.public_key())].into());
        }
    }
    // fee coins (plan §5.5: at least 8, the fee-coins-low floor)
    st.add_wallet_coins(10, 100_000_000);
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
            accept_blind_start: false,
            ycash_start_height: Some(1),
            ycash_signing: hawkeye::config::YcashSigning::Wallet,
            min_sender_balance_wei: 0,
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
        self.engine_with_peers(i, vec![]).await
    }

    /// Attestor `i`'s engine with peer API URLs and adjusted parameters.
    async fn engine_with(
        &self,
        i: usize,
        peers: Vec<String>,
        adjust: impl FnOnce(&mut Params),
    ) -> Engine {
        self.engine_full(i, peers, None, adjust).await
    }

    /// Attestor `i`'s node client: its own wallet view when the set needs per-member signing.
    fn node(&self, i: usize) -> hawkeye_ycash::YcashRpc {
        if self.opts.wallet_views {
            self.mock.wallet_client(&format!("a{i}"))
        } else {
            self.mock.client()
        }
    }

    /// A member-key request signer for `key` (the peer channel, HK-13).
    fn signer(&self, key: &SecretKey) -> PeerSigner {
        PeerSigner {
            key: key.clone(),
            set_id: self.set.0,
            deployment: self.params().deployment,
            require_auth: true,
        }
    }

    /// Attestor `i`'s engine, asking `peers` (signed with its member key).
    async fn engine_with_peers(&self, i: usize, peers: Vec<String>) -> Engine {
        self.engine_full(i, peers, None, |_| {}).await
    }

    /// Attestor `i`'s engine whose Ethereum transactions are sent by `sender` (a gas account,
    /// 05/M-1) instead of its member key.
    async fn engine_full(
        &self,
        i: usize,
        peers: Vec<String>,
        sender: Option<SecretKey>,
        adjust: impl FnOnce(&mut Params),
    ) -> Engine {
        let eth_key = sender.unwrap_or_else(|| self.keys[i].clone());
        let foreign = Arc::new(hawkeye::foreign::EthereumChain::new(
            self.eth(&eth_key).await,
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
        self.engine_db(i, &format!("attestor{i}.db"), peers, foreign, adjust)
    }

    /// As [`Env::engine_on`] over the ledger file `db` (a restored attestor: a fresh ledger).
    fn engine_db(
        &self,
        i: usize,
        db: &str,
        peers: Vec<String>,
        foreign: Arc<dyn hawkeye::foreign::ForeignChain>,
        adjust: impl FnOnce(&mut Params),
    ) -> Engine {
        let key = self.keys[i].clone();
        let store = Store::open(self.dir.path().join(db)).unwrap();
        let mut params = self.params();
        adjust(&mut params);
        Engine::new(Ctx {
            params: Arc::new(params),
            me: key.public_key(),
            foreign,
            ycash: Arc::new(self.node(i)),
            store: Arc::new(Mutex::new(store)),
            attributor: Arc::new(MockAttributor { set: self.set.0 }),
            peers: Peers::new(peers).unwrap().with_signer(self.signer(&key)),
            key,
            auth: Arc::new(hawkeye::peer_auth::AuthState::default()),
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
            .db(|t| {
                Ok((
                    t.lock(&lock_id)?.unwrap(),
                    t.mint_signatures_any(&lock_id)
                        .map(|v| v.into_iter().next())?,
                ))
            })
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
    let ctx0 = engines[0].ctx().clone();
    tokio::spawn(async move { hawkeye::api::serve(listener, ctx0).await.unwrap() });
    let peers = Peers::new(vec![format!("http://{addr}")])
        .unwrap()
        .with_signer(env.signer(&env.keys[1]));
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
        .db(|t| {
            t.mint_signatures_any(&lock_id)
                .map(|v| v.into_iter().next())
        })
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
        .map(|e| {
            e.ctx()
                .db(|t| {
                    t.mint_signatures_any(&lock_id)
                        .map(|v| v.into_iter().next())
                })
                .unwrap()
                .unwrap()
        })
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
        let after = e
            .ctx()
            .db(|t| {
                t.mint_signatures_any(&lock_id)
                    .map(|v| v.into_iter().next())
            })
            .unwrap()
            .unwrap();
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
    // the leader's engine stalls, its API still answers (01/V-2, review M-1: a takeover signs a
    // fresh vault only on every previous leader's signed "I hold no unlock for it")
    let (mut engines, _urls) = networked(&env).await;
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
    // the leader's engine stalls, its API still answers (01/V-2, review M-1: a takeover signs a
    // fresh vault only on every previous leader's signed "I hold no unlock for it")
    let (mut engines, _urls) = networked(&env).await;
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

/// Three engines, each serving its peer API on a loopback port and asking the other two
/// (member-key signed, HK-13).
async fn networked(env: &Env) -> (Vec<Engine>, Vec<String>) {
    let mut listeners = vec![];
    let mut urls = vec![];
    for _ in 0..3 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}", l.local_addr().unwrap()));
        listeners.push(l);
    }
    let mut engines = vec![];
    for i in 0..3 {
        let peers = (0..3)
            .filter(|j| *j != i)
            .map(|j| urls[j].clone())
            .collect();
        engines.push(env.engine_with_peers(i, peers).await);
    }
    for (l, e) in listeners.into_iter().zip(&engines) {
        let ctx = e.ctx().clone();
        tokio::spawn(async move { hawkeye::api::serve(l, ctx).await.unwrap() });
    }
    (engines, urls)
}

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

/// Audit W3-B-2: with `auto_slash = false` no act signature leaves this attestor, for its own
/// case or for a peer's `POST /slash/sign`, until its operator approves that case; a rejected case
/// is never signed and expires; a decision answers the `slash-case-<id>` page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w3b2_slash_vote_waits_for_operator() {
    use hawkeye::engine::slash::verify_and_sign;
    use hawkeye::peers::SlashSignRequest;
    use hawkeye_store::SlashDecision;
    let Some(env) = setup().await else { return };
    let mut engines = vec![];
    for i in 0..3 {
        engines.push(env.engine_with(i, vec![], |p| p.auto_slash = false).await);
    }
    lock_and_mint(&env, &mut engines).await;
    let (_, rogue_key) = rogue_unlock(&env).await;
    tick_all(&mut engines).await;
    tick_all(&mut engines).await;
    let rogue = index_of(&env, &rogue_key);
    let peer = (rogue + 1) % 3;
    let other = (rogue + 2) % 3;
    let case_of = |e: &Engine| {
        open_cases(e)
            .into_iter()
            .find(|c| c.target_key == rogue_key)
            .expect("a case against the rogue")
    };
    let page = |e: &Engine, id: i64| {
        let name = format!("slash-case-{id}");
        e.alarms().iter().any(|a| a.name == name)
    };
    let case = case_of(&engines[other]);
    assert!(
        page(&engines[other], case.id),
        "{:?}",
        engines[other].alarms()
    );
    // the owner's loop built no act: nothing was signed anywhere
    assert_eq!(env.mock.state().calls_to("set_buildact").len(), 0);
    assert_eq!(env.mock.state().calls_to("set_signact").len(), 0);
    let evidence: serde_json::Value = serde_json::from_str(&case.evidence_json).unwrap();
    let req = SlashSignRequest {
        evidence,
        act: remove_act(&env, rogue_key).await,
    };
    let refused = |r: anyhow::Result<_>| format!("{:#}", r.unwrap_err());

    // 1. undecided: the verified request is recorded as a local case and refused, unsigned
    let e = refused(verify_and_sign(engines[peer].ctx(), &req).await);
    assert!(e.contains("pending operator decision"), "{e}");
    let mine = case_of(&engines[peer]);
    assert_eq!(env.mock.state().calls_to("set_signact").len(), 0);

    // 2. rejected: refused for good; the case expires and the page is answered
    engines[peer]
        .ctx()
        .db(|t| t.decide_slash(mine.id, SlashDecision::Reject, "not convinced"))
        .unwrap();
    queue_remove_decode(&env, rogue_key);
    let e = refused(verify_and_sign(engines[peer].ctx(), &req).await);
    assert!(e.contains("rejected slash case"), "{e}");
    assert_eq!(env.mock.state().calls_to("set_signact").len(), 0);
    tick_all(&mut engines).await;
    let after = engines[peer]
        .ctx()
        .db(|t| t.slash_case(mine.id))
        .unwrap()
        .unwrap();
    assert_eq!(after.state, SlashState::Expired);
    assert!(
        !page(&engines[peer], mine.id),
        "{:?}",
        engines[peer].alarms()
    );

    // 3. approved: the same request is signed (re-verified), and the page is answered
    engines[other]
        .ctx()
        .db(|t| t.decide_slash(case.id, SlashDecision::Approve, "verified"))
        .unwrap();
    queue_remove_decode(&env, rogue_key);
    let r = verify_and_sign(engines[other].ctx(), &req).await.unwrap();
    assert!(r.signatures >= 1, "{r:?}");
    assert_eq!(env.mock.state().calls_to("set_signact").len(), 1);
    tick_all(&mut engines).await;
    assert!(
        !page(&engines[other], case.id),
        "{:?}",
        engines[other].alarms()
    );
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
    let cancel = |value: i64| {
        let tx = Transaction::new_v4(
            vec![TxIn {
                prevout: OutPoint::new(Hash256(intent.txid), intent.vout),
                script_sig: vec![],
                sequence: u32::MAX,
            }],
            vec![TxOut {
                value,
                script_pubkey: vault_spk.clone(),
            }],
            0,
            0,
        );
        let sh = hawkeye_ycash::mock::MockState::branch_sighash(&tx, 0, 0x6d5b_7a31);
        let sig = hawkeye_ycash::mock::mock_set_sig(&PubKey(cheat), &sh);
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
        .submit(cancel(100_000_000).encode())
        .unwrap();
    tick_all(&mut engines).await;
    assert!(env.mock.state().calls_to("set_equivocation").is_empty());
    {
        let mut st = env.mock.state();
        st.mempool.retain(|t| *t != first);
        st.submit(cancel(99_000_000).encode()).unwrap();
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

// ------------------------------------------------------------------------------------------
// (k) the peer channel (remedial report 05/H-1, HK-13): member-signed requests, `/unlock/sign`
// inert at unlockThreshold 1 and leader-gated above it, one live vault per burn, reused unlocks
// and co-signatures checked, cancel co-signing and fee-coin capacity

fn views(unlock: u32, cancel: u32) -> Opts {
    Opts {
        unlock_threshold: unlock,
        cancel_threshold: cancel,
        wallet_views: true,
        ..Opts::default()
    }
}

/// An unlock of `vault` paying `amount` to `r`, unsigned, with burn `nonce`'s memo if given.
async fn unlock_hex(
    env: &Env,
    vault: &OutPoint,
    r: &YcashRecipient,
    amount: i64,
    memo: Option<&hawkeye_core::memo::HawkeyeMemo>,
) -> String {
    // a fresh build every call (`rebuild`): the node remembers one build per vault (07/N-2),
    // these tests want distinct spends of one vault
    let built = env
        .mock
        .client()
        .vault_buildunlock_with(
            vault,
            &[hawkeye_ycash::types::Recipient::script(
                r.script(),
                Amount(amount),
            )],
            true,
        )
        .await
        .unwrap()
        .hex
        .to_string();
    let with = match memo {
        Some(m) => hawkeye_ycash::tx::insert_op_return(&built, &m.encode()).unwrap(),
        None => built,
    };
    // as Hawkeye builds them: no change output, funded exactly (review H-1)
    let value = {
        let st = env.mock.state();
        u64::try_from(st.templates[vault].valuezat()).unwrap()
    };
    hawkeye::engine::sign::fund_exactly(
        &env.mock.client(),
        &with,
        &CoreOutPoint::new(vault.txid.0, vault.vout),
        value,
    )
    .await
    .unwrap()
}

/// The set's vaults no transaction (mempool included) spends.
async fn free_vaults(env: &Env) -> Vec<OutPoint> {
    let c = env.mock.client();
    let mut out = vec![];
    for v in vaults(env) {
        if c.gettxout(&v.txid, v.vout, true).await.unwrap().is_some() {
            out.push(v);
        }
    }
    out
}

fn vaults(env: &Env) -> Vec<OutPoint> {
    let st = env.mock.state();
    st.templates
        .iter()
        .filter(|(_, t)| t.as_vault().is_some())
        .map(|(op, _)| *op)
        .collect()
}

/// The leader of burn `nonce` among the three (`nonce mod |live|` over the sorted keys).
fn leader_index(env: &Env, nonce: u64) -> usize {
    let mut live: Vec<[u8; 33]> = (0..3).map(|i| env.key_of_index(i)).collect();
    hawkeye_core::keys::sort_members(&mut live);
    index_of(env, &live[(nonce % 3) as usize])
}

/// The mempool transactions carrying burn `nonce`'s memo, and the vault each spends.
fn unlocks_for(env: &Env, nonce: u64) -> Vec<(Transaction, OutPoint)> {
    let vaults: Vec<OutPoint> = vaults(env);
    mempool_txs(env)
        .into_iter()
        .filter(|t| {
            t.outputs.iter().any(|o| {
                matches!(parse_memo_script(&o.script_pubkey), Ok(Some(m)) if m.reference == nonce)
            })
        })
        .filter_map(|t| {
            let v = t
                .inputs
                .iter()
                .map(|i| i.prevout)
                .find(|p| vaults.contains(p))?;
            Some((t, v))
        })
        .collect()
}

/// (k1) HK-1: at unlockThreshold 1 the endpoint is inert (and so is `/cancel/sign` at
/// cancelThreshold 1); unsigned, stale, replayed and non-member requests never reach a
/// signing closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k1_signing_routes_authenticated_and_inert_at_threshold_one() {
    use hawkeye::peers::{CancelSignRequest, SlashSignRequest, UnlockSignRequest};
    let Some(env) = setup().await else { return };
    let (mut engines, urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x44; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    engines[1].tick().await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[1].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    let memo = hawkeye_core::memo::HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let free = free_vaults(&env).await;
    let hex = unlock_hex(&env, &free[0], &r, 300_000_000, Some(&memo)).await;
    let req = UnlockSignRequest { hex: hex.clone() };
    let signs = || env.mock.state().calls_to("set_signunlock").len();
    let before = signs();
    // unsigned: 401
    let anon = Peers::new(vec![]).unwrap();
    let e = anon
        .unlock_sign(&urls[1], &req)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("401") && e.contains("missing"), "{e}");
    // signed by a key that is no member: 403
    let outsider = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.holder));
    let e = outsider
        .unlock_sign(&urls[1], &req)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("403") && e.contains("not a current member"),
        "{e}"
    );
    let e = outsider
        .slash_sign(
            &urls[1],
            &SlashSignRequest {
                evidence: serde_json::json!({}),
                act: "00".into(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("not a current member"), "{e}");
    // signed by the burn's leader, a current member: the endpoint is inert at threshold 1
    let leader = leader_index(&env, nonce);
    let member = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[leader]));
    let e = member
        .unlock_sign(&urls[1], &req)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("403") && e.contains("disabled"), "{e}");
    let e = member
        .cancel_sign(
            &urls[1],
            &CancelSignRequest {
                hex: hex.clone(),
                intent: format!("{}:0", "00".repeat(32)),
            },
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("disabled"), "{e}");
    // a replayed request (same nonce) and a stale one are refused before the handler
    let http = reqwest::Client::new();
    let body = serde_json::to_vec(&req).unwrap();
    let sr = env
        .signer(&env.keys[leader])
        .sign("/unlock/sign", &body)
        .unwrap();
    let send = |headers: Vec<(&'static str, String)>| {
        let mut rb = http
            .post(format!("{}/unlock/sign", urls[1]))
            .header("content-type", "application/json");
        for (n, v) in headers {
            rb = rb.header(n, v);
        }
        rb.body(body.clone()).send()
    };
    assert_eq!(send(sr.headers.clone()).await.unwrap().status(), 403);
    let replay = send(sr.headers.clone()).await.unwrap();
    assert_eq!(replay.status(), 401);
    assert!(replay.text().await.unwrap().contains("replayed"));
    let old = 1_000_000u64;
    let nonce16 = [7u8; 16];
    let msg = hawkeye_core::peerauth::request_msg(&hawkeye_core::peerauth::PeerRequest {
        set_id: &env.set.0,
        deployment: &dep_of(&engines[0]),
        method: "POST",
        path: "/unlock/sign",
        timestamp: old,
        nonce: &nonce16,
        body: &body,
    })
    .unwrap();
    let sig = hawkeye_core::peerauth::sign(&env.keys[leader], &msg).unwrap();
    let stale = send(vec![
        ("x-hawkeye-member", hex::encode(env.key_of_index(leader))),
        ("x-hawkeye-time", old.to_string()),
        ("x-hawkeye-nonce", hex::encode(nonce16)),
        ("x-hawkeye-sig", hex::encode(sig)),
    ])
    .await
    .unwrap();
    assert_eq!(stale.status(), 401);
    assert!(stale.text().await.unwrap().contains("stale"));
    // a signature over another path (a /slash/sign body replayed to /unlock/sign) does not recover
    let other = env
        .signer(&env.keys[leader])
        .sign("/slash/sign", &body)
        .unwrap();
    let r2 = send(other.headers).await.unwrap();
    assert_eq!(r2.status(), 401);
    assert_eq!(signs(), before, "no request reached a signing closure");
    // the read-only routes stay public
    let view = anon
        .lock(&urls[1], &format!("0x{}", hex::encode([0u8; 32])))
        .await;
    assert!(view.unwrap_err().to_string().contains("404"));
}

/// (k) unlockThreshold 2: `POST /unlock/sign` co-signs only a member-signed request of the
/// burn's leader here, only a burn ↔ memo match, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k_unlock_cosign_endpoint() {
    use hawkeye::peers::UnlockSignRequest;
    use hawkeye_core::memo::HawkeyeMemo;
    let Some(env) = setup_with(views(2, 1)).await else {
        return;
    };
    let (mut engines, urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x44; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let peer = (leader + 1) % 3;
    let third = (leader + 2) % 3;
    // only the peer ticks: it holds the finalized burn and posts nothing
    engines[peer].tick().await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[peer].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    assert_eq!(b.state, BurnState::Assigned);
    assert_eq!(b.leader, Some(env.key_of_index(leader)));
    let vault = vaults(&env)[0];
    let memo = HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let as_member = |i: usize| {
        Peers::new(vec![])
            .unwrap()
            .with_signer(env.signer(&env.keys[i]))
    };
    let with = unlock_hex(&env, &vault, &r, 300_000_000, Some(&memo)).await;
    let signs = || env.mock.state().calls_to("set_signunlock").len();
    let before = signs();
    // unsigned: 401; another member, not the leader: refused
    let e = Peers::new(vec![])
        .unwrap()
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: with.clone() })
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("401"), "{e}");
    let e = as_member(third)
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: with.clone() })
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("not the burn's leader"), "{e}");
    // the leader, no memo: refused
    let bare = unlock_hex(&env, &vault, &r, 300_000_000, None).await;
    let e = as_member(leader)
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: bare })
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("does not match"), "{e}");
    assert_eq!(signs(), before);
    // the leader, the burn's memo: co-signed once, the answer signed by the peer
    let ok = as_member(leader)
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: with.clone() })
        .await
        .unwrap();
    assert_eq!(ok.responder, Some(env.key_of_index(peer)));
    assert_eq!(ok.body.matched, format!("burn {nonce}"));
    assert!(!ok.body.complete, "one of two signatures");
    assert_eq!(signs(), before + 1);
    let again = as_member(leader)
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: with })
        .await
        .unwrap();
    assert_eq!(again.body.hex, ok.body.hex);
    assert_eq!(signs(), before + 1, "a repeat calls no node");
    // another spend of the same vault (other outputs) is never co-signed; the same unlock
    // re-funded (only its fee input differs) is the same spend: the existing signature
    let refunded = unlock_hex(&env, &vault, &r, 300_000_000, Some(&memo)).await;
    let merged = as_member(leader)
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: refunded })
        .await
        .unwrap();
    assert_eq!(signs(), before + 1, "merged, not signed again");
    assert_eq!(
        hawkeye::engine::burn::unlock_signatures(&merged.body.hex).unwrap(),
        1
    );
    let other = unlock_hex(&env, &vault, &r, 200_000_000, Some(&memo)).await;
    let e = as_member(leader)
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: other })
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("403"), "{e}");
    assert_eq!(signs(), before + 1, "never signed");
    let rows = engines[peer]
        .ctx()
        .db(|t| t.unlock_burn_rows(&env.set.0, &k))
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].origin, hawkeye_store::UnlockOrigin::Cosign);
}

/// (k2) The per-burn dimension: a burn the peer co-signed on V1 is never co-signed on V2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k2_per_burn_sign_once() {
    use hawkeye::peers::UnlockSignRequest;
    use hawkeye_core::memo::HawkeyeMemo;
    let Some(env) = setup_with(views(2, 1)).await else {
        return;
    };
    let (mut engines, urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x45; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let peer = (leader + 1) % 3;
    engines[peer].tick().await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[peer].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    let memo = HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let vs = vaults(&env);
    assert!(vs.len() >= 2);
    let leader_peers = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[leader]));
    let v1 = unlock_hex(&env, &vs[0], &r, 300_000_000, Some(&memo)).await;
    leader_peers
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: v1 })
        .await
        .unwrap();
    let before = env.mock.state().calls_to("set_signunlock").len();
    let v2 = unlock_hex(&env, &vs[1], &r, 300_000_000, Some(&memo)).await;
    let e = leader_peers
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: v2 })
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains(&format!("burn {k}")), "{e}");
    assert_eq!(
        env.mock.state().calls_to("set_signunlock").len(),
        before,
        "the second vault never reached the node"
    );
}

/// (k3) Audit 01/V-2 on finding 05/N-1: a co-signed (not leader) unlock for the burn sits in the
/// leader's ledger and its fee input is spent `C_Y` deep — the point where the old rule declared
/// it dead and signed another vault. It is still revivable (anyone may re-fund it); an attacker
/// does, and the leader re-sends it re-funded too: the burn is paid **once**, on that vault, and
/// no member ever signs a second vault for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k3_revived_cosigned_unlock_pays_the_burn_once() {
    use hawkeye_core::memo::HawkeyeMemo;
    use hawkeye_store::{UnlockBurn, UnlockOrigin, YcashSignKey};
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x46; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let other = (leader + 1) % 3;
    engines[other].tick().await;
    let b_hash = engines[other]
        .ctx()
        .db(|t| t.burn(&k))
        .unwrap()
        .unwrap()
        .tx_hash;
    let v1 = vaults(&env)[0];
    let memo = HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b_hash);
    let hex = unlock_hex(&env, &v1, &r, 300_000_000, Some(&memo)).await;
    let signed = env
        .mock
        .client()
        .set_signunlock(&hex.parse().unwrap())
        .await
        .unwrap();
    let key = YcashSignKey {
        domain: hawkeye_store::SignDomain::YcashUnlock,
        set_id: env.set.0,
        prevout: CoreOutPoint::new(v1.txid.0, v1.vout),
    };
    engines[leader]
        .ctx()
        .db(|t| {
            t.sign_once_unlock(
                &key,
                Some(&UnlockBurn {
                    key: k,
                    origin: UnlockOrigin::Cosign,
                    allow_double: false,
                }),
                &hex,
                |_| Ok::<_, String>((signed.hex.to_string(), signed.sighash.0)),
            )
        })
        .unwrap();
    // its fee input is spent elsewhere and buried C_Y + 1 deep
    let tx = Transaction::decode(&signed.hex.0).unwrap();
    let fee = tx.inputs.iter().find(|i| i.prevout != v1).unwrap().prevout;
    let spend = Transaction::new_v4(
        vec![TxIn {
            prevout: fee,
            script_sig: vec![0x51],
            sequence: u32::MAX,
        }],
        vec![TxOut {
            value: 1000,
            script_pubkey: YcashRecipient::p2pkh([0x13; 20]).script(),
        }],
        0,
        0,
    );
    env.mock.state().submit(spend.encode()).unwrap();
    env.mine(C_Y + 1);
    let builds = env.mock.state().calls_to("vault_buildunlock").len();
    // the attacker revives the signed bytes: re-funded by anyone, still a valid unlock
    let c = env.mock.client();
    let revived = c.vault_refee(&signed.hex).await.unwrap();
    c.vault_send(&revived.hex).await.unwrap();
    for _ in 0..3 {
        tick_all(&mut engines).await;
    }
    env.mine(1);
    for _ in 0..u32::from(DELAY) + 2 {
        tick_all(&mut engines).await;
        env.mine(1);
    }
    tick_all(&mut engines).await;
    assert_eq!(
        env.mock.state().calls_to("vault_buildunlock").len(),
        builds,
        "no member built another unlock for the burn"
    );
    for (i, e) in engines.iter().enumerate() {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::Released, "attestor {i}");
        let paying: Vec<_> = e
            .ctx()
            .db(|t| {
                let mut v = vec![];
                for st in [
                    IntentState::Matched,
                    IntentState::Released,
                    IntentState::Unmatched,
                    IntentState::CancelSent,
                    IntentState::Cancelled,
                ] {
                    v.extend(t.intents_in_state(st)?);
                }
                Ok(v)
            })
            .unwrap()
            .into_iter()
            .filter(|i| {
                i.memo.as_deref().is_some_and(|m| {
                    hawkeye_core::memo::HawkeyeMemo::decode(m).is_ok_and(|m| m.reference == nonce)
                })
            })
            .collect();
        assert_eq!(paying.len(), 1, "attestor {i}: one intent pays the burn");
        assert_eq!(
            paying[0].origin_vault,
            Some(key.prevout),
            "on the co-signed vault"
        );
        for row in e.ctx().db(|t| t.unlock_burn_rows(&env.set.0, &k)).unwrap() {
            assert_eq!(
                row.prevout, key.prevout,
                "attestor {i}: never a second vault"
            );
            assert!(row.is_live(), "never declared dead");
        }
    }
}

/// (k8) Takeover with prior signed bytes (audit 01/V-2): the burn's leader signed an unlock
/// that never left (its send failed) and went silent. The takeover leader finds those bytes
/// on the old leader's `GET /burns/<nonce>`, adopts them and sends them re-funded on the same
/// vault, instead of signing a second vault that a revival of the first would double.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k8_takeover_resends_the_previous_signed_unlock() {
    let Some(env) = setup().await else { return };
    let (mut engines, _urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x49; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    for (i, e) in engines.iter_mut().enumerate() {
        if i != leader {
            e.tick().await;
        }
    }
    env.mock
        .state()
        .inject_error("vault_send", -26, "16: mock refusal");
    engines[leader].tick().await;
    assert!(unlocks_for(&env, nonce).is_empty(), "the send failed");
    let first = engines[leader]
        .ctx()
        .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
        .unwrap()
        .unwrap()
        .prevout;
    let builds = env.mock.state().calls_to("vault_buildunlock").len();
    // the leader falls silent; the others take the burn over after TAKEOVER blocks
    for _ in 0..TAKEOVER + 1 {
        env.mine(1);
        for (i, e) in engines.iter_mut().enumerate() {
            if i != leader {
                e.tick().await;
            }
        }
    }
    // the takeover leader sent it, and it is mined: every watching attestor links the burn to
    // an intent of the previous leader's vault
    for (i, e) in engines.iter().enumerate() {
        if i == leader {
            continue;
        }
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert!(
            matches!(
                b.state,
                BurnState::IntentPending | BurnState::IntentConfirmed
            ),
            "attestor {i}: {:?}",
            b.state
        );
        let intent = e
            .ctx()
            .db(|t| t.intent(&b.intent.unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(
            intent.origin_vault,
            Some(first),
            "the previous leader's vault"
        );
    }
    assert_eq!(
        env.mock.state().calls_to("vault_buildunlock").len(),
        builds,
        "no new unlock was built"
    );
    let next = (0..3)
        .find(|i| {
            *i != leader
                && engines[*i]
                    .ctx()
                    .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
                    .unwrap()
                    .is_some()
        })
        .expect("the takeover leader recorded it");
    let row = engines[next]
        .ctx()
        .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
        .unwrap()
        .unwrap();
    assert_eq!(row.prevout, first);
    assert_eq!(row.origin, hawkeye_store::UnlockOrigin::Adopted);
}

/// (k9) The same at `unlockThreshold = 2`: the silent leader's unlock carries its own and a
/// co-signer's signature; whichever member takes over — the co-signer re-sending its row, or
/// the third adopting it from a peer — sends those bytes re-funded and builds nothing new.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9_takeover_at_unlock_threshold_two_resends_the_cosigned_unlock() {
    let Some(env) = setup_with(views(2, 1)).await else {
        return;
    };
    let (mut engines, _urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x49; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    for (i, e) in engines.iter_mut().enumerate() {
        if i != leader {
            e.tick().await;
        }
    }
    env.mock
        .state()
        .inject_error("vault_send", -26, "16: mock refusal");
    engines[leader].tick().await;
    assert!(unlocks_for(&env, nonce).is_empty(), "the send failed");
    let first = engines[leader]
        .ctx()
        .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
        .unwrap()
        .unwrap()
        .prevout;
    let builds = env.mock.state().calls_to("vault_buildunlock").len();
    // the leader falls silent; the others take the burn over after TAKEOVER blocks
    for _ in 0..TAKEOVER + 1 {
        env.mine(1);
        for (i, e) in engines.iter_mut().enumerate() {
            if i != leader {
                e.tick().await;
            }
        }
    }
    // the takeover leader sent it, and it is mined: every watching attestor links the burn to
    // an intent of the previous leader's vault
    for (i, e) in engines.iter().enumerate() {
        if i == leader {
            continue;
        }
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert!(
            matches!(
                b.state,
                BurnState::IntentPending | BurnState::IntentConfirmed
            ),
            "attestor {i}: {:?}",
            b.state
        );
        let intent = e
            .ctx()
            .db(|t| t.intent(&b.intent.unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(
            intent.origin_vault,
            Some(first),
            "the previous leader's vault"
        );
    }
    assert_eq!(
        env.mock.state().calls_to("vault_buildunlock").len(),
        builds,
        "no new unlock was built"
    );
    let next = (0..3)
        .find(|i| {
            *i != leader
                && engines[*i]
                    .ctx()
                    .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
                    .unwrap()
                    .is_some()
        })
        .expect("the takeover leader recorded it");
    let row = engines[next]
        .ctx()
        .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
        .unwrap()
        .unwrap();
    assert_eq!(row.prevout, first);
    assert!(
        matches!(
            row.origin,
            hawkeye_store::UnlockOrigin::Leader | hawkeye_store::UnlockOrigin::Cosign
        ),
        "its own co-signed row re-sent, or the previous unlock adopted: {:?}",
        row.origin
    );
}

/// (k10) A co-signer asked again for the **same** unlock re-funded (other fee inputs, 01/V-2)
/// adds the signature it already made over that sighash — no new signature, no sign-once
/// conflict; another unlock of the vault is still refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k10_cosigner_merges_its_signature_into_a_refunded_unlock() {
    use hawkeye::peers::UnlockSignRequest;
    use hawkeye_core::memo::HawkeyeMemo;
    let Some(env) = setup_with(views(2, 1)).await else {
        return;
    };
    let (mut engines, urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x4a; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let peer = (leader + 1) % 3;
    engines[peer].tick().await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[peer].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    let memo = HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let vault = vaults(&env)[0];
    let hex = unlock_hex(&env, &vault, &r, 300_000_000, Some(&memo)).await;
    let as_leader = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[leader]));
    let first = as_leader
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: hex.clone() })
        .await
        .unwrap();
    let signs = env.mock.state().calls_to("set_signunlock").len();
    // the same unlock, re-funded: other fee inputs, same template input and outputs
    let refunded = env
        .mock
        .client()
        .vault_refee(&hex.parse().unwrap())
        .await
        .unwrap()
        .hex
        .to_string();
    assert_ne!(refunded, hex);
    let again = as_leader
        .unlock_sign(
            &urls[peer],
            &UnlockSignRequest {
                hex: refunded.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        env.mock.state().calls_to("set_signunlock").len(),
        signs,
        "no new signature"
    );
    let ours = Transaction::decode_hex(&again.body.hex).unwrap();
    let base = Transaction::decode_hex(&refunded).unwrap();
    assert_eq!(ours.outputs, base.outputs);
    assert_eq!(
        ours.inputs.iter().map(|i| i.prevout).collect::<Vec<_>>(),
        base.inputs.iter().map(|i| i.prevout).collect::<Vec<_>>(),
        "the re-funded inputs"
    );
    assert_eq!(
        hawkeye::engine::burn::unlock_signatures(&again.body.hex).unwrap(),
        1
    );
    let had = Transaction::decode_hex(&first.body.hex).unwrap();
    let sig = |t: &Transaction| {
        let i = t.inputs.iter().position(|i| i.prevout == vault).unwrap();
        t.inputs[i].script_sig.clone()
    };
    assert_eq!(
        sig(&ours),
        sig(&had),
        "the signature it made the first time"
    );
    // another unlock of the vault (other outputs) is still refused
    let other = unlock_hex(&env, &vault, &r, 200_000_000, Some(&memo)).await;
    let e = as_leader
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: other })
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("403"), "{e}");
}

/// (k3b) A leader's own unlock that never left (vault_send failed) and whose fee input was then
/// spent is **re-funded** (`vault_refee`, audit 01/V-2) and re-sent on the same vault with the
/// same set signatures; it never dies and no other vault is signed for the burn (anyone holding
/// the signed bytes could re-fund the old one: a second vault would pay the burn twice).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k3b_unsendable_leader_unlock_is_refunded() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x47; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    for (i, e) in engines.iter_mut().enumerate() {
        if i != leader {
            e.tick().await;
        }
    }
    env.mock
        .state()
        .inject_error("vault_send", -26, "16: mock refusal");
    engines[leader].tick().await;
    assert!(unlocks_for(&env, nonce).is_empty(), "the send failed");
    let rows = engines[leader]
        .ctx()
        .db(|t| t.unlock_burn_rows(&env.set.0, &k))
        .unwrap();
    assert_eq!(rows.len(), 1);
    let first = rows[0].prevout;
    let rec = engines[leader]
        .ctx()
        .db(|t| {
            t.ycash_signature(&hawkeye_store::YcashSignKey {
                domain: hawkeye_store::SignDomain::YcashUnlock,
                set_id: env.set.0,
                prevout: first,
            })
        })
        .unwrap()
        .unwrap();
    let tx = Transaction::decode_hex(&rec.signed_hex).unwrap();
    let fee = tx
        .inputs
        .iter()
        .find(|i| CoreOutPoint::new(i.prevout.txid.0, i.prevout.vout) != first)
        .unwrap()
        .prevout;
    let spend = Transaction::new_v4(
        vec![TxIn {
            prevout: fee,
            script_sig: vec![0x51],
            sequence: u32::MAX,
        }],
        vec![TxOut {
            value: 1000,
            script_pubkey: YcashRecipient::p2pkh([0x14; 20]).script(),
        }],
        0,
        0,
    );
    env.mock.state().submit(spend.encode()).unwrap();
    env.mine(1);
    let signs = env.mock.state().calls_to("set_signunlock").len();
    let refees = env.mock.state().calls_to("vault_refee").len();
    engines[leader].tick().await; // re-sent: Missing inputs → vault_refee → sent
    assert_eq!(env.mock.state().calls_to("vault_refee").len(), refees + 1);
    let posted = unlocks_for(&env, nonce);
    assert_eq!(posted.len(), 1, "the re-funded unlock is in the mempool");
    assert_eq!(
        CoreOutPoint::new(posted[0].1.txid.0, posted[0].1.vout),
        first,
        "on the same vault"
    );
    assert_eq!(
        env.mock.state().calls_to("set_signunlock").len(),
        signs,
        "no new set signature"
    );
    // the broadcast spend carries the recorded template input (the same signatures)
    let raws: Vec<Vec<u8>> = {
        let st = env.mock.state();
        st.mempool
            .iter()
            .filter_map(|t| st.txs.get(t).map(|(r, _)| r.clone()))
            .collect()
    };
    let sent = raws
        .iter()
        .filter_map(|r| Transaction::decode(r).ok())
        .find(|t| {
            t.inputs
                .iter()
                .any(|i| CoreOutPoint::new(i.prevout.txid.0, i.prevout.vout) == first)
        })
        .expect("the re-funded unlock");
    let i = hawkeye::engine::sign::input_index(&sent, &first).unwrap();
    let j = hawkeye::engine::sign::input_index(&tx, &first).unwrap();
    assert_eq!(sent.inputs[i].script_sig, tx.inputs[j].script_sig);
    assert_eq!(sent.outputs, tx.outputs);
    assert!(sent.inputs.iter().all(|x| x.prevout != fee));
    env.mine(C_Y);
    engines[leader].tick().await;
    let rows = engines[leader]
        .ctx()
        .db(|t| t.unlock_burn_rows(&env.set.0, &k))
        .unwrap();
    assert_eq!(rows.len(), 1, "no other vault signed for the burn");
    assert!(rows[0].dead_reason.is_none(), "{:?}", rows[0]);
}

/// A peer that answers `/unlock/sign` with a forged transaction, signed by a member key.
async fn rogue_peer(env: &Env, member: SecretKey, forge: fn(&mut Transaction)) -> String {
    use axum::http::{HeaderMap, StatusCode};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let set = env.set.0;
    let dep = env.params().deployment;
    let app = axum::Router::new().route(
        "/unlock/sign",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let member = member.clone();
            async move {
                let h = |n: &str| headers.get(n).unwrap().to_str().unwrap().to_owned();
                let nonce = hawkeye_core::peerauth::parse_nonce(&h("x-hawkeye-nonce")).unwrap();
                let msg =
                    hawkeye_core::peerauth::request_msg(&hawkeye_core::peerauth::PeerRequest {
                        set_id: &set,
                        deployment: &dep,
                        method: "POST",
                        path: "/unlock/sign",
                        timestamp: h("x-hawkeye-time").parse().unwrap(),
                        nonce: &nonce,
                        body: &body,
                    })
                    .unwrap();
                let req: hawkeye::peers::UnlockSignRequest = serde_json::from_slice(&body).unwrap();
                let mut tx = Transaction::decode_hex(&req.hex).unwrap();
                forge(&mut tx);
                let out = serde_json::to_vec(&hawkeye::peers::UnlockSignResponse {
                    hex: tx.encode_hex(),
                    complete: true,
                    matched: "forged".into(),
                })
                .unwrap();
                let rs = hawkeye_core::peerauth::sign(
                    &member,
                    &hawkeye_core::peerauth::response_msg(&msg, &out),
                )
                .unwrap();
                (
                    StatusCode::OK,
                    [
                        ("x-hawkeye-member", hex::encode(member.public_key())),
                        ("x-hawkeye-sig", hex::encode(rs)),
                        ("content-type", "application/json".to_owned()),
                    ],
                    out,
                )
            }
        }),
    );
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

/// Two junk 65-byte pushes on the template input (the 05/L-1 attack).
fn junk_pushes(tx: &mut Transaction) {
    let idx = tx
        .inputs
        .iter()
        .position(|i| i.script_sig.last() == Some(&0x51))
        .unwrap();
    let mut ss = vec![];
    for b in [0x99u8, 0x98] {
        let mut j = vec![0x1f];
        j.extend([b; 64]);
        hawkeye_ycash::tx::push_data(&mut ss, &j);
    }
    ss.push(0x51);
    tx.inputs[idx].script_sig = ss;
}

/// A changed output (another transaction), signatures kept.
fn changed_output(tx: &mut Transaction) {
    tx.outputs[0].value -= 1;
}

/// (k4) Finding 05/L-1: a member's peer answering with junk pushes, or with another
/// transaction, is rejected; the honest peer's co-signature is adopted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k4_peer_returns_junk_pushes() {
    let Some(env) = setup_with(views(2, 1)).await else {
        return;
    };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x48; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let honest = (leader + 1) % 3;
    let bad = (leader + 2) % 3;
    drop(engines);
    // restart: the honest peer serves its API; two forged peers (both answering as the third
    // member) come first in the leader's list
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let honest_url = format!("http://{}", l.local_addr().unwrap());
    let mut h = env.engine_with_peers(honest, vec![]).await;
    let ctx = h.ctx().clone();
    tokio::spawn(async move { hawkeye::api::serve(l, ctx).await.unwrap() });
    let junk = rogue_peer(&env, env.keys[bad].clone(), junk_pushes).await;
    let changed = rogue_peer(&env, env.keys[bad].clone(), changed_output).await;
    let mut lead = env
        .engine_with_peers(leader, vec![junk, changed, honest_url])
        .await;
    h.tick().await;
    lead.tick().await;
    let posted = unlocks_for(&env, nonce);
    assert_eq!(posted.len(), 1, "the unlock went out");
    let idx = posted[0]
        .0
        .inputs
        .iter()
        .position(|i| i.prevout == posted[0].1)
        .unwrap();
    let s = hawkeye_core::template::parse_selector(
        hawkeye_core::template::TemplateKind::Vault,
        &posted[0].0.inputs[idx].script_sig,
    )
    .unwrap();
    let mut signers: Vec<[u8; 33]> = s
        .args
        .iter()
        .map(|a| a[1..34].try_into().unwrap())
        .collect();
    signers.sort_unstable();
    let mut want = vec![env.key_of_index(leader), env.key_of_index(honest)];
    want.sort_unstable();
    assert_eq!(signers, want, "the leader's and the honest peer's, no junk");
}

/// (k5) cancelThreshold 2: the intent's cancel leader gathers a peer's cancel signature over
/// `POST /cancel/sign` and the cancel confirms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k5_cancel_cosign_endpoint() {
    let Some(env) = setup_with(views(1, 2)).await else {
        return;
    };
    let (mut engines, _urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let (intent, _signer) = rogue_unlock(&env).await;
    for _ in 0..3 {
        tick_all(&mut engines).await;
    }
    let cancels = env.mock.state().calls_to("set_signcancel").len();
    assert!(cancels >= 2, "the leader's and a peer's signature");
    env.mine(1);
    tick_all(&mut engines).await;
    let cancelled: usize = engines
        .iter()
        .map(|e| {
            e.ctx()
                .db(|t| t.intents_in_state(IntentState::Cancelled))
                .unwrap()
                .len()
        })
        .sum();
    assert!(cancelled >= 1, "the cancel of {intent} confirmed");
    let st = env.mock.state();
    assert!(
        !st.templates
            .contains_key(&OutPoint::new(Hash256(intent.txid), intent.vout)),
        "the intent is spent"
    );
}

/// (k6) Finding 05/N-2: fewer than 8 confirmed fee coins raise `fee-coins-low`; a split into
/// 16 coins clears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k6_fee_coins_alarm() {
    let Some(env) = setup().await else { return };
    {
        let mut st = env.mock.state();
        st.unspent.truncate(3);
    }
    let mut e = env.engine(0).await;
    e.tick().await;
    assert!(
        e.alarms().iter().any(|a| a.name == "fee-coins-low"),
        "{:?}",
        e.alarms()
    );
    let c = env.mock.client();
    let mut to = vec![];
    for _ in 0..16 {
        to.push((c.getnewaddress().await.unwrap(), Amount(1_000_000)));
    }
    c.sendmany(&to).await.unwrap();
    env.mine(1);
    for _ in 0..20 {
        e.tick().await;
    }
    assert!(
        !e.alarms().iter().any(|a| a.name == "fee-coins-low"),
        "{:?}",
        e.alarms()
    );
    let st = e.ctx().status.read().unwrap().clone();
    assert!(st.fee_coins.unwrap() >= 16);
}

/// (k7) 07/F-5, `"wallet"` mode: a node wallet carrying the restore marker refuses every set
/// signature (`set-sign-restored`); the daemon pages `node-sign-restored` and signs nothing, and
/// once the operator acknowledges (`set_acknowledgerestore`, what `hawkeye acknowledge-restore`
/// ends with) the burn is unlocked and the alarm clears.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k7_restore_marker_pages_until_acknowledged() {
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    env.mock.state().restored = true;
    let nonce = burn_and_release(&env, &mut engines, &[0, 1, 2]).await;
    tick_all(&mut engines).await;
    assert!(unlocks_for(&env, nonce).is_empty(), "nothing signed");
    assert!(
        engines
            .iter()
            .any(|e| e.alarms().iter().any(|a| a.name == "node-sign-restored")),
        "{:?}",
        engines.iter().map(|e| e.alarms()).collect::<Vec<_>>()
    );
    let ack = env.mock.client().set_acknowledgerestore().await.unwrap();
    assert!(!ack.restored);
    tick_all(&mut engines).await;
    tick_all(&mut engines).await;
    assert_eq!(
        unlocks_for(&env, nonce).len(),
        1,
        "unlocked once acknowledged"
    );
    for e in &engines {
        assert!(
            !e.alarms().iter().any(|a| a.name == "node-sign-restored"),
            "{:?}",
            e.alarms()
        );
    }
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

/// (o) 05/M-1: with a separate gas account per attestor, the proposal and the execution are
/// sent from the gas accounts (the guardians send nothing) while the EIP-712 attestation is the
/// guardian's (the contract accepted it); the status reports the sender and its balance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn o_gas_account_sends_the_guardian_attests() {
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let senders: Vec<SecretKey> = (20..23).map(secret).collect();
    for k in &senders {
        set_balance(&env.provider, hawkeye::convert::addr(&k.eth_address())).await;
    }
    let mut engines = vec![];
    for (i, k) in senders.iter().enumerate() {
        engines.push(env.engine_full(i, vec![], Some(k.clone()), |_| {}).await);
    }
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let lock_id = drive_mint(&env, &mut engines, &op).await;
    let c = env.eth(&env.holder).await;
    let p = c
        .proposal(B256::from(lock_id))
        .await
        .unwrap()
        .expect("proposed");
    assert!(
        (0..3).any(|i| hawkeye::convert::addr(&env.keys[i].eth_address()) == p.proposer),
        "the proposer is a guardian (its EIP-712 signature)"
    );
    env.warp(WINDOW).await;
    eth_rounds(&env, &mut engines, 3).await;
    assert_eq!(
        c.balance_of(hawkeye::convert::addr(&to)).await.unwrap(),
        U256::from(1_000_000_000u64)
    );
    let nonce = |k: &SecretKey| {
        let a = hawkeye::convert::addr(&k.eth_address());
        let p = env.provider.clone();
        async move { p.get_transaction_count(a).await.unwrap() }
    };
    let mut sent = 0;
    for k in &senders {
        sent += nonce(k).await;
    }
    assert!(
        sent >= 2,
        "the gas accounts sent the proposal and the execution"
    );
    for k in &env.keys {
        assert_eq!(nonce(k).await, 0, "a guardian sends nothing");
    }
    let st = engines[0].ctx().status.read().unwrap().clone();
    assert_eq!(
        st.sender.as_deref(),
        Some(senders[0].eth_address().to_checksum().as_str())
    );
    assert!(st.sender_balance.as_ref().unwrap().parse::<u128>().unwrap() > 0);
    serde_json::to_value(&st).expect("a wei balance above u64 serialises");
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
        fn consumed_final(&self, l: Hash32) -> BoxFut<'_, bool> {
            self.inner.consumed_final(l)
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

// ------------------------------------------------------------------------------------------
// audit 05/L-5: exposure (a signed lock that left the active chain) and the blind start

impl Env {
    /// A Ycash reorg that drops every block from `height` up and mines a longer branch of empty
    /// blocks (the mock's UTXO effects are not undone: the follower only sees the blocks).
    fn reorg_from(&self, height: u32) {
        let mut st = self.mock.state();
        let old = st.blocks.len();
        st.blocks.truncate(height as usize);
        st.mempool.clear();
        let n = u32::try_from(old - height as usize).unwrap() + 1;
        st.mine(n);
    }
}

fn lock_state(e: &Engine, id: &[u8; 32]) -> LockState {
    e.ctx().db(|t| t.lock(id)).unwrap().unwrap().state
}

/// A threshold mint lands for a lock whose Ycash block is then reorged away before the `Minted`
/// is final: the lock ends MINTED_UNBACKED, `exposure` is raised (status and metrics), and on
/// mainnet semantics this attestor signs nothing new until `exposure ack`; challenges go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u_minted_on_reorged_lock_pauses_own_mints() {
    let Some(env) = setup_with(Opts {
        mint_cap: 100_000_000_000,
        ..Opts::default()
    })
    .await
    else {
        return;
    };
    let mut e = vec![
        env.engine_with(0, vec![], |p| {
            p.mainnet = true;
            p.drills = false;
        })
        .await,
    ];
    tick_all(&mut e).await;
    let to = env.holder.eth_address();
    let op = env.lock(1_000_000_000, &to);
    let l1 = hawkeye_core::lock::lock_id(&op);
    env.mine(C_Y);
    let c = env.eth(&env.holder).await;
    let mut rounds = 0;
    // policy-OK, signed, threshold mint submitted; no Ethereum block mined, so not final yet
    while c.total_supply().await.unwrap() == U256::ZERO {
        rounds += 1;
        assert!(
            rounds <= 20,
            "no mint after {rounds} ticks: {:?}",
            lock_state(&e[0], &l1)
        );
        env.mine(1); // the leader may be another member: takeover after TAKEOVER blocks
        tick_all(&mut e).await;
    }
    let height = e[0]
        .ctx()
        .db(|t| t.lock(&l1))
        .unwrap()
        .unwrap()
        .block_height;
    assert_ne!(
        lock_state(&e[0], &l1),
        LockState::Minted,
        "the Minted is not final yet"
    );
    env.reorg_from(height);
    tick_all(&mut e).await;
    env.eth_mine(3).await;
    tick_all(&mut e).await;
    assert_eq!(lock_state(&e[0], &l1), LockState::MintedUnbacked);
    let a = e[0].alarms();
    assert!(a.iter().any(|a| a.name == "exposure"), "{a:?}");
    let st = e[0].ctx().status.read().unwrap().clone();
    assert_eq!(st.exposure, vec![format!("0x{}", hex::encode(l1))]);
    assert!(hawkeye::status::render_metrics(&st).contains("hawkeye_exposure_unacked 1"));
    assert_eq!(
        fraud_cases(&e[0], env.key_of_index(0)),
        0,
        "no slash for a reorg"
    );
    // a new policy-OK lock is not signed while the exposure is unacknowledged
    let op2 = env.lock(500_000_000, &to);
    let l2 = hawkeye_core::lock::lock_id(&op2);
    env.mine(C_Y);
    for _ in 0..3 {
        tick_all(&mut e).await;
        env.eth_mine(3).await;
    }
    assert_eq!(lock_state(&e[0], &l2), LockState::PolicyOk, "paused");
    // the operator acknowledges: the pause ends and the lock mints
    e[0].ctx()
        .db(|t| t.ack_exposure(&l1, "set paused the bridge; supply reconciled"))
        .unwrap();
    let mut rounds = 0;
    while lock_state(&e[0], &l2) != LockState::Minted {
        rounds += 1;
        assert!(
            rounds <= 20,
            "not minted after the ack: {:?}",
            lock_state(&e[0], &l2)
        );
        env.mine(1); // the leader may be another member: takeover after TAKEOVER blocks
        tick_all(&mut e).await;
        env.eth_mine(3).await;
    }
    assert!(!e[0].alarms().iter().any(|a| a.name == "exposure"));
}

/// A proposed, not yet executed lock whose Ycash block reorgs away: its own proposer withdraws
/// the proposal by challenge (no fraud case), and the lock is an exposure until acknowledged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u2_signed_then_reorged_proposal_is_challenged() {
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
    let proposer = (0..3)
        .find(|&i| hawkeye::convert::addr(&env.keys[i].eth_address()) == p.proposer)
        .unwrap();
    let height = engines[proposer]
        .ctx()
        .db(|t| t.lock(&lock_id))
        .unwrap()
        .unwrap()
        .block_height;
    env.reorg_from(height);
    // only the proposer ticks: it withdraws its own proposal
    let mut own = vec![engines.remove(proposer)];
    tick_all(&mut own).await;
    assert!(
        c.proposal(B256::from(lock_id)).await.unwrap().is_none(),
        "withdrawn"
    );
    assert_eq!(challenges(&own[0]).len(), 1);
    assert_eq!(lock_state(&own[0], &lock_id), LockState::Reorged);
    for _ in 0..3 {
        env.eth_mine(3).await;
        tick_all(&mut own).await;
    }
    assert!(own[0].alarms().iter().any(|a| a.name == "exposure"));
    assert!(open_cases(&own[0]).is_empty(), "{:?}", open_cases(&own[0]));
    assert_eq!(c.total_supply().await.unwrap(), U256::ZERO);
}

/// `ycash.start_height` above the set's oldest bridge vault: the follower refuses to start
/// (it would challenge honest proposals for locks it never saw) unless the operator accepts a
/// blind start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u3_blind_start_refused() {
    let Some(env) = setup().await else {
        return;
    };
    env.lock(1_000_000_000, &env.holder.eth_address());
    env.mine(10);
    let late = env.mock.state().tip_height();
    let mut e = env
        .engine_with(0, vec![], |p| p.ycash_start_height = Some(late))
        .await;
    let r = e.tick().await;
    assert!(
        r.errors
            .iter()
            .any(|x| x.contains("is above the set's oldest WYEC vault")),
        "{:?}",
        r.errors
    );
    drop(e);
    let mut e = env
        .engine_with(1, vec![], |p| {
            p.ycash_start_height = Some(late);
            p.accept_blind_start = true;
        })
        .await;
    let r = e.tick().await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
}

// ------------------------------------------------------------------------------------------
// audit 05/L-3: migration to a successor bridge

impl Env {
    /// A client of deployment `dep` sending from `key`.
    async fn eth_at(&self, key: &SecretKey, dep: &Deployment) -> EthClient {
        let mut c = EthConfig::new(self.url.clone(), 31337, dep.bridge);
        c.token = Some(dep.token);
        EthClient::connect(&c, Some(eth_signer(key).unwrap()))
            .await
            .unwrap()
    }

    /// Attestor `i`'s engine on deployment `dep` over the ledger file `db`.
    async fn engine_at(&self, i: usize, db: &str, dep: &Deployment) -> Engine {
        let foreign = Arc::new(hawkeye::foreign::EthereumChain::new(
            self.eth_at(&self.keys[i], dep).await,
        ));
        let (bridge, start) = (dep.bridge, dep.deploy_block);
        self.engine_db(i, db, vec![], foreign, |p| {
            p.deployment = CoreDeployment {
                chain_id: 31337,
                bridge: EthAddress(bridge.0.0),
            };
            p.eth_start_block = start;
        })
    }
}

/// Three attestors on bridge A: lock L1 minted, lock L2 proposed but not executed. A successor
/// B (predecessor A) is deployed over the same token, A hands off to B, the attestors switch to
/// B with their ledgers: L2 is signed anew for B's domain (no SignOnceConflict), proposed and
/// minted on B; L1 is never proposed (consumed through the predecessor). A restored attestor
/// with a fresh ledger records L1 as minted without signing it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s_migration_reproposes_pending_and_never_remints() {
    let Some(env) = setup_with(opt()).await else {
        return;
    };
    let mut engines = three(&env).await;
    let to = env.holder.eth_address();
    let l1 = drive_mint(&env, &mut engines, &env.lock(1_000_000_000, &to)).await;
    env.warp(WINDOW).await;
    eth_rounds(&env, &mut engines, 3).await;
    let c = env.eth(&env.holder).await;
    assert!(c.consumed(B256::from(l1)).await.unwrap(), "L1 minted on A");
    let l2 = drive_mint(&env, &mut engines, &env.lock(300_000_000, &to)).await;
    assert!(
        c.proposal(B256::from(l2)).await.unwrap().is_some(),
        "L2 proposed on A"
    );
    drop(engines);

    // the successor and the hand-off (the guardians' threshold act on A)
    let guardians: Vec<Address> = env
        .keys
        .iter()
        .map(|k| hawkeye::convert::addr(&k.eth_address()))
        .collect();
    let b = hawkeye_eth::deploy_successor(
        &env.provider,
        &env.dep,
        &DeployParams::new(&guardians, 2, WINDOW, MintMode::Optimistic),
    )
    .await
    .unwrap();
    assert_eq!(
        (b.token, b.predecessor),
        (env.dep.token, Some(env.dep.bridge))
    );
    let a = env.eth(&env.keys[0]).await;
    let nonce = a.admin_nonce().await.unwrap();
    let d = hawkeye_eth::eip712::set_bridge_digest(31337, env.dep.bridge, b.bridge, nonce);
    let sigs: Vec<Bytes> = env.keys[..2]
        .iter()
        .map(|k| Bytes::from(hawkeye_core::eth::sign_digest(k, &d.0).unwrap().to_vec()))
        .collect();
    a.set_bridge(b.bridge, &sigs).await.unwrap();
    let cb = env.eth_at(&env.holder, &b).await;
    assert!(
        cb.consumed(B256::from(l1)).await.unwrap(),
        "isConsumed through the predecessor"
    );

    let mut engines = vec![
        env.engine_at(0, "attestor0.db", &b).await,
        env.engine_at(1, "attestor1.db", &b).await,
        env.engine_at(2, "attestor2.db", &b).await,
    ];
    let mut rounds = 0;
    while cb.proposal(B256::from(l2)).await.unwrap().is_none() {
        rounds += 1;
        assert!(rounds <= 12, "L2 not proposed on B after {rounds} rounds");
        env.mine(1);
        tick_all(&mut engines).await;
        env.eth_mine(3).await;
    }
    let dep_b = engines[0].ctx().params.deployment;
    for e in &engines {
        let recs = e.ctx().db(|t| t.mint_signatures_any(&l2)).unwrap();
        assert!(recs.iter().any(|r| r.deployment == dep_b), "signed for B");
        assert_eq!(recs.len(), 2, "one record per deployment");
    }
    env.warp(WINDOW).await;
    for _ in 0..4 {
        env.mine(1);
        tick_all(&mut engines).await;
        env.eth_mine(3).await;
    }
    assert_eq!(
        c.balance_of(hawkeye::convert::addr(&to)).await.unwrap(),
        U256::from(1_300_000_000u64),
        "L1 once on A, L2 once on B"
    );
    assert!(cb.proposal(B256::from(l1)).await.unwrap().is_none());
    assert_eq!(
        cb.proposal_count().await.unwrap(),
        1,
        "only L2 proposed on B"
    );
    for e in &engines {
        assert_eq!(lock_state(e, &l2), LockState::Minted);
        assert_eq!(lock_state(e, &l1), LockState::Minted);
    }
    drop(engines);

    // a restored attestor (fresh ledger) on B: L1 is consumed, recorded MINTED, never signed
    let mut fresh = vec![env.engine_at(0, "restored0.db", &b).await];
    for _ in 0..4 {
        env.mine(1);
        tick_all(&mut fresh).await;
        env.eth_mine(3).await;
    }
    assert_eq!(lock_state(&fresh[0], &l1), LockState::Minted);
    assert!(
        fresh[0]
            .ctx()
            .db(|t| t.mint_signatures_any(&l1))
            .unwrap()
            .is_empty(),
        "a consumed lock is never signed"
    );
    assert_eq!(cb.proposal_count().await.unwrap(), 1);
}

/// (q) `hawkeye audit-ledger` (remedial report 05/M-3, docs/operations.md §5): the leader's ledger
/// agrees with the node while its unlock is in the mempool and once it is mined; a copy of the
/// ledger with that unlock's sign-once record deleted (a restored backup older than the
/// signature) reports the vault as signed by this member with no record here (and not for a
/// member that did not sign it), and opening it read-only neither migrates nor writes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn q_audit_ledger_detects_missing_record() {
    let Some(env) = setup().await else { return };
    let mut engines = vec![
        env.engine(0).await,
        env.engine(1).await,
        env.engine(2).await,
    ];
    lock_and_mint(&env, &mut engines).await;
    burn_and_release(&env, &mut engines, &[0, 1, 2]).await;
    tick_all(&mut engines).await;
    let attributor = MockAttributor { set: env.set.0 };
    let node = env.mock.client();
    // the burn's leader: the one ledger with an unlock record
    let (i, vault) = (0..3)
        .find_map(|i| {
            let p = engines[i].ctx().params.clone();
            let recs = engines[i]
                .ctx()
                .db(|t| t.ycash_signatures(&p.set_id))
                .unwrap();
            recs.iter()
                .find(|r| r.key.domain == hawkeye_store::SignDomain::YcashUnlock)
                .map(|r| (i, r.key.prevout))
        })
        .expect("an unlock record");
    let params = engines[i].ctx().params.clone();
    // the member whose set signature is on the unlock (the mock's wallet signs with one of its
    // member keys): the audit asks about *its* signatures
    let me: [u8; 33] = {
        let st = env.mock.state();
        let tx = st
            .mempool
            .iter()
            .map(|t| Transaction::decode(&st.txs[t].0).unwrap())
            .find(|t| t.inputs.iter().any(|i| i.prevout.txid.0 == vault.txid))
            .expect("the unlock in the mempool");
        let input = tx
            .inputs
            .iter()
            .find(|i| i.prevout.txid.0 == vault.txid)
            .unwrap();
        let sel = hawkeye_core::template::parse_selector(
            hawkeye_core::template::TemplateKind::Vault,
            &input.script_sig,
        )
        .unwrap();
        sel.args[0][1..34].try_into().unwrap()
    };
    for mined in [false, true] {
        if mined {
            env.mine(1);
            tick_all(&mut engines).await;
        }
        let view = {
            let mut st = engines[i].ctx().store.lock().unwrap();
            hawkeye::audit::ledger_view(&mut st, &params).unwrap()
        };
        let r = hawkeye::audit::audit_view(view, &node, &attributor, &params, &me)
            .await
            .unwrap();
        assert!(r.ok, "mined {mined}: {r:?}");
        assert!(
            r.records
                .iter()
                .any(|x| x.domain == "ycash-unlock" && x.prevout == vault.to_string()),
            "{r:?}"
        );
    }
    // an older copy: the record deleted behind the immutability trigger's back
    let src = env.dir.path().join(format!("attestor{i}.db"));
    let copy = env.dir.path().join("restored.db");
    {
        let c = rusqlite::Connection::open(&src).unwrap();
        c.execute("VACUUM INTO ?1", [copy.to_str().unwrap()])
            .unwrap();
    }
    {
        let c = rusqlite::Connection::open(&copy).unwrap();
        c.execute_batch("DROP TRIGGER sign_once_ycash_immutable_delete;")
            .unwrap();
        let n = c
            .execute(
                "DELETE FROM sign_once_ycash WHERE domain = 'ycash-unlock'",
                [],
            )
            .unwrap();
        assert!(n >= 1);
    }
    let before = std::fs::read(&copy).unwrap();
    let mut restored = Store::open_readonly(&copy).unwrap();
    let r = hawkeye::audit::audit_ledger(&mut restored, &node, &attributor, &params, &me)
        .await
        .unwrap();
    assert!(!r.ok, "{r:?}");
    assert!(
        r.missing.iter().any(|m| m.vault == vault.to_string()),
        "{r:?}"
    );
    assert!(
        r.verdict()
            .contains("ledger is behind the chain: records for vault"),
        "{}",
        r.verdict()
    );
    assert_eq!(hawkeye::audit::refuse(&r).to_string(), r.verdict());
    drop(restored);
    assert_eq!(
        std::fs::read(&copy).unwrap(),
        before,
        "read-only: not written"
    );
    // a member that did not sign it owes no record of it
    let other = (0..3)
        .map(|k| env.key_of_index(k))
        .find(|k| *k != me)
        .unwrap();
    let mut restored = Store::open_readonly(&copy).unwrap();
    let r = hawkeye::audit::audit_ledger(&mut restored, &node, &attributor, &params, &other)
        .await
        .unwrap();
    assert!(r.ok, "{r:?}");
    drop(restored);
    // a ledger of another schema version is refused read-only (never migrated)
    {
        let c = rusqlite::Connection::open(&copy).unwrap();
        c.execute_batch("PRAGMA user_version = 1;").unwrap();
    }
    assert!(Store::open_readonly(&copy).is_err());
}

// ------------------------------------------------------------------------------------------
// (r) the review of fix/unlock-revival (01/V-2): H-1 bounded value, H-2 authenticated bytes and
// orphans, M-1 signed "none", M-2 dead inference from the ledger, M-3 evicted unlocks

/// An unlock of `vault` to `r` with burn `memo`, **as the node builds it** (with its change
/// output), signed through `node`: what a malicious or careless builder would hand out.
async fn fat_unlock(
    env: &Env,
    node: &hawkeye_ycash::YcashRpc,
    vault: &OutPoint,
    r: &YcashRecipient,
    memo: &hawkeye_core::memo::HawkeyeMemo,
) -> (String, String) {
    let built = env
        .mock
        .client()
        .vault_buildunlock(
            vault,
            &[hawkeye_ycash::types::Recipient::script(
                r.script(),
                Amount(300_000_000),
            )],
        )
        .await
        .unwrap()
        .hex
        .to_string();
    let with = hawkeye_ycash::tx::insert_op_return(&built, &memo.encode()).unwrap();
    let signed = node
        .set_signunlock(&with.parse().unwrap())
        .await
        .unwrap()
        .hex
        .to_string();
    (with, signed)
}

/// (r1) H-1: a co-signer refuses an unlock that moves more than the vault's value (here the
/// node's change output, which any re-funder would pay).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_cosigner_refuses_an_unlock_with_change() {
    use hawkeye::peers::UnlockSignRequest;
    let Some(env) = setup_with(views(2, 1)).await else {
        return;
    };
    let (mut engines, urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x61; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let peer = (leader + 1) % 3;
    engines[peer].tick().await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[peer].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    let memo = hawkeye_core::memo::HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let vault = free_vaults(&env).await[0];
    let built = env
        .mock
        .client()
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
        .to_string();
    let with = hawkeye_ycash::tx::insert_op_return(&built, &memo.encode()).unwrap();
    let signs = env.mock.state().calls_to("set_signunlock").len();
    let e = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[leader]))
        .unlock_sign(&urls[peer], &UnlockSignRequest { hex: with })
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("403") && e.contains("no change"), "{e}");
    assert_eq!(env.mock.state().calls_to("set_signunlock").len(), signs);
}

/// (r2) H-1 at takeover: the silent previous leader serves a signed unlock carrying a change
/// output (the theft: the adopter's `vault_refee` would pay it). The takeover leader rejects it,
/// funds nothing, signs nothing fresh (that member did not say "none"), and alarms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_takeover_never_funds_a_fat_unlock() {
    use hawkeye_store::{UnlockBurn, UnlockOrigin, YcashSignKey};
    let Some(env) = setup().await else { return };
    let (mut engines, _urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x62; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    for (i, e) in engines.iter_mut().enumerate() {
        if i != leader {
            e.tick().await;
        }
    }
    let other = (leader + 1) % 3;
    let b = engines[other].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    let memo = hawkeye_core::memo::HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let vault = free_vaults(&env).await[0];
    let (built, signed) = fat_unlock(&env, &env.mock.client(), &vault, &r, &memo).await;
    let key = YcashSignKey {
        domain: hawkeye_store::SignDomain::YcashUnlock,
        set_id: env.set.0,
        prevout: CoreOutPoint::new(vault.txid.0, vault.vout),
    };
    engines[leader]
        .ctx()
        .db(|t| {
            t.sign_once_unlock(
                &key,
                Some(&UnlockBurn {
                    key: k,
                    origin: UnlockOrigin::Leader,
                    allow_double: false,
                }),
                &built,
                |_| Ok::<_, String>((signed.clone(), [0x33; 32])),
            )
        })
        .unwrap();
    // the leader ticks once (its burn is ASSIGNED, so it serves the bytes), its send fails, it
    // falls silent
    env.mock
        .state()
        .inject_error("vault_send", -26, "16: mock refusal");
    engines[leader].tick().await;
    let refees = env.mock.state().calls_to("vault_refee").len();
    let builds = env.mock.state().calls_to("vault_buildunlock").len();
    for _ in 0..TAKEOVER + 2 {
        env.mine(1);
        for (i, e) in engines.iter_mut().enumerate() {
            if i != leader {
                e.tick().await;
            }
        }
    }
    assert!(
        unlocks_for(&env, nonce).is_empty(),
        "nothing was sent for the burn"
    );
    assert_eq!(
        env.mock.state().calls_to("vault_refee").len(),
        refees,
        "nobody funded the fat unlock"
    );
    assert_eq!(
        env.mock.state().calls_to("vault_buildunlock").len(),
        builds,
        "no fresh vault"
    );
    assert!(
        engines.iter().enumerate().any(
            |(i, e)| i != leader && e.alarms().iter().any(|a| a.name == "unlock-prior-unknown")
        ),
        "the takeover leader holds and alarms"
    );
}

/// W4-B-1: a non-leader member signs and sends a fat unlock (a change output) for the burn; it
/// is observed and then evicted. Its signer holds that sign-once record and answers "held" with
/// the fat bytes, which nobody may adopt. That signer is not a required answerer: the leader
/// signs a fresh vault and releases instead of holding the burn forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w4b1_fat_unlock_by_a_non_leader_does_not_hold_the_burn() {
    use hawkeye_store::{UnlockBurn, UnlockOrigin, YcashSignKey};
    let Some(env) = setup_with(views(1, 1)).await else {
        return;
    };
    let (mut engines, _urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x65; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let rogue = (leader + 1) % 3;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    engines[rogue].tick().await;
    let b = engines[rogue].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    let memo = hawkeye_core::memo::HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let vault = free_vaults(&env).await[0];
    let (built, signed) = fat_unlock(&env, &env.node(rogue), &vault, &r, &memo).await;
    let key = YcashSignKey {
        domain: hawkeye_store::SignDomain::YcashUnlock,
        set_id: env.set.0,
        prevout: CoreOutPoint::new(vault.txid.0, vault.vout),
    };
    engines[rogue]
        .ctx()
        .db(|t| {
            t.sign_once_unlock(
                &key,
                Some(&UnlockBurn {
                    key: k,
                    origin: UnlockOrigin::Leader,
                    allow_double: false,
                }),
                &built,
                |_| Ok::<_, String>((signed.clone(), [0x34; 32])),
            )
        })
        .unwrap();
    env.node(rogue)
        .vault_send(&signed.parse().unwrap())
        .await
        .unwrap();
    // every ledger observes it (attributed to the rogue), then it is evicted
    for e in engines.iter_mut() {
        e.tick().await;
    }
    let prefix = format!("observed_unlock/{k}/");
    assert!(
        !engines[leader]
            .ctx()
            .db(|t| t.meta_prefix(&prefix))
            .unwrap()
            .is_empty(),
        "the leader observed the fat unlock"
    );
    drop_unlocks(&env, nonce);
    let mut fresh = None;
    for _ in 0..4 * TAKEOVER + 8 {
        env.mine(1);
        engines[leader].tick().await;
        if let Some((tx, v)) = unlocks_for(&env, nonce).into_iter().next() {
            fresh = Some((tx, v));
            break;
        }
    }
    let (tx, v) = fresh.expect("the leader released without the rogue's \"none\"");
    let value = u64::try_from(env.mock.state().templates[&v].valuezat()).unwrap();
    hawkeye::engine::sign::unlock_value_bounded(&tx, value).unwrap();
    assert!(
        !engines[leader]
            .alarms()
            .iter()
            .any(|a| a.name == "unlock-prior-unknown"),
        "the leader did not hold the burn"
    );
}

/// (r3) H-1: `send_refunded` never sends a re-fund that would cost this wallet more than the fee
/// bound (a change output to pay).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_refund_is_bounded() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let vault = free_vaults(&env).await[0];
    let r = YcashRecipient::p2pkh([0x63; 20]);
    let memo = hawkeye_core::memo::HawkeyeMemo::burn_release(dep_of(&engines[0]), 77, [0x77; 32]);
    let (_, signed) = fat_unlock(&env, &env.mock.client(), &vault, &r, &memo).await;
    let sends = env.mock.state().calls_to("vault_send").len();
    let e = hawkeye::engine::sign::send_refunded(
        &env.mock.client(),
        &signed.parse().unwrap(),
        &CoreOutPoint::new(vault.txid.0, vault.vout),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(e.contains("review H-1"), "{e}");
    assert_eq!(
        env.mock.state().calls_to("vault_send").len(),
        sends,
        "not sent"
    );
    // the same unlock funded exactly costs the fee only
    let exact = unlock_hex(&env, &vault, &r, 300_000_000, Some(&memo)).await;
    let tx = Transaction::decode_hex(&exact).unwrap();
    let value = u64::try_from(env.mock.state().templates[&vault].valuezat()).unwrap();
    hawkeye::engine::sign::unlock_value_bounded(&tx, value).unwrap();
    assert_eq!(
        hawkeye::engine::sign::refund_cost(&tx, value, 10_000).unwrap(),
        10_000
    );
}

/// (r4) H-2: the public `GET /burns/<nonce>` never carries signed bytes; `POST /burns/unlock` is
/// for members only and serves nothing once the burn is paid.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_signed_unlock_bytes_are_members_only_and_unpaid_only() {
    let Some(env) = setup().await else { return };
    let (mut engines, urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x64; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    for _ in 0..u32::from(DELAY) + 4 {
        tick_all(&mut engines).await;
        env.mine(1);
    }
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let b = engines[leader].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    assert_eq!(b.state, BurnState::Released);
    let body: serde_json::Value = reqwest::get(format!("{}/burns/{nonce}", urls[leader]))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body.get("unlock").is_none(), "{body}");
    let e = Peers::new(vec![])
        .unwrap()
        .burn_unlock(&urls[leader], nonce)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("401"), "{e}");
    let other = (leader + 1) % 3;
    let a = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[other]))
        .burn_unlock(&urls[leader], nonce)
        .await
        .unwrap();
    assert_eq!(a.responder, Some(env.key_of_index(leader)));
    assert!(a.body.held, "the leader signed it");
    assert_eq!(a.body.unlock, None, "paid: never served");
    assert_eq!(a.body.state, "RELEASED");
}

/// (r5) H-2: a member holds a signed unlock of V1 for a burn that was paid from V2. It marks V1
/// due and reports it; the roll leader (a member that never signed V1) rolls V1, which spends
/// it: the orphaned bytes can never pay the burn again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_orphaned_unlock_vault_is_rolled() {
    use hawkeye_store::{UnlockBurn, UnlockOrigin, YcashSignKey};
    let Some(env) = setup_with(views(1, 1)).await else {
        return;
    };
    let (mut engines, _urls) = networked(&env).await;
    let to = env.holder.eth_address();
    let (v1, _) = env.lock_aged(1_000_000_000, &to, 2000);
    drive_mint(&env, &mut engines, &v1).await;
    let (v2, _) = env.lock_aged(1_000_000_000, &to, 1000);
    drive_mint(&env, &mut engines, &v2).await;
    let r = YcashRecipient::p2pkh([0x65; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let holder = (leader + 1) % 3;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    engines[holder].tick().await;
    let b = engines[holder].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    let memo = hawkeye_core::memo::HawkeyeMemo::burn_release(dep_of(&engines[0]), nonce, b.tx_hash);
    let v1r = OutPoint::new(Hash256(v1.txid), v1.vout);
    // the holder signed an unlock of V1 for the burn on its own node; it never left
    let hex = unlock_hex(&env, &v1r, &r, 300_000_000, Some(&memo)).await;
    let signed = env
        .node(holder)
        .set_signunlock(&hex.parse().unwrap())
        .await
        .unwrap();
    engines[holder]
        .ctx()
        .db(|t| {
            t.sign_once_unlock(
                &YcashSignKey {
                    domain: hawkeye_store::SignDomain::YcashUnlock,
                    set_id: env.set.0,
                    prevout: v1,
                },
                Some(&UnlockBurn {
                    key: k,
                    origin: UnlockOrigin::Cosign,
                    allow_double: false,
                }),
                &hex,
                |_| Ok::<_, String>((signed.hex.to_string(), signed.sighash.0)),
            )
        })
        .unwrap();
    // the leader pays the burn from V2 (the nearest ownerHeight); it is released
    let mut rolled = false;
    for _ in 0..u32::from(DELAY) + 4 * TAKEOVER + 12 {
        tick_all(&mut engines).await;
        env.mine(1);
        if env
            .mock
            .client()
            .gettxout(&v1r.txid, v1r.vout, true)
            .await
            .unwrap()
            .is_none()
        {
            rolled = true;
            break;
        }
    }
    tick_all(&mut engines).await;
    let b = engines[leader].ctx().db(|t| t.burn(&k)).unwrap().unwrap();
    assert!(
        matches!(b.state, BurnState::Released | BurnState::IntentConfirmed),
        "{:?}",
        b.state
    );
    let paid = engines[leader]
        .ctx()
        .db(|t| t.intent(&b.intent.unwrap()))
        .unwrap()
        .unwrap();
    assert_eq!(paid.origin_vault, Some(v2), "paid from V2");
    assert!(rolled, "V1 was spent");
    let rolls: Vec<_> = engines[leader]
        .ctx()
        .db(|t| {
            let mut v = t.intents_in_state(IntentState::Matched)?;
            v.extend(t.intents_in_state(IntentState::Released)?);
            Ok(v)
        })
        .unwrap()
        .into_iter()
        .filter(|i| i.origin_vault == Some(v1))
        .collect();
    assert_eq!(rolls.len(), 1, "one spend of V1");
    assert_eq!(
        rolls[0].classification.as_deref(),
        Some("matched-roll"),
        "a roll, never a second payment of the burn"
    );
}

/// (r6) M-1: the previous leader is unreachable: its takeover successor signs no fresh vault
/// (it may hold a signed unlock), alarms, and goes on once the previous leader answers "none".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r6_unreachable_previous_leader_holds_the_burn() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x66; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    drop(engines);
    // three APIs; the leader's port is closed (its process is down)
    let mut listeners = vec![];
    let mut urls = vec![];
    for _ in 0..3 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}", l.local_addr().unwrap()));
        listeners.push(Some(l));
    }
    let leader_addr = listeners[leader].as_ref().unwrap().local_addr().unwrap();
    listeners[leader] = None;
    let mut engines = vec![];
    for i in 0..3 {
        let peers = (0..3)
            .filter(|j| *j != i)
            .map(|j| urls[j].clone())
            .collect();
        engines.push(env.engine_with_peers(i, peers).await);
    }
    for (i, l) in listeners.into_iter().enumerate() {
        if let Some(l) = l {
            let ctx = engines[i].ctx().clone();
            tokio::spawn(async move { hawkeye::api::serve(l, ctx).await.unwrap() });
        }
    }
    let signs = env.mock.state().calls_to("set_signunlock").len();
    for _ in 0..TAKEOVER + 2 {
        for (i, e) in engines.iter_mut().enumerate() {
            if i != leader {
                e.tick().await;
            }
        }
        env.mine(1);
    }
    assert!(unlocks_for(&env, nonce).is_empty(), "held");
    assert_eq!(env.mock.state().calls_to("set_signunlock").len(), signs);
    assert!(
        engines.iter().enumerate().any(
            |(i, e)| i != leader && e.alarms().iter().any(|a| a.name == "unlock-prior-unknown")
        ),
    );
    // the previous leader's API is back (it holds nothing): the takeover goes on
    let l = tokio::net::TcpListener::bind(leader_addr).await.unwrap();
    let ctx = engines[leader].ctx().clone();
    tokio::spawn(async move { hawkeye::api::serve(l, ctx).await.unwrap() });
    for (i, e) in engines.iter_mut().enumerate() {
        if i != leader {
            e.tick().await;
        }
    }
    assert_eq!(
        unlocks_for(&env, nonce).len(),
        1,
        "the fresh unlock, now confirmed safe"
    );
}

/// The leader of `nonce` signs its unlock but the send fails: `(leader, vault)`.
async fn unsent_unlock(env: &Env, e: &mut Engine, nonce: u64) -> CoreOutPoint {
    env.mock
        .state()
        .inject_error("vault_send", -26, "16: mock refusal");
    e.tick().await;
    assert!(unlocks_for(env, nonce).is_empty());
    let k = BurnKey::new(dep_of(e), nonce);
    e.ctx()
        .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
        .unwrap()
        .unwrap()
        .prevout
}

/// Spend `vault` with a transaction that is not the unlock (it bypasses scripts: the mock).
fn spend_otherwise(env: &Env, vault: &CoreOutPoint) {
    let spend = Transaction::new_v4(
        vec![TxIn {
            prevout: OutPoint::new(Hash256(vault.txid), vault.vout),
            script_sig: vec![0x51],
            sequence: u32::MAX,
        }],
        vec![TxOut {
            value: 1000,
            script_pubkey: YcashRecipient::p2pkh([0x15; 20]).script(),
        }],
        0,
        0,
    );
    env.mock.state().submit(spend.encode()).unwrap();
}

fn row_of(
    e: &Engine,
    env: &Env,
    nonce: u64,
    vault: &CoreOutPoint,
) -> hawkeye_store::UnlockBurnRecord {
    let k = BurnKey::new(dep_of(e), nonce);
    e.ctx()
        .db(|t| t.unlock_burn_rows(&env.set.0, &k))
        .unwrap()
        .into_iter()
        .find(|r| r.prevout == *vault)
        .unwrap()
}

/// (r7) M-2: the conflicting spend of the vault is reorged away: the dead inference reads the
/// ledger's spend record (rewound by the reorg), so blocks mined afterwards never fast-forward
/// the row to dead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r7_reorged_conflict_never_makes_a_row_dead() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    // takeover is 1,000 here, so the vault must sit beyond roll_margin + takeover × |live|
    let (op, _) = env.lock_aged(1_000_000_000, &env.holder.eth_address(), 20_000);
    drive_mint(&env, &mut engines, &op).await;
    let r = YcashRecipient::p2pkh([0x67; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let mut e = env.engine_with(leader, vec![], |p| p.takeover = 1000).await;
    drop(engines);
    let vault = unsent_unlock(&env, &mut e, nonce).await;
    spend_otherwise(&env, &vault);
    let height = env.mock.state().tip_height() + 1;
    env.mine(1);
    e.tick().await;
    assert!(row_of(&e, &env, nonce, &vault).is_live());
    env.reorg_from(height);
    for _ in 0..C_Y + 3 {
        e.tick().await;
        env.mine(1);
    }
    e.tick().await;
    assert!(
        row_of(&e, &env, nonce, &vault).is_live(),
        "a reorged-away conflict never counts"
    );
}

/// (r8) M-2: the follower lags the tip: no dead inference until it has recorded the vault's
/// spender at the tip; then a conflicting spend `C_Y` deep is dead (the positive control).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r8_lagging_follower_never_declares_dead() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    let (op, _) = env.lock_aged(1_000_000_000, &env.holder.eth_address(), 20_000);
    drive_mint(&env, &mut engines, &op).await;
    let r = YcashRecipient::p2pkh([0x68; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let mut e = env.engine_with(leader, vec![], |p| p.takeover = 1000).await;
    drop(engines);
    let vault = unsent_unlock(&env, &mut e, nonce).await;
    spend_otherwise(&env, &vault);
    env.mine(1);
    for _ in 0..C_Y + 3 {
        env.mock
            .state()
            .inject_error("getblockhash", -1, "mock: the node is busy");
        e.tick().await;
        env.mine(1);
    }
    assert!(
        row_of(&e, &env, nonce, &vault).is_live(),
        "the follower never recorded the spend"
    );
    e.tick().await; // caught up: the spend, C_Y deep, is another transaction's
    let row = row_of(&e, &env, nonce, &vault);
    assert!(
        row.dead_reason
            .as_deref()
            .is_some_and(|r| r.contains("spent by another transaction")),
        "{row:?}"
    );
}

/// (r9) M-3: the leader's unlock leaves the mempool unmined: after `max(TAKEOVER, C_Y)` blocks
/// the burn is assigned again and the same signed unlock is re-sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r9_evicted_unlock_is_resent() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x69; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    tick_all(&mut engines).await;
    let posted = unlocks_for(&env, nonce);
    assert_eq!(posted.len(), 1);
    let (tx, vault) = posted[0].clone();
    let txid = tx.txid();
    {
        let mut st = env.mock.state();
        st.mempool.retain(|t| *t != txid);
        st.txs.remove(&txid);
    }
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let signs = env.mock.state().calls_to("set_signunlock").len();
    let mut back = false;
    for _ in 0..TAKEOVER + 3 {
        env.mine(1);
        tick_all(&mut engines).await;
        if !unlocks_for(&env, nonce).is_empty() {
            back = true;
            break;
        }
    }
    assert!(back, "re-sent");
    let again = unlocks_for(&env, nonce);
    assert_eq!(again[0].1, vault, "the same vault");
    assert_eq!(
        env.mock.state().calls_to("set_signunlock").len(),
        signs,
        "the same signature, no new one"
    );
    tick_all(&mut engines).await;
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::IntentPending, "linked again");
    }
}

/// (r10) L-2: a ledger holding fewer sign-once records than its high-water mark is flagged
/// restored; while flagged, a fresh unlock needs every member's signed "none" (`prior_unlock`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r10_ledger_restore_is_detected() {
    let Some(env) = setup().await else { return };
    let e = env.engine(0).await;
    let hwm = env.dir.path().join("attestor0.db.hwm");
    assert_eq!(hawkeye::restore::detect(e.ctx(), &hwm).await.unwrap(), None);
    hawkeye::restore::write_hwm(&hwm, 5).unwrap();
    let why = hawkeye::restore::detect(e.ctx(), &hwm)
        .await
        .unwrap()
        .unwrap();
    assert!(why.contains("high-water mark"), "{why}");
    hawkeye::restore::check_restore(e.ctx(), &hwm)
        .await
        .unwrap();
    assert!(
        e.ctx()
            .db(|t| t.meta(hawkeye::engine::burn::LEDGER_RESTORED))
            .unwrap()
            .is_some()
    );
    // the mark never goes down by itself
    hawkeye::restore::write_hwm(&hwm, 2).unwrap();
    assert_eq!(hawkeye::restore::read_hwm(&hwm), 5);
}

// ------------------------------------------------------------------------------------------
// (s) re-review of fix/unlock-revival: N-1 non-current members, the owner's override, N-2 a
// restored ledger never says "none", N-3 observed unlocks adopted

/// Three engines whose APIs are served except the `down` one's (its port is closed). Returns
/// the engines and the down member's address (to serve it later).
async fn with_one_down(env: &Env, down: usize) -> (Vec<Engine>, std::net::SocketAddr) {
    let mut listeners = vec![];
    let mut urls = vec![];
    for _ in 0..3 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}", l.local_addr().unwrap()));
        listeners.push(Some(l));
    }
    let addr = listeners[down].as_ref().unwrap().local_addr().unwrap();
    listeners[down] = None;
    let mut engines = vec![];
    for i in 0..3 {
        let peers = (0..3)
            .filter(|j| *j != i)
            .map(|j| urls[j].clone())
            .collect();
        engines.push(env.engine_with_peers(i, peers).await);
    }
    for (i, l) in listeners.into_iter().enumerate() {
        if let Some(l) = l {
            let ctx = engines[i].ctx().clone();
            tokio::spawn(async move { hawkeye::api::serve(l, ctx).await.unwrap() });
        }
    }
    (engines, addr)
}

/// Lock, mint and burn; the burn's leader never ticks and its API is down; the others tick past
/// the takeover: the burn is held (r6). Returns `(engines, leader, nonce)`.
async fn held_takeover(env: &Env) -> (Vec<Engine>, usize, u64) {
    let mut engines = three(env).await;
    lock_and_mint(env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x71; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(env, nonce);
    drop(engines);
    let (mut engines, _) = with_one_down(env, leader).await;
    for _ in 0..TAKEOVER + 2 {
        for (i, e) in engines.iter_mut().enumerate() {
            if i != leader {
                e.tick().await;
            }
        }
        env.mine(1);
    }
    assert!(unlocks_for(env, nonce).is_empty(), "held");
    (engines, leader, nonce)
}

/// (s1) N-1: once the unreachable previous leader is no longer a current member (here it left
/// the set), its answer is not needed — a non-current member's set signature can never confirm
/// (`CheckSetSigs`) — and the takeover signs a fresh vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s1_a_member_no_longer_current_is_not_required() {
    let Some(env) = setup().await else { return };
    let (mut engines, leader, nonce) = held_takeover(&env).await;
    {
        let mut st = env.mock.state();
        let h = st.tip_height();
        st.leave_member(&env.set, &PubKey(env.key_of_index(leader)), h);
    }
    env.mine(1);
    for _ in 0..2 {
        for (i, e) in engines.iter_mut().enumerate() {
            if i != leader {
                e.tick().await;
            }
        }
    }
    assert_eq!(unlocks_for(&env, nonce).len(), 1, "no longer held");
}

/// (s2) The owner's override: a quorum — a strict majority of the other current members, never
/// less than `unlockThreshold` — declares the unreachable leader gone; the hold is released. A self-declaration, a forged
/// signature and a non-member's declaration are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2_declared_gone_by_a_quorum_releases_the_hold() {
    let Some(env) = setup().await else { return };
    let (mut engines, leader, nonce) = held_takeover(&env).await;
    let mk = env.key_of_index(leader);
    let decl = |by: &SecretKey, member: [u8; 33]| gone_decl(&env, by, member, 2 * TAKEOVER);
    // refusals, on every ledger
    for (i, e) in engines.iter().enumerate() {
        if i == leader {
            continue;
        }
        let me = env.keys[i].clone();
        assert!(
            hawkeye::engine::burn::record_gone(e.ctx(), None, &decl(&env.keys[leader], mk))
                .await
                .is_err(),
            "self-declaration"
        );
        let mut forged = decl(&me, mk);
        forged.sig = decl(&env.keys[leader], mk).sig;
        assert!(
            hawkeye::engine::burn::record_gone(e.ctx(), None, &forged)
                .await
                .is_err(),
            "forged"
        );
        assert!(
            hawkeye::engine::burn::record_gone(e.ctx(), None, &decl(&env.holder, mk))
                .await
                .is_err(),
            "not a member"
        );
    }
    // n = 3, k = 1: the quorum is a strict majority of the two others, 2; one is not enough
    let first = (leader + 2) % 3;
    for (i, e) in engines.iter().enumerate() {
        if i == leader {
            continue;
        }
        let a = hawkeye::engine::burn::record_gone(e.ctx(), None, &decl(&env.keys[first], mk))
            .await
            .unwrap();
        assert_eq!((a.declarations, a.quorum), (1, 2));
    }
    for (i, e) in engines.iter_mut().enumerate() {
        if i != leader {
            e.tick().await;
        }
    }
    assert!(
        unlocks_for(&env, nonce).is_empty(),
        "one declaration is not a quorum"
    );
    let second = (leader + 1) % 3;
    for (i, e) in engines.iter().enumerate() {
        if i == leader {
            continue;
        }
        let a = hawkeye::engine::burn::record_gone(e.ctx(), None, &decl(&env.keys[second], mk))
            .await
            .unwrap();
        assert_eq!((a.declarations, a.quorum), (2, 2));
    }
    for _ in 0..2 {
        for (i, e) in engines.iter_mut().enumerate() {
            if i != leader {
                e.tick().await;
            }
        }
    }
    assert_eq!(
        unlocks_for(&env, nonce).len(),
        1,
        "released by the override"
    );
}

/// (s3) N-2: a restored ledger never answers "none" (it cannot know what it signed before the
/// backup).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_a_restored_ledger_answers_unknown() {
    let Some(env) = setup().await else { return };
    let (mut engines, urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let ask = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[1]));
    let a = ask.burn_unlock(&urls[0], 5).await.unwrap();
    assert!(!a.body.held && !a.body.restored, "an ordinary ledger: none");
    engines[0]
        .ctx()
        .db(|t| t.set_meta(hawkeye::engine::burn::LEDGER_RESTORED, "test"))
        .unwrap();
    let a = ask.burn_unlock(&urls[0], 5).await.unwrap();
    assert!(a.body.restored);
    assert!(a.body.held, "restored: never 'none'");
    assert_eq!(a.body.unlock, None);
}

/// (s4) N-3: the leader's unlock was observed in the mempool by the others, then evicted, and
/// the leader is gone (API down). The re-finalized burn's takeover adopts the observed bytes
/// (the same spend, re-funded) without the leader's answer and without building anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_a_divergent_leaders_evicted_unlock_is_adopted_not_rebuilt() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x72; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    drop(engines);
    let (mut engines, _) = with_one_down(&env, leader).await;
    // the leader posts; everyone observes it
    tick_all(&mut engines).await;
    tick_all(&mut engines).await;
    let posted = unlocks_for(&env, nonce);
    assert_eq!(posted.len(), 1);
    let (tx, vault) = posted[0].clone();
    // evicted, and the leader is gone for good
    {
        let mut st = env.mock.state();
        let txid = tx.txid();
        st.mempool.retain(|t| *t != txid);
        st.txs.remove(&txid);
    }
    let builds = env.mock.state().calls_to("vault_buildunlock").len();
    let signs = env.mock.state().calls_to("set_signunlock").len();
    let mut back = false;
    for _ in 0..3 * TAKEOVER + 4 {
        env.mine(1);
        for (i, e) in engines.iter_mut().enumerate() {
            if i != leader {
                e.tick().await;
            }
        }
        if !unlocks_for(&env, nonce).is_empty() {
            back = true;
            break;
        }
    }
    assert!(back, "the observed unlock was re-sent");
    assert_eq!(unlocks_for(&env, nonce)[0].1, vault, "on its own vault");
    assert_eq!(
        env.mock.state().calls_to("vault_buildunlock").len(),
        builds,
        "nothing rebuilt"
    );
    assert!(
        env.mock.state().calls_to("set_signunlock").len() <= signs + 1,
        "no fresh signature beyond the adopter's no-op pass"
    );
}

/// (s2b) The override quorum at `k = 1`, `n = 4`: a strict majority of the three others (2).
/// One declaration (a single, possibly malicious, member) releases nothing; a declaration from a
/// member that then leaves the set stops counting; after three declarations (two from members
/// still current: the majority of the three current members) the hold is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2b_one_declaration_is_not_a_quorum_at_k1_n4() {
    let Some(env) = setup_with(Opts {
        members: 4,
        ..Opts::default()
    })
    .await
    else {
        return;
    };
    assert_eq!(hawkeye::engine::burn::gone_quorum(1, 4), 2);
    assert_eq!(hawkeye::engine::burn::gone_quorum(1, 3), 2);
    assert_eq!(hawkeye::engine::burn::gone_quorum(3, 4), 3);
    assert_eq!(hawkeye::engine::burn::gone_quorum(1, 7), 4);
    let mut engines = vec![];
    for i in 0..4 {
        engines.push(env.engine(i).await);
    }
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x73; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let mut live: Vec<[u8; 33]> = (0..4).map(|i| env.key_of_index(i)).collect();
    hawkeye_core::keys::sort_members(&mut live);
    let leader = (0..4)
        .find(|i| env.key_of_index(*i) == live[(nonce % 4) as usize])
        .unwrap();
    drop(engines);
    // four APIs, the leader's down
    let mut listeners = vec![];
    let mut urls = vec![];
    for _ in 0..4 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}", l.local_addr().unwrap()));
        listeners.push(Some(l));
    }
    listeners[leader] = None;
    let mut engines = vec![];
    for i in 0..4 {
        let peers = (0..4)
            .filter(|j| *j != i)
            .map(|j| urls[j].clone())
            .collect();
        engines.push(env.engine_with_peers(i, peers).await);
    }
    for (i, l) in listeners.into_iter().enumerate() {
        if let Some(l) = l {
            let ctx = engines[i].ctx().clone();
            tokio::spawn(async move { hawkeye::api::serve(l, ctx).await.unwrap() });
        }
    }
    for _ in 0..2 * TAKEOVER + 2 {
        tick_except(&mut engines, leader).await;
        env.mine(1);
    }
    assert!(unlocks_for(&env, nonce).is_empty(), "held");
    let mk = env.key_of_index(leader);
    let decl = |by: &SecretKey| gone_decl(&env, by, mk, 2 * TAKEOVER);
    let others: Vec<usize> = (0..4).filter(|i| *i != leader).collect();
    let declare = |by: usize, engines: &Vec<Engine>| {
        let d = decl(&env.keys[by]);
        let ctxs: Vec<_> = others.iter().map(|i| engines[*i].ctx().clone()).collect();
        async move {
            let mut last = None;
            for c in ctxs {
                last = Some(
                    hawkeye::engine::burn::record_gone(&c, None, &d)
                        .await
                        .unwrap(),
                );
            }
            last.unwrap()
        }
    };
    // one member alone (the attack): no release
    let a = declare(others[0], &engines).await;
    assert_eq!((a.declarations, a.quorum), (1, 2));
    tick_except(&mut engines, leader).await;
    assert!(
        unlocks_for(&env, nonce).is_empty(),
        "one declaration releases nothing"
    );
    // its declarer leaves the set: its declaration stops counting
    {
        let mut st = env.mock.state();
        let h = st.tip_height();
        st.leave_member(&env.set, &PubKey(env.key_of_index(others[0])), h);
    }
    env.mine(1);
    tick_except(&mut engines, leader).await;
    // three: released
    let a = declare(others[1], &engines).await;
    assert_eq!(
        (a.declarations, a.quorum),
        (1, 2),
        "the leaver's declaration no longer counts (n = 3 current now)"
    );
    tick_except(&mut engines, leader).await;
    assert!(unlocks_for(&env, nonce).is_empty(), "still no quorum");
    let a = declare(others[2], &engines).await;
    assert_eq!((a.declarations, a.quorum), (2, 2), "{a:?}");
    // the burn may sit with the member that left until the takeover moves it on
    let mut released = false;
    for _ in 0..3 * TAKEOVER + 3 {
        tick_except(&mut engines, leader).await;
        if !unlocks_for(&env, nonce).is_empty() {
            released = true;
            break;
        }
        env.mine(1);
    }
    assert!(released, "released by a majority");
}

/// Tick every engine but `skip`.
async fn tick_except(engines: &mut [Engine], skip: usize) {
    for (i, e) in engines.iter_mut().enumerate() {
        if i != skip {
            e.tick().await;
        }
    }
}

/// A declaration by `by` that `member` (its current membership) is gone, expiring `blocks` ahead.
fn gone_decl(
    env: &Env,
    by: &SecretKey,
    member: [u8; 33],
    blocks: u32,
) -> hawkeye::peers::GoneDeclaration {
    let (seq, tip) = {
        let st = env.mock.state();
        let seq = st.sets[&env.set]
            .memberlist
            .iter()
            .find(|m| m.key.0 == member)
            .map_or(0, |m| m.joinheight);
        (seq, st.tip_height())
    };
    gone_decl_at(env, by, member, seq, tip + blocks)
}

fn gone_decl_at(
    env: &Env,
    by: &SecretKey,
    member: [u8; 33],
    seq: u32,
    expiry: u32,
) -> hawkeye::peers::GoneDeclaration {
    hawkeye::peers::GoneDeclaration {
        member: hex::encode(member),
        declarer: hex::encode(by.public_key()),
        seq,
        expiry,
        sig: hex::encode(
            hawkeye_core::peerauth::sign(
                by,
                &hawkeye_core::peerauth::gone_msg(&env.set.0, &member, seq, expiry),
            )
            .unwrap(),
        ),
        reason: "test".into(),
    }
}

// ------------------------------------------------------------------------------------------
// (t) final re-review: R-1 restored reports, R-2 scoped declarations, R-3 bounded growth

fn restore_report(vault: &OutPoint, count: u32, event: &str) -> hawkeye::peers::OrphanRequest {
    hawkeye::peers::OrphanRequest {
        nonce: 0,
        vault: format!("{}:{}", vault.txid, vault.vout),
        restored: true,
        count,
        event: event.into(),
    }
}

/// (t1) R-1: a restored report is refused from a reporter that does not say it is restored;
/// without evidence (this ledger never saw the reporter sign a spend of the vault) a reporter gets
/// 4 reports per 4,032-block window, across all its events — a fresh event id resets nothing; past
/// that, refused and alarmed `restore-report-flood`, which clears once the window has passed; a
/// vault already marked is never marked again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t1_restored_reports_need_evidence_and_are_rate_limited() {
    let Some(env) = setup().await else { return };
    let (mut engines, urls) = networked(&env).await;
    for _ in 0..5 {
        lock_and_mint(&env, &mut engines).await;
    }
    let vs = free_vaults(&env).await;
    assert!(vs.len() >= 5);
    let reporter = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[1]));
    // not restored: refused
    let e = reporter
        .orphaned(&urls[0], &restore_report(&vs[0], 2, "ab"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("does not show its ledger restored"), "{e}");
    engines[1]
        .ctx()
        .db(|t| t.set_meta(hawkeye::engine::burn::LEDGER_RESTORED, "test"))
        .unwrap();
    // the receiver cached the reporter's earlier `false` (TTL); let it lapse
    engines[0]
        .ctx()
        .auth
        .restore_answers
        .lock()
        .unwrap()
        .clear();
    // four uncorroborated, each under a new event id
    for (n, v) in vs[..4].iter().enumerate() {
        let a = reporter
            .orphaned(&urls[0], &restore_report(v, 1, &format!("e{n}")))
            .await
            .unwrap();
        assert!(a.body.marked);
    }
    // a fifth, under yet another event: refused, the window counts across events
    let e = reporter
        .orphaned(&urls[0], &restore_report(&vs[4], 1, "ff"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("uncorroborated") && e.contains("cap 4"), "{e}");
    // a vault already marked: never again
    let e = reporter
        .orphaned(&urls[0], &restore_report(&vs[0], 1, "aa"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("already rolled"), "{e}");
    engines[0].tick().await;
    assert!(
        engines[0]
            .alarms()
            .iter()
            .any(|a| a.name == "restore-report-flood")
    );
    // the window passes: the alarm clears
    env.mine(hawkeye::engine::roll::RESTORE_WINDOW + 2);
    engines[0].tick().await;
    assert!(
        !engines[0]
            .alarms()
            .iter()
            .any(|a| a.name == "restore-report-flood"),
        "{:?}",
        engines[0].alarms()
    );
}

/// (t5) R-1 lineage: a vault rolled for a restored report is rolled for real (roll intent, then
/// its release into a new vault); that successor is never marked for a restored report.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t5_the_successor_of_a_restore_rolled_vault_is_never_marked() {
    let Some(env) = setup().await else { return };
    let (mut engines, urls) = networked(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let v = free_vaults(&env).await[0];
    let vc = CoreOutPoint::new(v.txid.0, v.vout);
    engines[1]
        .ctx()
        .db(|t| t.set_meta(hawkeye::engine::burn::LEDGER_RESTORED, "test"))
        .unwrap();
    let reporter = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[1]));
    for i in [0usize, 2] {
        let a = reporter
            .orphaned(&urls[i], &restore_report(&v, 1, "ab"))
            .await
            .unwrap();
        assert!(a.body.marked);
    }
    // the reporter's own ledger marks it too (as its restore check does)
    engines[1]
        .ctx()
        .db(|t| {
            t.transition_vault(
                &vc,
                VaultState::RollDue,
                None,
                Some("restore orphan (test)"),
            )
        })
        .unwrap();
    // the roll, its window, its release
    let mut successor = None;
    for _ in 0..4 * TAKEOVER + u32::from(DELAY) + 10 {
        tick_all(&mut engines).await;
        env.mine(1);
        successor = engines[0]
            .ctx()
            .db(|t| {
                let mut out = None;
                for i in t.intents_in_state(IntentState::Released)? {
                    if i.origin_vault == Some(vc)
                        && let Some(r) = i.released_txid
                    {
                        for x in t.vaults_in_state(VaultState::Live)? {
                            if x.outpoint.txid == r {
                                out = Some(x.outpoint);
                            }
                        }
                    }
                }
                Ok(out)
            })
            .unwrap();
        if successor.is_some() {
            break;
        }
    }
    let succ = successor.expect("the roll was released into a new vault");
    let so = OutPoint::new(Hash256(succ.txid), succ.vout);
    let e = reporter
        .orphaned(&urls[0], &restore_report(&so, 1, "cd"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("descends"), "{e}");
}

/// (t2) R-2: an expired declaration does not count; a declaration naming another membership
/// (seq) of the member is refused; a declaration about a member that is not in the set is
/// refused (R-3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t2_declarations_are_scoped_and_expire() {
    let Some(env) = setup().await else { return };
    let (mut engines, leader, nonce) = held_takeover(&env).await;
    let mk = env.key_of_index(leader);
    let others: Vec<usize> = (0..3).filter(|i| *i != leader).collect();
    // a quorum (2 of the 2 others), but expiring in one block
    for &d in &others {
        for &i in &others {
            hawkeye::engine::burn::record_gone(
                engines[i].ctx(),
                None,
                &gone_decl(&env, &env.keys[d], mk, 1),
            )
            .await
            .unwrap();
        }
    }
    env.mine(2); // past their expiry
    for _ in 0..3 {
        tick_except(&mut engines, leader).await;
        env.mine(1);
    }
    assert!(
        unlocks_for(&env, nonce).is_empty(),
        "expired declarations release nothing"
    );
    // the positive control: the same quorum, not expired, releases
    for &d in &others {
        for &i in &others {
            hawkeye::engine::burn::record_gone(
                engines[i].ctx(),
                None,
                &gone_decl(&env, &env.keys[d], mk, 4),
            )
            .await
            .unwrap();
        }
    }
    tick_except(&mut engines, leader).await;
    tick_except(&mut engines, leader).await;
    assert_eq!(unlocks_for(&env, nonce).len(), 1, "a live quorum releases");
    // another membership of the member
    let seq = {
        let st = env.mock.state();
        st.sets[&env.set]
            .memberlist
            .iter()
            .find(|m| m.key.0 == mk)
            .unwrap()
            .joinheight
    };
    let tip = env.mock.state().tip_height();
    let e = hawkeye::engine::burn::record_gone(
        engines[others[0]].ctx(),
        None,
        &gone_decl_at(&env, &env.keys[others[1]], mk, seq + 1, tip + 4),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(e.contains("membership"), "{e}");
    // too far ahead
    let e = hawkeye::engine::burn::record_gone(
        engines[others[0]].ctx(),
        None,
        &gone_decl_at(&env, &env.keys[others[1]], mk, seq, tip + 100 * TAKEOVER),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(e.contains("expires"), "{e}");
    // not a member of the set at all
    let stranger = secret(50).public_key();
    let e = hawkeye::engine::burn::record_gone(
        engines[others[0]].ctx(),
        None,
        &gone_decl_at(&env, &env.keys[others[1]], stranger, 0, tip + 4),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(e.contains("not in the set's member list"), "{e}");
}

/// (t3) R-2 and the `gone-member-answered` path: a member declared gone by a quorum answers
/// (here: its ledger is restored, so it answers "held"); its declarations are dropped, the alarm
/// is raised, and its hold stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t3_a_declared_member_that_answers_keeps_its_hold() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x74; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    drop(engines);
    let (mut engines, addr) = with_one_down(&env, leader).await;
    for _ in 0..TAKEOVER + 2 {
        tick_except(&mut engines, leader).await;
        env.mine(1);
    }
    let mk = env.key_of_index(leader);
    let others: Vec<usize> = (0..3).filter(|i| *i != leader).collect();
    for &d in &others {
        for &i in &others {
            hawkeye::engine::burn::record_gone(engines[i].ctx(), None, &{
                // uppercase keys: stored and deleted normalised (R-2 nit)
                let mut g = gone_decl(&env, &env.keys[d], mk, 3 * TAKEOVER);
                g.member = g.member.to_uppercase();
                g.declarer = g.declarer.to_uppercase();
                g
            })
            .await
            .unwrap();
        }
    }
    // stored under the lowercase keys whatever the declarations' case
    for &i in &others {
        let n = engines[i]
            .ctx()
            .db(|t| t.meta_prefix(&format!("gone/{}/", hex::encode(mk))))
            .unwrap()
            .len();
        assert_eq!(n, 2, "normalised keys");
    }
    // the member comes back before anyone acts: restored, it answers "held"
    engines[leader]
        .ctx()
        .db(|t| t.set_meta(hawkeye::engine::burn::LEDGER_RESTORED, "test"))
        .unwrap();
    let l = tokio::net::TcpListener::bind(addr).await.unwrap();
    let ctx = engines[leader].ctx().clone();
    tokio::spawn(async move { hawkeye::api::serve(l, ctx).await.unwrap() });
    tick_except(&mut engines, leader).await;
    assert!(unlocks_for(&env, nonce).is_empty(), "its hold stands");
    assert!(
        engines.iter().enumerate().any(
            |(i, e)| i != leader && e.alarms().iter().any(|a| a.name == "gone-member-answered")
        ),
        "alarmed"
    );
    let left = engines[others[0]]
        .ctx()
        .db(|t| t.meta_prefix(&format!("gone/{}/", hex::encode(mk))))
        .unwrap();
    let left1 = engines[others[1]]
        .ctx()
        .db(|t| t.meta_prefix(&format!("gone/{}/", hex::encode(mk))))
        .unwrap();
    assert!(
        left.is_empty() || left1.is_empty(),
        "the taking-over ledger dropped the declarations once the member answered"
    );
}

/// (t4) R-3: the observed unlocks of a burn released `C_Y` deep are pruned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t4_observed_unlocks_are_pruned_after_release() {
    let Some(env) = setup().await else { return };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x75; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    tick_all(&mut engines).await;
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let prefix = format!("observed_unlock/{k}/");
    assert!(
        engines
            .iter()
            .any(|e| !e.ctx().db(|t| t.meta_prefix(&prefix)).unwrap().is_empty()),
        "observed while pending"
    );
    for _ in 0..u32::from(DELAY) + C_Y + 4 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for e in &engines {
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::Released);
        assert!(
            e.ctx().db(|t| t.meta_prefix(&prefix)).unwrap().is_empty(),
            "pruned"
        );
    }
}

// ------------------------------------------------------------------------------------------
// (v) nits after the final review: the restored-answer cache, the cap before any request, pruning

/// (v1) The reporter's "restored" answer is cached per reporter with a TTL: a cached `true`
/// lapses, so once the reporter acknowledged its restore its reports are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_a_cached_restored_answer_expires() {
    let Some(env) = setup().await else { return };
    let (mut engines, urls) = networked(&env).await;
    for _ in 0..3 {
        lock_and_mint(&env, &mut engines).await;
    }
    let vs = free_vaults(&env).await;
    let reporter = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[1]));
    engines[1]
        .ctx()
        .db(|t| t.set_meta(hawkeye::engine::burn::LEDGER_RESTORED, "test"))
        .unwrap();
    reporter
        .orphaned(&urls[0], &restore_report(&vs[0], 1, "e1"))
        .await
        .unwrap();
    let me1 = env.key_of_index(1);
    assert_eq!(
        engines[0].ctx().auth.restore_answers.lock().unwrap().len(),
        1,
        "one entry per reporter, whatever the event"
    );
    // the reporter acknowledges its restore; the cached `true` still holds within the TTL
    engines[1]
        .ctx()
        .db(|t| t.set_meta(hawkeye::engine::burn::LEDGER_RESTORED, "acknowledged"))
        .unwrap();
    reporter
        .orphaned(&urls[0], &restore_report(&vs[1], 1, "e2"))
        .await
        .unwrap();
    assert_eq!(
        engines[0].ctx().auth.restore_answers.lock().unwrap().len(),
        1,
        "still one entry: keyed by reporter"
    );
    // the TTL passes: asked again, the answer is now `false`
    {
        let mut c = engines[0].ctx().auth.restore_answers.lock().unwrap();
        let old = std::time::Instant::now()
            .checked_sub(hawkeye::peer_auth::RESTORE_ANSWER_TTL + std::time::Duration::from_secs(1))
            .unwrap();
        c.insert(me1, (true, old));
    }
    let e = reporter
        .orphaned(&urls[0], &restore_report(&vs[2], 1, "e3"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("does not show its ledger restored"), "{e}");
}

/// (v2) A reporter already over its cap is refused before anything is asked of it: no cached
/// answer appears, and the refusal is the cap's (not "does not show restored").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_the_cap_is_checked_before_any_request() {
    let Some(env) = setup().await else { return };
    let (mut engines, urls) = networked(&env).await;
    for _ in 0..5 {
        lock_and_mint(&env, &mut engines).await;
    }
    let vs = free_vaults(&env).await;
    let reporter = Peers::new(vec![])
        .unwrap()
        .with_signer(env.signer(&env.keys[1]));
    engines[1]
        .ctx()
        .db(|t| t.set_meta(hawkeye::engine::burn::LEDGER_RESTORED, "test"))
        .unwrap();
    for (n, v) in vs[..4].iter().enumerate() {
        reporter
            .orphaned(&urls[0], &restore_report(v, 1, &format!("e{n}")))
            .await
            .unwrap();
    }
    // forget the cached answer and make the reporter no longer restored: were it asked, the
    // refusal would be "does not show restored"
    engines[0]
        .ctx()
        .auth
        .restore_answers
        .lock()
        .unwrap()
        .clear();
    engines[1]
        .ctx()
        .db(|t| t.set_meta(hawkeye::engine::burn::LEDGER_RESTORED, "acknowledged"))
        .unwrap();
    let e = reporter
        .orphaned(&urls[0], &restore_report(&vs[4], 1, "e9"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("cap 4"), "{e}");
    assert!(
        engines[0]
            .ctx()
            .auth
            .restore_answers
            .lock()
            .unwrap()
            .is_empty(),
        "nothing was asked of the reporter"
    );
}

/// (v3) `restore_report/` keys older than the window are pruned; recent ones stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v3_old_restore_reports_are_pruned() {
    let Some(env) = setup().await else { return };
    let mut e = env.engine(0).await;
    e.tick().await;
    env.mine(hawkeye::engine::roll::RESTORE_WINDOW + 10);
    let tip = env.mock.state().tip_height();
    let rep = hex::encode(env.key_of_index(1));
    let old = format!("restore_report/{rep}/{:010}/{}:0", 1, "aa".repeat(32));
    let recent = format!("restore_report/{rep}/{:010}/{}:0", tip - 1, "bb".repeat(32));
    e.ctx()
        .db(|t| {
            t.set_meta(&old, "u")?;
            t.set_meta(&recent, "u")
        })
        .unwrap();
    e.tick().await;
    let left: Vec<String> = e
        .ctx()
        .db(|t| t.meta_prefix("restore_report/"))
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(left, vec![recent]);
}

fn drop_unlocks(env: &Env, nonce: u64) {
    let ids: Vec<_> = unlocks_for(env, nonce)
        .into_iter()
        .map(|(t, _)| t.txid())
        .collect();
    let mut st = env.mock.state();
    st.mempool.retain(|t| !ids.contains(t));
}

fn core_of(op: &OutPoint) -> CoreOutPoint {
    CoreOutPoint::new(op.txid.0, op.vout)
}

fn alarm_named(e: &Engine, name: &str) -> bool {
    e.alarms().iter().any(|a| a.name == name)
}

/// Drive `nonce` until its leader has an unlock in the mempool and every engine has ticked
/// while that unlock is still there. Returns the vault.
async fn signed_observed(env: &Env, engines: &mut [Engine], nonce: u64) -> OutPoint {
    let leader = leader_index(env, nonce);
    let mut vault = None;
    for _ in 0..8 {
        engines[leader].tick().await;
        if let Some((_, v)) = unlocks_for(env, nonce).into_iter().next() {
            vault = Some(v);
            break;
        }
        env.mine(1);
    }
    let vault = vault.expect("the leader signed an unlock");
    tick_all(engines).await;
    vault
}

/// W4-B-2: an unlock signed only by a member who then leaves is not adopted. The burn is paid
/// from another vault and the first vault is rolled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w4b2_unlock_signed_by_a_departed_member_is_never_adopted() {
    let opts = Opts {
        wallet_views: true,
        ..Opts::default()
    };
    let Some(env) = setup_with(opts).await else {
        return;
    };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x71; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let v1 = signed_observed(&env, &mut engines, nonce).await;
    let owner = {
        let st = env.mock.state();
        st.templates[&v1].as_vault().unwrap().fields.ownerheight
    };
    drop_unlocks(&env, nonce);
    {
        let mut st = env.mock.state();
        let h = st.tip_height();
        st.leave_member(&env.set, &PubKey(env.key_of_index(leader)), h);
    }
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let v1c = core_of(&v1);
    for _ in 0..(4 * TAKEOVER) {
        env.mine(1);
        tick_all(&mut engines).await;
        let done = engines.iter().all(|e| {
            e.ctx().db(|t| t.burn(&k)).unwrap().unwrap().state == BurnState::Released
                && e.ctx().db(|t| t.vault(&v1c)).unwrap().unwrap().state == VaultState::Rolled
        });
        if done {
            break;
        }
    }
    for e in &engines {
        let rows = e
            .ctx()
            .db(|t| t.unlock_burns_of_vault(&env.set.0, &v1c))
            .unwrap();
        assert!(
            rows.iter()
                .all(|r| r.origin != hawkeye_store::UnlockOrigin::Adopted),
            "no adopted row: {rows:?}"
        );
        let v = e.ctx().db(|t| t.vault(&v1c)).unwrap().unwrap();
        assert_eq!(
            v.state,
            VaultState::Rolled,
            "rolled before owner height {owner}"
        );
        let b = e.ctx().db(|t| t.burn(&k)).unwrap().unwrap();
        assert_eq!(b.state, BurnState::Released);
        assert!(open_cases(e).is_empty(), "{:?}", open_cases(e));
    }
}

/// A ledger that already holds the pre-fix adoption (origin leader, no signature of this
/// member) marks the row dead and still rolls the vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w4b2_pre_fix_adopted_rows_die_and_the_vault_rolls() {
    use hawkeye_store::{SignDomain, UnlockBurn, UnlockOrigin, YcashSignKey};
    let opts = Opts {
        wallet_views: true,
        ..Opts::default()
    };
    let Some(env) = setup_with(opts).await else {
        return;
    };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x72; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let leader = leader_index(&env, nonce);
    let v1 = signed_observed(&env, &mut engines, nonce).await;
    drop_unlocks(&env, nonce);
    let v1c = core_of(&v1);
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let hex = engines[leader]
        .ctx()
        .db(|t| {
            let key = YcashSignKey {
                domain: SignDomain::YcashUnlock,
                set_id: env.set.0,
                prevout: v1c,
            };
            Ok(t.ycash_signature(&key)?.unwrap().signed_hex)
        })
        .unwrap();
    for (i, e) in engines.iter().enumerate() {
        if i == leader {
            continue;
        }
        let hex = hex.clone();
        e.ctx()
            .db(|t| {
                let key = YcashSignKey {
                    domain: SignDomain::YcashUnlock,
                    set_id: env.set.0,
                    prevout: v1c,
                };
                t.sign_once_unlock(
                    &key,
                    Some(&UnlockBurn {
                        key: k,
                        origin: UnlockOrigin::Leader,
                        allow_double: false,
                    }),
                    &hex.clone(),
                    move |_| Ok::<_, String>((hex, [0x22; 32])),
                )?;
                Ok(())
            })
            .unwrap();
    }
    {
        let mut st = env.mock.state();
        let h = st.tip_height();
        st.leave_member(&env.set, &PubKey(env.key_of_index(leader)), h);
    }
    for _ in 0..(4 * TAKEOVER) {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    assert!(
        engines
            .iter()
            .any(|e| alarm_named(e, "legacy_adoption_row")),
        "legacy adoption reported"
    );
    for e in &engines {
        let rows = e
            .ctx()
            .db(|t| t.unlock_burns_of_vault(&env.set.0, &v1c))
            .unwrap();
        assert!(rows.iter().all(|r| !r.is_live()), "rows dead: {rows:?}");
        assert_eq!(
            e.ctx().db(|t| t.vault(&v1c)).unwrap().unwrap().state,
            VaultState::Rolled
        );
        assert_eq!(
            e.ctx().db(|t| t.burn(&k)).unwrap().unwrap().state,
            BurnState::Released
        );
    }
}

/// Burns are not drawn on roll-due vaults, nor on a live vault that falls due inside one
/// takeover rotation (V-N2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w4b2_burns_never_draw_on_roll_due_vaults() {
    let opts = Opts {
        min_owner_age: 5,
        roll_margin: 40,
        ..Opts::default()
    };
    let Some(env) = setup_with(opts).await else {
        return;
    };
    let mut engines = three(&env).await;
    let to = env.holder.eth_address();
    let (near, _) = env.lock_aged(1_000_000_000, &to, 5);
    let (far, _) = env.lock_aged(1_000_000_000, &to, 5_000);
    drive_mint(&env, &mut engines, &near).await;
    drive_mint(&env, &mut engines, &far).await;
    // the near vault is inside ROLL_MARGIN and becomes ROLL_DUE
    for _ in 0..3 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for e in &engines {
        assert_eq!(
            e.ctx().db(|t| t.vault(&near)).unwrap().unwrap().state,
            VaultState::RollDue
        );
        assert_eq!(
            e.ctx().db(|t| t.vault(&far)).unwrap().unwrap().state,
            VaultState::Live
        );
    }
    let r = YcashRecipient::p2pkh([0x73; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    for _ in 0..TAKEOVER + 4 {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    let spent: Vec<_> = unlocks_for(&env, nonce)
        .into_iter()
        .map(|(_, v)| core_of(&v))
        .collect();
    assert!(
        spent.iter().all(|v| *v == far),
        "the unlock spends the live vault, not the roll-due one: {spent:?}"
    );
}

/// After the next branch activates and is C_Y deep, an unmined unlock signed under the old
/// branch dies and its vault is rolled (W4-B-5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w4b5_unlock_signed_under_the_old_branch_dies_after_activation_plus_cy() {
    let opts = Opts {
        wallet_views: true,
        ..Opts::default()
    };
    let Some(env) = setup_with(opts).await else {
        return;
    };
    let mut engines = three(&env).await;
    lock_and_mint(&env, &mut engines).await;
    lock_and_mint(&env, &mut engines).await;
    let r = YcashRecipient::p2pkh([0x74; 20]);
    let nonce = env.burn(300_000_000, &r).await;
    env.eth_mine(3).await;
    let v1 = signed_observed(&env, &mut engines, nonce).await;
    drop_unlocks(&env, nonce);
    let activation = env.mock.state().next_height();
    env.mock.state().set_next_branch(0x2222_2222, activation);
    tick_all(&mut engines).await;
    let k = BurnKey::new(dep_of(&engines[0]), nonce);
    let v1c = core_of(&v1);
    assert!(
        engines.iter().any(|e| {
            e.ctx()
                .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
                .unwrap()
                .is_some()
        }),
        "the row is not dead yet"
    );
    for _ in 0..C_Y + 1 {
        env.mine(1);
    }
    tick_all(&mut engines).await;
    assert!(
        engines.iter().all(|e| {
            e.ctx()
                .db(|t| t.live_unlock_for_burn(&env.set.0, &k))
                .unwrap()
                .is_none()
        }),
        "dead once the new branch is C_Y deep"
    );
    for _ in 0..(3 * TAKEOVER) {
        env.mine(1);
        tick_all(&mut engines).await;
    }
    for e in &engines {
        assert_eq!(
            e.ctx().db(|t| t.vault(&v1c)).unwrap().unwrap().state,
            VaultState::Rolled
        );
        assert_eq!(
            e.ctx().db(|t| t.burn(&k)).unwrap().unwrap().state,
            BurnState::Released
        );
    }
}
