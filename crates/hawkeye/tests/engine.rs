//! Engine tests (plan §9 H4/H5): three Hawkeye engines against one mock ycashd (hawkeye-ycash
//! feature `mock`) and a local anvil with wYEC deployed. Ticks are driven by hand, blocks are
//! mined by hand on both chains, so every run is deterministic.
//!
//! (a) lock → sign → mint observed; (b) burn → unlock with the HKB1 memo → release after the
//! delay; (c) rogue intent → cancelled + slash case → SET_REMOVE; (d) restart mid-flow: no second
//! signature; (e) leader takeover.
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
    Address, B256, Deployment, EthClient, EthConfig, MintMode, PrivateKeySigner, U256, deploy,
    wallet_provider,
};
use hawkeye_store::{BurnKey, BurnState, IntentState, LockState, SlashState, Store, VaultState};
use hawkeye_ycash::mock::{KnownScript, MockState, MockYcashd};
use hawkeye_ycash::tx::{Transaction, TxIn, TxOut};
use hawkeye_ycash::types::{MemberStatus, SetParams, VaultFields};
use hawkeye_ycash::{Amount, Hash256, HexBytes, OutPoint, PubKey};

/// The mock's set signatures are `0x1f ‖ key ‖ sighash[..31]`: attribute by reading the key.
struct MockAttributor;

impl Attributor for MockAttributor {
    fn attribute(
        &self,
        tx_bytes: &[u8],
        input_index: usize,
        prev_spk: &[u8],
        _value: u64,
        _branch: u32,
    ) -> Result<Attribution, String> {
        let tx = Transaction::decode(tx_bytes).map_err(|e| e.to_string())?;
        let input = tx.inputs.get(input_index).ok_or("no input")?;
        let v = hawkeye_core::template::parse_vault(prev_spk).map_err(|e| e.to_string())?;
        let spend = hawkeye_core::template::parse_selector(
            hawkeye_core::template::TemplateKind::Vault,
            &input.script_sig,
        )
        .map_err(|e| e.to_string())?;
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
            set_id: v.set_id,
            role: Role::Unlock,
            prevout: CoreOutPoint::new(input.prevout.txid.0, input.prevout.vout),
            sighash,
            signers,
        })
    }
}

const DELAY: u16 = 6;
const C_Y: u32 = 2;
const TAKEOVER: u32 = 4;

struct Env {
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
    let dep = deploy(
        &provider,
        deployer.address(),
        &guardians,
        1,
        MintMode::Threshold { k: 1 },
        0,
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
            min_owner_age: 400,
            roll_margin: 50,
            takeover: TAKEOVER,
            heartbeat_blocks: 10,
            min_lock: 10_000_000,
            max_lock: 100_000_000_000,
            mint_mode: MintMode::Threshold { k: 1 },
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
            attributor: Arc::new(MockAttributor),
            peers: Peers::new(vec![]).unwrap(),
            status: Arc::new(RwLock::new(Status::default())),
            network_name: "regtest".into(),
        })
    }

    fn mine(&self, n: u32) {
        self.mock.state().mine(n);
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
        let mut st = self.mock.state();
        let owner = st.new_wallet_key();
        let tip = st.tip_height();
        let vp = VaultParams {
            tag: TAG_WYEC,
            set_id: self.set.0,
            cancel_set_id: self.set.0,
            delay: DELAY,
            owner_height: tip + 1000,
            app_height: 0,
            owner_key: owner.0,
        };
        let script = vp.script().unwrap();
        st.register_script(
            script.clone(),
            KnownScript::Vault(VaultFields {
                tag: HexBytes(b"WYEC".to_vec()),
                tagtext: "WYEC".into(),
                setid: self.set,
                cancelsetid: self.set,
                delay: u32::from(DELAY),
                ownerheight: vp.owner_height,
                appheight: 0,
                ownerkey: owner,
            }),
        );
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
        CoreOutPoint::new(txid.0, 0)
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
    let lock_id = hawkeye_core::lock::lock_id(&op);
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
    let refused = peers
        .slash_sign(
            &peers.urls()[0],
            &hawkeye::peers::SlashSignRequest {
                evidence: serde_json::json!({"fault": "FRAUDULENT_INTENT",
                    "target": hex::encode(env.keys[1].public_key()), "subject": "00"}),
                act: "00".into(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("no matching case"), "{refused}");
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
