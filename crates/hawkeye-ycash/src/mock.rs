//! A mock `ycashd` (feature `mock`): an in-process HTTP JSON-RPC server with a scriptable
//! in-memory chain, for this crate's tests and for other crates' engine tests.
//!
//! It answers the 27 `set_*` / `vault_*` RPCs with the contract's shapes and the stock RPCs
//! Hawkeye uses, keeps blocks, a mempool, sets and a template-output index, and applies a
//! simplified version of the node's rules: thresholds, the sign-once record (`set-sign-once`), the
//! cancel window, maturity, the owner branch, the rate limit, double spends. It is not consensus:
//!
//! - vault and intent scripts are placeholders (`MOCKV…`/`MOCKI…` plus a hash of the fields), not
//!   the §15.3 templates; register real scripts with [`MockState::register_script`];
//! - set signatures are fake 65-byte strings `0x1f ‖ key ‖ sighash[..31]` over a mock sighash
//!   (SHA256d of the transaction reduced to its template input, scriptSig cleared, and every
//!   output: like the node's `SIGHASH_ALL|SIGHASH_ANYONECANPAY`, audit 01/V-2, so `vault_refee`
//!   keeps the signatures valid), act transactions carry a mock payload, fee inputs come from an
//!   unlimited mock wallet;
//! - builds are remembered per wallet and vault (`vault_buildunlock`: `reused`, `already built a
//!   different unlock`, `rebuild`; 07/N-2); the sign-once listing RPCs answer from
//!   [`MockState::sign_once`] and [`MockState::restored`] (the restore marker, off by default);
//! - a join is current as soon as it is mined (no maturity).
//!
//! The bond rules are modelled (owner 2026-10-11, quantum plan D-Q-29..D-Q-31): bonds are real
//! P2SH bond outputs ([`mock_bond_spk`]) in a bond index ([`MockState::bonds`]); a bond is
//! spendable only after its member left without a freeze (`set_leave`, or a `SET_REMOVE` without
//! burn) and the set's `maturity` has passed since (`bad-vault-bond-locked` before,
//! `bad-vault-bond-frozen` once frozen), with the script's CLTV on top; one unspent bond per
//! (set, key) (`bad-vault-act-join`); a cosigned burn `SET_REMOVE` reaches a member already in its
//! exit delay; `set_create` refuses a `maturity` below the network's floor ([`MockState::min_set_maturity`]).
//!
//! Every call is recorded ([`MockState::calls`]); [`MockState::queue_result`] and
//! [`MockState::inject_error`] script the next answer of a method, [`MockState::fail_http`] the
//! next HTTP status. Amounts are printed as the node prints them (decimal numbers, 8 places).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::amount::{Amount, COIN};
use crate::client::{Auth, YcashRpc};
use crate::primitives::{
    BlockHash, Bytes32, Hash256, HexBytes, OutPoint, PqKeyId, PubKey, SetId, Txid,
};
use crate::stock::Unspent;
use crate::tx::{OP_1, Transaction, TxIn, TxOut};
use crate::types::*;

/// The vault upgrade's branch id.
pub const VAULT_BRANCH_ID: &str = "6d5b7a31";
/// The flat fee of every transaction the vault RPCs build.
pub const FEE: i64 = 10_000;
/// The node's default `-pqfeerate` (zat per 1000 bytes: the relay floor, quantum plan §4.5). Since
/// the fee structure (ycash-dd rpcversion 8, quantum plan D-Q-23 (b)) it is the rate only while no
/// attested price exists ([`MockState::fee_price_micro_usd`] `None`).
pub const PQ_FEE_RATE: i64 = 100;
/// `-yellowbackfeeusdperkb`: the vault/Yellowback network fee, $0.05 per KB at the attested price.
pub const YED_FEE_USD_PER_KB_MICRO: i64 = 50_000;
/// `DEFAULT_ATTESTED_FEE_FLOOR_PER_KB`: with a price the rate never goes below max(this, `-pqfeerate`).
pub const ATTESTED_FEE_FLOOR_PER_KB: i64 = 5_000;
/// `-maxtxfee` (`DEFAULT_TRANSACTION_MAXFEE`, 0.1 YEC).
pub const MAX_TX_FEE: i64 = 10_000_000;
/// `-yellowbackmaxtxfeeusd`: the vault/Yellowback cap is max(`-maxtxfee`, $2 at the price).
pub const YED_MAX_TX_FEE_USD_MICRO: i64 = 2_000_000;
/// `-yellowbackmaxtxfee`: the absolute YEC ceiling of that cap (10 YEC).
pub const YED_MAX_TX_FEE_CEILING: i64 = 10 * 100_000_000;
/// The bytes of an SLH-DSA owner scriptSig (quantum spec §1.5): 15 chunks of 520 and one of 57,
/// `OP_16`, the 32-byte key, `OP_1`, the selector.
pub const PQ_OWNER_SCRIPTSIG_LEN: usize = 7939;

type RpcResult = Result<Value, (i64, String)>;

/// A scripted answer.
#[derive(Clone, Debug)]
pub enum Reply {
    /// A result (JSON text in the node's format is accepted by [`MockState::queue_result_text`]).
    Result(Value),
    Error {
        code: i64,
        message: String,
    },
}

/// A recorded call.
#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    pub params: Vec<Value>,
    /// The error answered, if any.
    pub error: Option<(i64, String)>,
}

/// A mined block.
#[derive(Clone, Debug)]
pub struct MockBlock {
    pub hash: BlockHash,
    pub height: u32,
    pub time: i64,
    pub txids: Vec<Txid>,
}

/// A template script the mock recognises.
#[derive(Clone, Debug)]
pub enum KnownScript {
    Vault(VaultFields),
    Intent {
        fields: IntentFields,
        origin: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
enum PendingAct {
    Create(SetParams),
    Join {
        setid: SetId,
        member: PubKey,
        bond: Amount,
        locktime: u32,
        bondoutpoint: OutPoint,
    },
    Heartbeat {
        setid: SetId,
        member: PubKey,
    },
    Remove {
        setid: SetId,
        member: PubKey,
        burn: bool,
    },
    /// The member's own `SET_REMOVE` (burn 0, signed by itself alone): `set_leave`.
    Leave {
        setid: SetId,
        member: PubKey,
    },
    Equivocation {
        setid: SetId,
        member: PubKey,
    },
    Winddown {
        setid: SetId,
    },
}

/// A bond in the mock's bond index (the node's `BondRecord` plus the output it names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockBond {
    pub setid: SetId,
    pub member: PubKey,
    pub value: Amount,
    /// The bond script's CLTV height.
    pub locktime: u32,
    pub frozen: bool,
    /// The height its member left the set without a freeze; 0 = still a member's bond.
    pub exitheight: u32,
}

/// The mock node's state. Lock it with [`MockYcashd::state`] and edit it freely.
#[derive(Debug)]
pub struct MockState {
    pub chain: String,
    /// `UPGRADE_VAULT`'s activation height (-1: unscheduled).
    pub activation_height: i64,
    /// The branch id reported before activation.
    pub pre_vault_branch_id: String,
    /// The active chain, `blocks[h]` at height `h`.
    pub blocks: Vec<MockBlock>,
    pub mempool: Vec<Txid>,
    /// Every transaction seen: raw bytes and the block it is in.
    pub txs: HashMap<Txid, (Vec<u8>, Option<BlockHash>)>,
    pub sets: BTreeMap<SetId, SetInfo>,
    /// The bond index: every unspent member bond (frozen ones included).
    pub bonds: BTreeMap<OutPoint, MockBond>,
    /// D-Q-31: the least `maturity` `set_create` accepts (2 on regtest, 16,128 elsewhere).
    pub min_set_maturity: u32,
    /// The confirmed template-output index (`vault_list`); dynamic fields are refreshed on read.
    pub templates: BTreeMap<OutPoint, TemplateOut>,
    pub scripts: HashMap<Vec<u8>, KnownScript>,
    /// Keys in the mock wallet: member keys it signs with.
    pub wallet_keys: BTreeSet<PubKey>,
    /// Post-quantum owner keys in the mock wallet (`vault_getnewowner`).
    pub wallet_owners: BTreeSet<PqKeyId>,
    /// `-pqfeerate` in zat per 1000 bytes (owner spends pay `max(FEE, rate × size)` while no
    /// attested price exists; with one it is part of the floor).
    pub pq_fee_rate: i64,
    /// The attested tip price the node's fee policy uses (µUSD per YEC; ycash-dd rpcversion 8,
    /// `yed_getinfo.params.fees.network.priceMicroUsd`): `None` = no price (the `-pqfeerate`
    /// fallback). With a price an owner spend pays `$0.05/KB × size` at it ([`owner_spend_fee`]).
    pub fee_price_micro_usd: Option<i64>,
    /// Address → scriptPubKey for addresses the mock handed out or was told about.
    pub addresses: BTreeMap<String, Vec<u8>>,
    /// `listunspent`'s answer.
    pub unspent: Vec<Unspent>,
    /// The `(setid, prevout)` → `(role, sighash)` sign-once record.
    pub sign_once: HashMap<(SetId, OutPoint), (u8, Bytes32)>,
    /// The sign-once records of each wallet view ([`MockState::wallet_views`]): separate
    /// attestor nodes each keep their own (the shared map serves the view-less client).
    pub view_sign_once: HashMap<(String, SetId, OutPoint), (u8, Bytes32)>,
    /// The wallet's restore marker (07/F-5): while set, `set_signunlock` / `set_signcancel`
    /// refuse a `(setid, prevout)` with no record (`set-sign-restored`) unless the call passes
    /// `{"acknowledgerestore": true}`; `set_acknowledgerestore` clears it.
    pub restored: bool,
    /// Recipient scripts by `recipienthash` (for `vault_release` without a recipient).
    pub recipients: HashMap<Bytes32, Vec<u8>>,
    /// `-rpcuser`/`-rpcpassword`, checked when set.
    pub auth: Option<(String, String)>,
    /// Per-wallet views of the shared wallet: a client of [`MockYcashd::wallet_client`]
    /// `name` signs set and act signatures with these member keys only (several attestors'
    /// nodes simulated by one mock; a name with no view sees every wallet key).
    pub wallet_views: HashMap<String, BTreeSet<PubKey>>,
    /// The wallet the current call came through (`/wallet/<name>`), if any.
    current_wallet: Option<String>,
    pub calls: Vec<Call>,
    canned: HashMap<String, VecDeque<Reply>>,
    http_failures: VecDeque<u16>,
    pending: HashMap<Txid, PendingAct>,
    cancels: HashMap<OutPoint, Vec<u8>>,
    /// `vault_buildunlock`'s remembered builds: `(wallet, vault)` → (the requested outputs, the
    /// build).
    builds: HashMap<BuildKey, (Vec<TxOut>, Vec<u8>)>,
    counter: u64,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b))
}

fn p2pkh(h: &[u8]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&h[..20]);
    s.extend([0x88, 0xac]);
    s
}

/// `ceil(usd_micro × COIN / price)` bounded below by `floor` (ycash-dd `AttestedRateZatPerKB`).
fn attested_rate(usd_micro: i64, price_micro_usd: i64, floor: i64) -> i64 {
    let r = (i128::from(usd_micro) * 100_000_000 + i128::from(price_micro_usd) - 1)
        / i128::from(price_micro_usd);
    i64::try_from(r).unwrap_or(i64::MAX).max(floor.max(0))
}

/// The fee `vault_ownerspend` charges an owner spend of `size` bytes (ycash-dd `src/rpc/vault.cpp`,
/// `src/policy/policy.cpp`, rpcversion 8; quantum plan D-Q-23 (b)): `max(FEE, rate × size / 1000)`
/// (`CFeeRate::GetFee`), the rate `pq_fee_rate` without a price, else $0.05/KB at the price with
/// the floor `max(5,000, pq_fee_rate)`; capped at `min(max(-maxtxfee, $2 at the price), 10 YEC)`.
pub fn owner_spend_fee(pq_fee_rate: i64, price_micro_usd: Option<i64>, size: i64) -> i64 {
    let (rate, cap) = match price_micro_usd.filter(|p| *p > 0) {
        None => (pq_fee_rate, MAX_TX_FEE.min(YED_MAX_TX_FEE_CEILING)),
        Some(p) => (
            attested_rate(
                YED_FEE_USD_PER_KB_MICRO,
                p,
                ATTESTED_FEE_FLOOR_PER_KB.max(pq_fee_rate),
            ),
            MAX_TX_FEE
                .max(attested_rate(YED_MAX_TX_FEE_USD_MICRO, p, 0))
                .min(YED_MAX_TX_FEE_CEILING),
        ),
    };
    let mut sized = rate.saturating_mul(size) / 1000;
    if sized == 0 && rate > 0 {
        sized = rate;
    }
    FEE.max(sized).min(cap)
}

/// The node's `TX_PQPKH` script (`GetScriptForPQKey`, ycash-dd `src/script/standard.cpp:338` at
/// `d41026209`): `20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG`, the scheme as a script number.
fn pqpkh(h: &[u8; 32], scheme: u8) -> Vec<u8> {
    let mut s = vec![32];
    s.extend_from_slice(h);
    s.extend([OP_1 + scheme - 1, OP_CHECKPQSIG]);
    s
}

/// `OP_CHECKPQSIG` (quantum spec §0).
const OP_CHECKPQSIG: u8 = 0xc2;

fn err<T>(code: i64, msg: impl Into<String>) -> Result<T, (i64, String)> {
    Err((code, msg.into()))
}

fn to_json<T: serde::Serialize>(t: &T) -> RpcResult {
    serde_json::to_value(t).map_err(|e| (-32603, e.to_string()))
}

fn arg<T: DeserializeOwned>(p: &[Value], i: usize, name: &str) -> Result<T, (i64, String)> {
    match p.get(i) {
        None | Some(Value::Null) => err(-1, format!("missing parameter {name}")),
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| (-8, format!("{name}: {e}"))),
    }
}

fn opt_arg<T: DeserializeOwned>(
    p: &[Value],
    i: usize,
    name: &str,
) -> Result<Option<T>, (i64, String)> {
    match p.get(i) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => arg(p, i, name).map(Some),
    }
}

/// The placeholder V script of `f`.
pub fn mock_vault_script(f: &VaultFields) -> Vec<u8> {
    let mut s = vec![0x05, b'M', b'O', b'C', b'K', b'V', 0x20];
    s.extend(sha256(&serde_json::to_vec(f).expect("fields serialize")));
    s
}

/// The placeholder I script of `f`.
pub fn mock_intent_script(f: &IntentFields) -> Vec<u8> {
    let mut s = vec![0x05, b'M', b'O', b'C', b'K', b'I', 0x20];
    s.extend(sha256(&serde_json::to_vec(f).expect("fields serialize")));
    s
}

/// The shape of a post-quantum owner scriptSig (quantum spec §1.5): 15 chunks of 520 bytes and
/// one of 57 (the 7,856-byte SLH-DSA signature and its hashtype), `OP_16`, the 32-byte key,
/// `OP_1`, then the selector; the bytes are placeholders derived from the owner.
pub fn mock_pq_owner_script_sig(owner: &PqKeyId, selector: u8) -> Vec<u8> {
    let mut ss = Vec::with_capacity(PQ_OWNER_SCRIPTSIG_LEN);
    for i in 0..16 {
        let n: u16 = if i < 15 { 520 } else { 57 };
        if n > 75 {
            ss.push(0x4d);
            ss.extend(n.to_le_bytes());
        } else {
            ss.push(n as u8);
        }
        ss.extend(std::iter::repeat_n(owner.0[1], usize::from(n)));
    }
    ss.push(OP_1 + 15);
    ss.push(32);
    ss.extend(owner.hash());
    ss.push(OP_1);
    ss.push(OP_1 + selector - 1);
    ss
}

/// A mock set signature by `key` over `sighash`.
/// The bond redeem script `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <memberKey> OP_CHECKSIG`.
pub fn mock_bond_redeem(member: &PubKey, locktime: u32) -> Vec<u8> {
    // a minimal CScriptNum push of the locktime
    let mut n = Vec::new();
    let mut v = u64::from(locktime);
    while v > 0 {
        n.push((v & 0xff) as u8);
        v >>= 8;
    }
    if n.last().is_some_and(|b| b & 0x80 != 0) {
        n.push(0);
    }
    let mut s = Vec::new();
    match locktime {
        0 => s.push(0x00),
        1..=16 => s.push(0x50 + locktime as u8),
        _ => {
            s.push(n.len() as u8);
            s.extend(&n);
        }
    }
    s.extend([0xb1, 0x75, 33]);
    s.extend(member.0);
    s.push(0xac);
    s
}

/// The bond's P2SH scriptPubKey (`OP_HASH160 <HASH160(redeem)> OP_EQUAL`).
pub fn mock_bond_spk(member: &PubKey, locktime: u32) -> Vec<u8> {
    use ripemd::Ripemd160;
    let h = Ripemd160::digest(sha256(&mock_bond_redeem(member, locktime)));
    let mut s = vec![0xa9, 20];
    s.extend(h);
    s.push(0x87);
    s
}

pub fn mock_set_sig(key: &PubKey, sighash: &Bytes32) -> Vec<u8> {
    let mut s = vec![0x1f];
    s.extend(key.0);
    s.extend(&sighash.0[..31]);
    s
}

fn sig_key(sig: &[u8]) -> Option<PubKey> {
    (sig.len() == 65).then(|| PubKey(sig[1..34].try_into().expect("33 bytes")))
}

/// The pushes and the final selector of a template scriptSig.
fn parse_scriptsig(s: &[u8]) -> Option<(Vec<Vec<u8>>, u8)> {
    let (&sel, body) = s.split_last()?;
    if !(OP_1..=OP_1 + 3).contains(&sel) {
        return None;
    }
    let mut sigs = vec![];
    let mut rest = body;
    while let Some((&n, r)) = rest.split_first() {
        let n = n as usize;
        if n == 0 || n > 0x4b || r.len() < n {
            return None;
        }
        sigs.push(r[..n].to_vec());
        rest = &r[n..];
    }
    Some((sigs, sel - OP_1 + 1))
}

fn tag_bytes(tag: &str) -> Result<Vec<u8>, (i64, String)> {
    if tag.len() == 8
        && let Ok(b) = hex::decode(tag)
    {
        return Ok(b);
    }
    if tag.is_empty() || tag.len() > 4 || !tag.is_ascii() {
        return err(
            -8,
            "tag must be 1-4 ASCII characters (zero-padded) or 8 hex digits",
        );
    }
    let mut b = tag.as_bytes().to_vec();
    b.resize(4, 0);
    Ok(b)
}

fn tag_text(tag: &[u8]) -> String {
    String::from_utf8_lossy(tag)
        .trim_end_matches('\0')
        .to_owned()
}

/// A remembered build's key: the wallet (`/wallet/<name>`, if any) and the vault.
type BuildKey = (Option<String>, OutPoint);

impl Default for MockState {
    fn default() -> Self {
        Self::new()
    }
}

impl MockState {
    /// A regtest chain at height 0 (a genesis block), the upgrade active from height 1.
    pub fn new() -> Self {
        let mut s = MockState {
            chain: "regtest".into(),
            activation_height: 1,
            pre_vault_branch_id: "76b809bb".into(),
            blocks: vec![],
            mempool: vec![],
            txs: HashMap::new(),
            sets: BTreeMap::new(),
            bonds: BTreeMap::new(),
            min_set_maturity: REGTEST_MIN_SET_MATURITY,
            templates: BTreeMap::new(),
            scripts: HashMap::new(),
            wallet_keys: BTreeSet::new(),
            wallet_owners: BTreeSet::new(),
            pq_fee_rate: PQ_FEE_RATE,
            fee_price_micro_usd: None,
            addresses: BTreeMap::new(),
            unspent: vec![],
            sign_once: HashMap::new(),
            view_sign_once: HashMap::new(),
            restored: false,
            recipients: HashMap::new(),
            auth: None,
            wallet_views: HashMap::new(),
            current_wallet: None,
            calls: vec![],
            canned: HashMap::new(),
            http_failures: VecDeque::new(),
            pending: HashMap::new(),
            cancels: HashMap::new(),
            builds: HashMap::new(),
            counter: 0,
        };
        s.mine_block();
        s
    }

    // ------------------------------------------------------------------ scripting

    /// Answer the next call of `method` with `result` (a JSON value; amounts may be strings).
    pub fn queue_result(&mut self, method: &str, result: Value) {
        self.canned
            .entry(method.into())
            .or_default()
            .push_back(Reply::Result(result));
    }

    /// Answer the next call of `method` with a result given as node JSON text.
    pub fn queue_result_text(&mut self, method: &str, text: &str) {
        let v = crate::json::to_value(text).expect("valid JSON");
        self.queue_result(method, v);
    }

    /// Answer the next call of `method` with an RPC error.
    pub fn inject_error(&mut self, method: &str, code: i64, message: &str) {
        self.canned
            .entry(method.into())
            .or_default()
            .push_back(Reply::Error {
                code,
                message: message.into(),
            });
    }

    /// Answer the next HTTP request with `status` and no JSON-RPC body.
    pub fn fail_http(&mut self, status: u16) {
        self.http_failures.push_back(status);
    }

    /// The recorded calls of `method`.
    pub fn calls_to(&self, method: &str) -> Vec<&Call> {
        self.calls.iter().filter(|c| c.method == method).collect()
    }

    // ------------------------------------------------------------------ chain

    pub fn tip_height(&self) -> u32 {
        self.blocks.len() as u32 - 1
    }

    pub fn next_height(&self) -> u32 {
        self.blocks.len() as u32
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.blocks.last().expect("genesis").hash
    }

    fn active_next(&self) -> bool {
        self.activation_height >= 0 && i64::from(self.next_height()) >= self.activation_height
    }

    fn fresh(&mut self, what: &str) -> [u8; 32] {
        self.counter += 1;
        sha256(format!("{what}/{}", self.counter).as_bytes())
    }

    /// `n` confirmed P2PKH wallet coins of `amount` zatoshi each (fee capacity, `listunspent`).
    pub fn add_wallet_coins(&mut self, n: usize, amount: i64) {
        for _ in 0..n {
            let prev = Hash256(self.fresh("walletcoin"));
            let a = format!("tmMock{}", hex::encode(&prev.0[..10]));
            let spk = p2pkh(&sha256(&prev.0));
            self.addresses.insert(a.clone(), spk.clone());
            self.unspent.push(Unspent {
                txid: prev,
                vout: 0,
                generated: false,
                address: Some(a),
                account: None,
                redeem_script: None,
                script_pub_key: HexBytes(spk),
                amount: Amount(amount),
                amount_zat: amount,
                confirmations: 6,
                spendable: true,
            });
        }
    }

    /// A new key in the wallet.
    pub fn new_wallet_key(&mut self) -> PubKey {
        let mut k = [2u8; 33];
        k[1..].copy_from_slice(&self.fresh("key"));
        let k = PubKey(k);
        self.wallet_keys.insert(k);
        k
    }

    /// A new SLH-DSA owner key in the wallet (`vault_getnewowner`).
    pub fn new_wallet_owner(&mut self) -> PqKeyId {
        let mut k = [1u8; 33];
        k[1..].copy_from_slice(&self.fresh("pqowner"));
        let k = PqKeyId(k);
        self.wallet_owners.insert(k);
        k
    }

    /// The mock PQ address of `owner` (the node's is base58check, 53 characters).
    pub fn pq_address(owner: &PqKeyId) -> String {
        format!("yrMock{owner}")
    }

    /// A new wallet address (a mock P2PKH).
    pub fn new_address(&mut self) -> String {
        let h = self.fresh("addr");
        let a = format!("tmMock{}", hex::encode(&h[..10]));
        self.addresses.insert(a.clone(), p2pkh(&h));
        a
    }

    /// A new plain-YEC post-quantum address of the wallet (`getnewaddress "" "pq"`, quantum
    /// plan D-Q-20): the node's is base58check `rq…` (53 characters) and pays the `TX_PQPKH`
    /// script `20 <keyHash> OP_1 OP_CHECKPQSIG`; the mock's is `rqMock<hex>` over the same
    /// 35-byte script (scheme 1), which `validateaddress` and `vault_release` resolve.
    pub fn new_pq_address(&mut self) -> String {
        let h = self.fresh("pqaddr");
        let a = format!("rqMock{}", hex::encode(&h[..10]));
        self.addresses.insert(a.clone(), pqpkh(&h, 1));
        a
    }

    fn address_script(&self, a: &str) -> Option<Vec<u8>> {
        if let Some(s) = self.addresses.get(a) {
            return Some(s.clone());
        }
        (!a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric()))
            .then(|| p2pkh(&sha256(a.as_bytes())))
    }

    /// Mine `n` blocks: each confirms the whole mempool (in order) and applies its effects.
    pub fn mine(&mut self, n: u32) -> Vec<BlockHash> {
        (0..n).map(|_| self.mine_block()).collect()
    }

    fn mine_block(&mut self) -> BlockHash {
        let height = self.next_height();
        let prev = self.blocks.last().map(|b| b.hash).unwrap_or_default();
        let mut pre = prev.0.to_vec();
        pre.extend(height.to_le_bytes());
        pre.extend(self.fresh("block"));
        let hash = Hash256(sha256d(&pre));
        // coinbase
        let mut h = vec![3];
        h.extend(&height.to_le_bytes()[..3]);
        let cb = Transaction::new_v4(
            vec![TxIn {
                prevout: OutPoint::new(Hash256::default(), u32::MAX),
                script_sig: h,
                sequence: u32::MAX,
            }],
            vec![TxOut {
                value: 625_000_000,
                script_pubkey: p2pkh(&sha256(b"miner")),
            }],
            0,
            height,
        );
        let cbid = cb.txid();
        self.txs.insert(cbid, (cb.encode(), Some(hash)));
        let mut txids = vec![cbid];
        let mempool = std::mem::take(&mut self.mempool);
        for txid in mempool {
            if let Some(e) = self.txs.get_mut(&txid) {
                e.1 = Some(hash);
                let raw = e.0.clone();
                self.apply(txid, &raw, height);
                txids.push(txid);
            }
        }
        self.blocks.push(MockBlock {
            hash,
            height,
            time: 1_700_000_000 + i64::from(height) * 75,
            txids,
        });
        self.roll_epochs(height);
        hash
    }

    fn roll_epochs(&mut self, height: u32) {
        for s in self.sets.values_mut() {
            let set = &mut s.set;
            if let Some(epoch) = height.checked_div(set.params.ratewindow) {
                let epoch = i64::from(epoch);
                if epoch != set.epoch {
                    set.epoch = epoch;
                    set.epochbasis = set.lockedvalue;
                    set.epochused = Amount::ZERO;
                }
            }
        }
    }

    fn set_mut(&mut self, id: &SetId) -> Option<&mut Set> {
        self.sets.get_mut(id).map(|s| &mut s.set)
    }

    fn apply(&mut self, txid: Txid, raw: &[u8], height: u32) {
        let Ok(tx) = Transaction::decode(raw) else {
            return;
        };
        let mut unlocked_from: Option<SetId> = None;
        for i in &tx.inputs {
            if let Some(t) = self.templates.remove(&i.prevout)
                && let TemplateOut::Vault(v) = t
            {
                let sel = parse_scriptsig(&i.script_sig).map(|x| x.1);
                if sel == Some(1) || sel == Some(4) {
                    unlocked_from = Some(v.fields.setid);
                }
                if let Some(set) = self.set_mut(&v.fields.setid) {
                    set.lockedvalue = Amount(set.lockedvalue.0.saturating_sub(v.valuezat).max(0));
                }
            }
            self.unspent
                .retain(|u| OutPoint::new(u.txid, u.vout) != i.prevout);
            if let Some(b) = self.bonds.remove(&i.prevout) {
                let op = i.prevout;
                self.with_member(&b.setid, &b.member, |m| {
                    if m.status == MemberStatus::Active && m.bondoutpoint == op {
                        m.status = MemberStatus::Withdrawn;
                    }
                });
            }
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            let op = OutPoint::new(txid, n as u32);
            match self.scripts.get(&o.script_pubkey).cloned() {
                Some(KnownScript::Vault(fields)) => {
                    if let Some(set) = self.set_mut(&fields.setid) {
                        set.lockedvalue = Amount(set.lockedvalue.0 + o.value);
                    }
                    let wallet = self.wallet_owners.contains(&fields.owner);
                    self.templates.insert(
                        op,
                        TemplateOut::Vault(VaultOut {
                            txid,
                            vout: n as u32,
                            outpoint: op,
                            value: Amount(o.value),
                            valuezat: o.value,
                            height,
                            script: HexBytes(o.script_pubkey.clone()),
                            fields,
                            wallet,
                        }),
                    );
                }
                Some(KnownScript::Intent { fields, origin }) => {
                    if let Some(sid) = unlocked_from
                        && let Some(set) = self.set_mut(&sid)
                    {
                        set.epochused = Amount(set.epochused.0 + o.value);
                    }
                    let wallet = self.wallet_owners.contains(&fields.owner);
                    self.templates.insert(
                        op,
                        TemplateOut::Intent(IntentOutput {
                            txid,
                            vout: n as u32,
                            outpoint: op,
                            value: Amount(o.value),
                            valuezat: o.value,
                            height,
                            script: HexBytes(o.script_pubkey.clone()),
                            matureheight: height + fields.delay,
                            fields,
                            mature: false,
                            cancellable: true,
                            origin: HexBytes(origin),
                            wallet,
                        }),
                    );
                }
                None => {}
            }
        }
        if let Some(act) = self.pending.remove(&txid) {
            self.apply_act(txid, act, height);
        }
    }

    fn apply_act(&mut self, txid: Txid, act: PendingAct, height: u32) {
        match act {
            PendingAct::Create(params) => {
                let set = Set {
                    setid: txid,
                    height,
                    params,
                    createheight: height,
                    winddownheight: 0,
                    lockedvalue: Amount::ZERO,
                    epoch: 0,
                    epochbasis: Amount::ZERO,
                    epochused: Amount::ZERO,
                    unlockavailable: None,
                    members: 0,
                    active: 0,
                    current: 0,
                    dormant: false,
                    released: false,
                };
                self.sets.insert(
                    txid,
                    SetInfo {
                        set,
                        memberlist: vec![],
                    },
                );
            }
            PendingAct::Join {
                setid,
                member,
                bond,
                locktime,
                bondoutpoint,
            } => {
                self.add_member_at(&setid, member, bond, locktime, bondoutpoint, height);
            }
            PendingAct::Heartbeat { setid, member } => {
                self.with_member(&setid, &member, |m| m.lastact = height)
            }
            PendingAct::Remove {
                setid,
                member,
                burn,
            } => {
                let Some(m) = self.member_of(&setid, &member) else {
                    return;
                };
                let bond = self.bonds.get(&m.bondoutpoint).cloned();
                if m.status == MemberStatus::Active {
                    self.with_member(&setid, &member, |m| {
                        m.status = MemberStatus::Removed;
                        m.bondfrozen = burn;
                    });
                    if let Some(b) = self.bonds.get_mut(&m.bondoutpoint) {
                        if burn {
                            b.frozen = true;
                        } else {
                            b.exitheight = height; // the bond exit delay starts
                        }
                    }
                } else if m.status == MemberStatus::Removed
                    && burn
                    && bond.is_some_and(|b| !b.frozen && b.exitheight != 0)
                {
                    // a slash after the exit (review A1): the bond in its exit delay is frozen
                    self.with_member(&setid, &member, |m| m.bondfrozen = true);
                    if let Some(b) = self.bonds.get_mut(&m.bondoutpoint) {
                        b.frozen = true;
                    }
                }
            }
            PendingAct::Leave { setid, member } => {
                let Some(m) = self.member_of(&setid, &member) else {
                    return;
                };
                if m.status != MemberStatus::Active {
                    return;
                }
                self.with_member(&setid, &member, |m| m.status = MemberStatus::Removed);
                if let Some(b) = self.bonds.get_mut(&m.bondoutpoint) {
                    b.exitheight = height;
                }
            }
            PendingAct::Equivocation { setid, member } => {
                self.with_member(&setid, &member, |m| {
                    m.status = MemberStatus::Ejected;
                    m.bondfrozen = true;
                });
                if let Some(m) = self.member_of(&setid, &member)
                    && let Some(b) = self.bonds.get_mut(&m.bondoutpoint)
                {
                    b.frozen = true;
                }
            }
            PendingAct::Winddown { setid } => {
                if let Some(s) = self.set_mut(&setid) {
                    s.winddownheight = height;
                }
            }
        }
    }

    fn member_of(&self, setid: &SetId, key: &PubKey) -> Option<Member> {
        self.sets
            .get(setid)
            .and_then(|s| s.memberlist.iter().find(|m| &m.key == key).cloned())
    }

    /// `bad-vault-act-join` for a key that is an ACTIVE member or still has an unspent bond in
    /// the set (one unspent bond per (set, key), review B1).
    fn join_refusal(&self, setid: &SetId, key: &PubKey) -> Option<(i64, String)> {
        let m = self.member_of(setid, key)?;
        (m.status == MemberStatus::Active || self.bonds.contains_key(&m.bondoutpoint))
            .then(|| (-26, "16: bad-vault-act-join".to_owned()))
    }

    /// `bad-vault-act-remove` unless `key` is ACTIVE, or REMOVED with its bond in the exit
    /// delay and the removal burns (a slash after the exit, review A1).
    fn remove_refusal(&self, setid: &SetId, key: &PubKey, burn: bool) -> Option<(i64, String)> {
        let ok = self.member_of(setid, key).is_some_and(|m| {
            m.status == MemberStatus::Active
                || (m.status == MemberStatus::Removed
                    && burn
                    && self
                        .bonds
                        .get(&m.bondoutpoint)
                        .is_some_and(|b| !b.frozen && b.exitheight != 0))
        });
        (!ok).then(|| (-26, "16: bad-vault-act-remove".to_owned()))
    }

    /// The bond rules of a spend at the next block: frozen, the exit delay, the CLTV.
    fn bond_refusal(&self, tx: &Transaction) -> Option<(i64, String)> {
        let next = self.next_height();
        for (n, i) in tx.inputs.iter().enumerate() {
            let Some(b) = self.bonds.get(&i.prevout) else {
                continue;
            };
            if b.frozen {
                return Some((-26, "16: bad-vault-bond-frozen".into()));
            }
            let maturity = self.set(&b.setid).map_or(0, |s| s.set.params.maturity);
            if b.exitheight == 0 || next < b.exitheight + maturity {
                return Some((-26, "16: bad-vault-bond-locked".into()));
            }
            if tx.lock_time < b.locktime || tx.inputs[n].sequence == u32::MAX {
                return Some((
                    -26,
                    "16: mandatory-script-verify-flag-failed (Locktime requirement not satisfied)"
                        .into(),
                ));
            }
            if tx.lock_time >= next {
                return Some((-26, "64: non-final".into()));
            }
        }
        None
    }

    fn with_member(&mut self, setid: &SetId, key: &PubKey, f: impl FnOnce(&mut Member)) {
        if let Some(m) = self
            .sets
            .get_mut(setid)
            .and_then(|s| s.memberlist.iter_mut().find(|m| &m.key == key))
        {
            f(m);
        }
    }

    // ------------------------------------------------------------------ direct setup

    /// Create a confirmed set directly (no transaction). Returns its id.
    pub fn add_set(&mut self, params: SetParams) -> SetId {
        let id = Hash256(self.fresh("set"));
        let h = self.tip_height();
        self.apply_act(id, PendingAct::Create(params), h);
        id
    }

    /// Add a current member directly; `in_wallet` puts its key in the mock wallet.
    pub fn add_member(&mut self, setid: &SetId, key: PubKey, in_wallet: bool) {
        if in_wallet {
            self.wallet_keys.insert(key);
        }
        let bond = OutPoint::new(Hash256(self.fresh("bond")), 0);
        let h = self.tip_height();
        let bondmin = self
            .sets
            .get(setid)
            .map_or(Amount(COIN), |s| s.set.params.bondmin);
        self.add_member_at(setid, key, bondmin, h + 1000, bond, h);
    }

    /// Mark `key`'s bond as left at `height` (its exit delay starts), as `set_leave` would, and
    /// make it REMOVED: for tests that start from a member already in its exit delay.
    pub fn leave_member(&mut self, setid: &SetId, key: &PubKey, height: u32) {
        self.apply_act(
            Hash256::default(),
            PendingAct::Leave {
                setid: *setid,
                member: *key,
            },
            height,
        );
    }

    fn add_member_at(
        &mut self,
        setid: &SetId,
        key: PubKey,
        bond: Amount,
        locktime: u32,
        bondoutpoint: OutPoint,
        h: u32,
    ) {
        let Some(s) = self.sets.get_mut(setid) else {
            return;
        };
        s.memberlist.retain(|m| m.key != key);
        self.bonds.insert(
            bondoutpoint,
            MockBond {
                setid: *setid,
                member: key,
                value: bond,
                locktime,
                frozen: false,
                exitheight: 0,
            },
        );
        let Some(s) = self.sets.get_mut(setid) else {
            return;
        };
        s.memberlist.push(Member {
            key,
            status: MemberStatus::Active,
            current: true,
            live: true,
            joinheight: h,
            lastact: h,
            bondoutpoint,
            bondvalue: bond,
            bondlocktime: locktime,
            bondfrozen: false,
            exitheight: None,
            unlockheight: None,
            wallet: false,
        });
    }

    /// Register a template script (e.g. a real §15.3 V or I built by hawkeye-core) so that the
    /// outputs paying to it enter the index when mined.
    pub fn register_script(&mut self, script: Vec<u8>, known: KnownScript) {
        self.scripts.insert(script, known);
    }

    /// A confirmed vault output directly in the index (at the tip). Returns its outpoint.
    pub fn add_vault(&mut self, fields: VaultFields, value: Amount) -> OutPoint {
        let script = mock_vault_script(&fields);
        self.add_vault_with_script(fields, value, script)
    }

    pub fn add_vault_with_script(
        &mut self,
        fields: VaultFields,
        value: Amount,
        script: Vec<u8>,
    ) -> OutPoint {
        self.register_script(script.clone(), KnownScript::Vault(fields));
        self.add_confirmed_output(value, script)
    }

    /// A confirmed intent output directly in the index (at the tip).
    pub fn add_intent(&mut self, fields: IntentFields, value: Amount, origin: Vec<u8>) -> OutPoint {
        let script = mock_intent_script(&fields);
        self.register_script(script.clone(), KnownScript::Intent { fields, origin });
        self.add_confirmed_output(value, script)
    }

    fn add_confirmed_output(&mut self, value: Amount, script: Vec<u8>) -> OutPoint {
        let mut tx = Transaction::new_v4(
            vec![],
            vec![TxOut {
                value: value.0,
                script_pubkey: script,
            }],
            0,
            0,
        );
        self.fund(&mut tx, 0);
        self.sign_wallet_inputs(&mut tx);
        let txid = tx.txid();
        let raw = tx.encode();
        let h = self.tip_height();
        let tip = self.tip_hash();
        self.txs.insert(txid, (raw.clone(), Some(tip)));
        self.blocks.last_mut().expect("genesis").txids.push(txid);
        self.apply(txid, &raw, h);
        OutPoint::new(txid, 0)
    }

    /// Put a transaction into the mempool (the double-spend and duplicate checks of
    /// `sendrawtransaction` apply).
    pub fn submit(&mut self, raw: Vec<u8>) -> Result<Txid, (i64, String)> {
        let tx = Transaction::decode(&raw).map_err(|_| (-22, "TX decode failed".to_owned()))?;
        let txid = tx.txid();
        match self.txs.get(&txid) {
            Some((_, Some(_))) => return err(-27, "transaction already in block chain"),
            Some((_, None)) if self.mempool.contains(&txid) => {
                return err(-26, "18: txn-already-in-mempool");
            }
            _ => {}
        }
        for i in &tx.inputs {
            let conflict = self.mempool.iter().any(|m| {
                self.txs
                    .get(m)
                    .and_then(|(r, _)| Transaction::decode(r).ok())
                    .is_some_and(|t| t.inputs.iter().any(|j| j.prevout == i.prevout))
            });
            if conflict {
                return err(-26, "18: txn-mempool-conflict");
            }
            if self.spent_on_chain(&i.prevout) {
                return err(-25, "Missing inputs");
            }
            if self.spent_in_block(&i.prevout) {
                // what both node lines answer for a spent output of a known transaction
                return err(-26, "18: bad-txns-inputs-spent");
            }
        }
        if let Some(e) = self.bond_refusal(&tx) {
            return Err(e);
        }
        self.txs.insert(txid, (raw, None));
        self.mempool.push(txid);
        Ok(txid)
    }

    /// Any outpoint (a fee coin too) spent by a mined transaction.
    fn spent_in_block(&self, op: &OutPoint) -> bool {
        self.txs.values().any(|(r, b)| {
            b.is_some()
                && Transaction::decode(r).is_ok_and(|t| t.inputs.iter().any(|i| i.prevout == *op))
        })
    }

    fn spent_on_chain(&self, op: &OutPoint) -> bool {
        // a template outpoint that was created and is no longer in the index was spent
        let created = self.txs.get(&op.txid).is_some_and(|(r, b)| {
            b.is_some()
                && Transaction::decode(r)
                    .ok()
                    .and_then(|t| {
                        t.outputs
                            .get(op.vout as usize)
                            .map(|o| self.scripts.contains_key(&o.script_pubkey))
                    })
                    .unwrap_or(false)
        });
        created && !self.templates.contains_key(op)
    }

    // ------------------------------------------------------------------ building

    /// Add a mock wallet coin covering `outputs + FEE - input_value`, and change.
    fn fund(&mut self, tx: &mut Transaction, input_value: i64) {
        let out: i64 = tx.outputs.iter().map(|o| o.value).sum();
        let needed = out + FEE - input_value;
        if needed <= 0 {
            return;
        }
        let coin = needed + COIN;
        let prev = Hash256(self.fresh("coin"));
        // the coin is a confirmed wallet P2PKH output (gettxout, validateaddress see it)
        let a = format!("tmMock{}", hex::encode(&prev.0[..10]));
        let spk = p2pkh(&sha256(&prev.0));
        self.addresses.insert(a.clone(), spk.clone());
        self.unspent.push(Unspent {
            txid: prev,
            vout: 0,
            generated: false,
            address: Some(a),
            account: None,
            redeem_script: None,
            script_pub_key: HexBytes(spk),
            amount: Amount(coin),
            amount_zat: coin,
            confirmations: 6,
            spendable: true,
        });
        tx.inputs.push(TxIn {
            prevout: OutPoint::new(prev, 0),
            script_sig: vec![],
            sequence: u32::MAX,
        });
        let change = p2pkh(&self.fresh("change"));
        tx.outputs.push(TxOut {
            value: coin - needed,
            script_pubkey: change,
        });
    }

    fn sign_wallet_inputs(&self, tx: &mut Transaction) {
        for i in tx.inputs.iter_mut() {
            if i.script_sig.is_empty() && self.template(&i.prevout).is_none() {
                let mut s = vec![0x47];
                s.extend([0x30; 71]);
                s.push(0x21);
                s.extend([0x02; 33]);
                i.script_sig = s;
            }
        }
    }

    /// A template output: confirmed (index) or created by a mempool transaction.
    /// Returns `(fields, value, height or None for the mempool)`.
    fn template(&self, op: &OutPoint) -> Option<(KnownScript, i64, Option<u32>)> {
        if let Some(t) = self.templates.get(op) {
            let k = match t {
                TemplateOut::Vault(v) => KnownScript::Vault(v.fields.clone()),
                TemplateOut::Intent(i) => KnownScript::Intent {
                    fields: i.fields.clone(),
                    origin: i.origin.0.clone(),
                },
            };
            return Some((k, t.valuezat(), Some(t.height())));
        }
        if !self.mempool.contains(&op.txid) {
            return None;
        }
        let (raw, _) = self.txs.get(&op.txid)?;
        let tx = Transaction::decode(raw).ok()?;
        let o = tx.outputs.get(op.vout as usize)?;
        self.scripts
            .get(&o.script_pubkey)
            .map(|k| (k.clone(), o.value, None))
    }

    /// The mock set-signature sighash of template input `idx`: the transaction reduced to that
    /// input (scriptSig cleared) and every output — what `SIGHASH_ALL|SIGHASH_ANYONECANPAY`
    /// commits to (01/V-2), so replacing the fee inputs keeps it.
    pub fn mock_sighash(tx: &Transaction, idx: usize) -> Bytes32 {
        let mut t = tx.clone();
        t.inputs = vec![TxIn {
            script_sig: vec![],
            ..tx.inputs[idx].clone()
        }];
        Bytes32(sha256d(&t.encode()))
    }

    fn act_tx(&mut self, payload: Vec<u8>, extra: Vec<TxOut>) -> Transaction {
        let mut outs = extra;
        outs.push(TxOut::op_return(&payload));
        let mut tx = Transaction::new_v4(vec![], outs, 0, 0);
        self.fund(&mut tx, 0);
        tx
    }

    // ------------------------------------------------------------------ dispatch

    fn ensure_active(&self) -> Result<(), (i64, String)> {
        if self.active_next() {
            Ok(())
        } else {
            err(
                -1,
                format!(
                    "the vault upgrade is not active at the next block (height {})",
                    self.next_height()
                ),
            )
        }
    }

    fn set(&self, id: &SetId) -> Option<&SetInfo> {
        self.sets.get(id)
    }

    /// A set's predicates and counts at `h`.
    fn set_view(&self, s: &SetInfo, h: u32) -> SetInfo {
        let mut s = s.clone();
        let lw = s.set.params.livenesswindow;
        let since = h.saturating_sub(lw);
        for m in s.memberlist.iter_mut() {
            m.current = m.status == MemberStatus::Active;
            m.live = m.current && m.lastact >= since;
            m.wallet = self.wallet_keys.contains(&m.key);
        }
        let set = &mut s.set;
        set.height = h;
        set.members = s.memberlist.len() as u32;
        set.active = s
            .memberlist
            .iter()
            .filter(|m| m.status == MemberStatus::Active)
            .count() as u32;
        set.current = s.memberlist.iter().filter(|m| m.current).count() as u32;
        let any_live = s.memberlist.iter().any(|m| m.live);
        set.dormant = set.current > 0 && !any_live;
        set.released = set.dormant || (set.winddownheight != 0 && h >= set.winddownheight + lw);
        set.unlockavailable = (set.params.ratelimitbps != 0).then(|| {
            let cap = set.epochbasis.0 as i128 * i128::from(set.params.ratelimitbps) / 10_000;
            Amount((cap as i64 - set.epochused.0).max(0))
        });
        s
    }

    fn template_view(&self, t: &TemplateOut) -> TemplateOut {
        let next = self.next_height();
        let mut t = t.clone();
        match &mut t {
            TemplateOut::Vault(v) => v.wallet = self.wallet_owners.contains(&v.fields.owner),
            TemplateOut::Intent(i) => {
                i.matureheight = i.height + i.fields.delay;
                i.mature = next >= i.matureheight;
                i.cancellable = next - i.height < i.fields.delay;
                i.wallet = self.wallet_owners.contains(&i.fields.owner);
            }
        }
        t
    }

    fn dispatch(&mut self, method: &str, p: &[Value]) -> RpcResult {
        match method {
            // ---- vault read RPCs
            "vault_getinfo" => self.vault_getinfo(),
            "set_list" => {
                let h = self.next_height();
                let v: Vec<Set> = self
                    .sets
                    .values()
                    .map(|s| self.set_view(s, h).set)
                    .collect();
                to_json(&v)
            }
            "set_getinfo" => {
                let id: SetId = arg(p, 0, "setid")?;
                let h = opt_arg::<u32>(p, 1, "height")?.unwrap_or(self.next_height());
                match self.set(&id) {
                    Some(s) => to_json(&self.set_view(s, h)),
                    None => err(-5, format!("unknown set {id}")),
                }
            }
            "vault_list" => self.vault_list(p),
            "vault_decodescript" => {
                let h: HexBytes = arg(p, 0, "hex")?;
                let d = match self.scripts.get(&h.0) {
                    Some(KnownScript::Vault(f)) => DecodedScript::Vault(f.clone()),
                    Some(KnownScript::Intent { fields, .. }) => {
                        DecodedScript::Intent(fields.clone())
                    }
                    None => DecodedScript::None,
                };
                to_json(&d)
            }
            // ---- acts
            "set_create" => self.set_create(p),
            "set_join" => self.set_join(p),
            "set_heartbeat" => self.set_heartbeat(p),
            "set_leave" => self.set_leave(p),
            "set_buildact" => self.set_buildact(p),
            "set_signact" => self.set_signact(p),
            "set_sendact" => self.set_sendact(p),
            "set_equivocation" => self.set_equivocation(p),
            // ---- vaults
            "vault_lock" => self.vault_lock(p),
            "vault_getnewowner" => self.vault_getnewowner(p),
            "vault_buildunlock" => self.vault_build_spend(p, false),
            "vault_app" => self.vault_build_spend(p, true),
            "set_signunlock" => self.set_sign(p, 1),
            "set_signcancel" => self.set_sign(p, 2),
            "vault_buildcancel" => self.vault_buildcancel(p),
            "vault_send" => self.vault_send(p),
            "vault_refee" => self.vault_refee(p),
            "set_listsigned" => self.set_listsigned(),
            "set_importsigned" => self.set_importsigned(p),
            "set_acknowledgerestore" => {
                self.restored = false;
                to_json(&AckRestoreResult {
                    restored: false,
                    pendingkeys: 0,
                })
            }
            "vault_release" => self.vault_release(p),
            "vault_ownerspend" => self.vault_ownerspend(p),
            // ---- stock
            "getblockchaininfo" => self.getblockchaininfo(),
            "getblockcount" => Ok(self.tip_height().into()),
            "getbestblockhash" => to_json(&self.tip_hash()),
            "getblockhash" => {
                let h: u32 = arg(p, 0, "height")?;
                match self.blocks.get(h as usize) {
                    Some(b) => to_json(&b.hash),
                    None => err(-8, "Block height out of range"),
                }
            }
            "getblock" => self.getblock(p),
            "getrawtransaction" => self.getrawtransaction(p),
            "getrawmempool" => to_json(&self.mempool),
            "decoderawtransaction" => {
                let h: HexBytes = arg(p, 0, "hexstring")?;
                let tx =
                    Transaction::decode(&h.0).map_err(|_| (-22, "TX decode failed".to_owned()))?;
                Ok(self.tx_json(&tx, None))
            }
            "sendrawtransaction" => {
                let h: HexBytes = arg(p, 0, "hexstring")?;
                let txid = self.submit(h.0)?;
                to_json(&txid)
            }
            "signrawtransaction" => {
                let h: HexBytes = arg(p, 0, "hexstring")?;
                let mut tx =
                    Transaction::decode(&h.0).map_err(|_| (-22, "TX decode failed".to_owned()))?;
                self.sign_wallet_inputs(&mut tx);
                Ok(json!({"hex": tx.encode_hex(), "complete": true}))
            }
            "validateaddress" => {
                let a: String = arg(p, 0, "address")?;
                Ok(match self.address_script(&a) {
                    Some(spk) => {
                        json!({"isvalid": true, "address": a, "scriptPubKey": hex::encode(spk),
                                        "ismine": self.addresses.contains_key(&a), "iswatchonly": false, "isscript": false})
                    }
                    None => json!({"isvalid": false}),
                })
            }
            "getnewaddress" => {
                // `getnewaddress "" "pq"` files a plain-YEC PQ key (`rq…`, D-Q-20); any other
                // type (or none) is a transparent P2PKH address
                let kind: Option<String> = opt_arg(p, 1, "type")?;
                Ok(match kind.as_deref() {
                    Some("pq") => self.new_pq_address().into(),
                    _ => self.new_address().into(),
                })
            }
            "importprivkey" => {
                let wif: String = arg(p, 0, "privkey")?;
                let h = sha256(wif.as_bytes());
                let a = format!("tmMock{}", hex::encode(&h[..10]));
                self.addresses.insert(a.clone(), p2pkh(&h));
                let mut k = [3u8; 33];
                k[1..].copy_from_slice(&h);
                self.wallet_keys.insert(PubKey(k));
                Ok(a.into())
            }
            "listunspent" => {
                // confirmations from the chain for coins of known transactions (phantom
                // funding coins keep theirs); minconf / maxconf applied
                let minconf: i64 = opt_arg::<i64>(p, 0, "minconf")?.unwrap_or(1);
                let maxconf: i64 = opt_arg::<i64>(p, 1, "maxconf")?.unwrap_or(9_999_999);
                let tip = i64::from(self.tip_height());
                let rows: Vec<Unspent> = self
                    .unspent
                    .iter()
                    .cloned()
                    .map(|mut u| {
                        if let Some((_, b)) = self.txs.get(&u.txid) {
                            u.confirmations = b
                                .and_then(|b| self.blocks.iter().find(|x| x.hash == b))
                                .map_or(0, |x| tip - i64::from(x.height) + 1);
                        }
                        u
                    })
                    .filter(|u| u.confirmations >= minconf && u.confirmations <= maxconf)
                    .collect();
                to_json(&rows)
            }
            "sendmany" => self.sendmany(p),
            "gettxout" => self.gettxout(p),
            "generate" => {
                let n: u32 = arg(p, 0, "numblocks")?;
                to_json(&self.mine(n))
            }
            _ => err(-32601, "Method not found"),
        }
    }

    fn vault_getinfo(&self) -> RpcResult {
        let tip = self.tip_height();
        let active_tip = self.activation_height >= 0 && i64::from(tip) >= self.activation_height;
        let vaults = self
            .templates
            .values()
            .filter(|t| t.as_vault().is_some())
            .count() as u32;
        let locked: i64 = self
            .templates
            .values()
            .filter_map(|t| t.as_vault())
            .map(|v| v.valuezat)
            .sum();
        let mut state =
            serde_json::to_vec(&self.templates.values().collect::<Vec<_>>()).unwrap_or_default();
        state.extend(
            serde_json::to_vec(&self.sets.values().collect::<Vec<_>>()).unwrap_or_default(),
        );
        let info = VaultInfo {
            branchid: VAULT_BRANCH_ID.into(),
            activationheight: self.activation_height,
            active: self.active_next(),
            height: i64::from(tip),
            attestorsetid: None,
            moduleactive: false,
            dbtip: active_tip.then(|| DbTip {
                hash: self.tip_hash(),
                height: tip,
            }),
            sets: Some(self.sets.len() as u32),
            vaults: Some(vaults),
            intents: Some(self.templates.len() as u32 - vaults),
            lockedvalue: Some(Amount(locked)),
            statehash: Some(Hash256(sha256d(&state))),
        };
        to_json(&info)
    }

    fn vault_list(&self, p: &[Value]) -> RpcResult {
        let f: VaultListFilter = match p.first() {
            None | Some(Value::Null) => VaultListFilter::default(),
            Some(Value::Object(o)) => {
                if let Some(k) = o.get("kind")
                    && k != "vault"
                    && k != "intent"
                {
                    return err(-8, "kind must be vault or intent");
                }
                serde_json::from_value(Value::Object(o.clone())).map_err(|e| (-8, e.to_string()))?
            }
            Some(_) => return err(-3, "Expected type object"),
        };
        let tag = f.tag.as_deref().map(tag_bytes).transpose()?;
        let rows: Vec<TemplateOut> = self
            .templates
            .values()
            .filter(|t| {
                let (k, tg, s1, s2, owner) = match t {
                    TemplateOut::Vault(v) => (
                        TemplateKind::Vault,
                        &v.fields.tag,
                        v.fields.setid,
                        v.fields.cancelsetid,
                        v.fields.owner,
                    ),
                    TemplateOut::Intent(i) => (
                        TemplateKind::Intent,
                        &i.fields.tag,
                        i.fields.setid,
                        i.fields.cancelsetid,
                        i.fields.owner,
                    ),
                };
                f.kind.is_none_or(|x| x == k)
                    && tag.as_ref().is_none_or(|x| x == &tg.0)
                    && f.setid.is_none_or(|x| x == s1 || x == s2)
                    && f.owner.is_none_or(|x| x == owner)
                    && (f.mine != Some(true) || self.wallet_owners.contains(&owner))
            })
            .map(|t| self.template_view(t))
            .collect();
        to_json(&rows)
    }

    fn set_params_from(&mut self, o: &SetCreateParams) -> Result<SetParams, (i64, String)> {
        let p = SetParams {
            seats: o.seats,
            unlockthreshold: o.unlockthreshold,
            cancelthreshold: o.cancelthreshold.unwrap_or(1),
            slashthreshold: o.slashthreshold.unwrap_or(o.unlockthreshold),
            open: o.open.unwrap_or(false),
            ratelimitbps: o.ratelimitbps.unwrap_or(0),
            ratewindow: o.ratewindow.unwrap_or(144),
            livenesswindow: o.livenesswindow.unwrap_or(1000),
            bondmin: o.bondmin.unwrap_or(Amount(COIN)),
            bondlockmin: o.bondlockmin.unwrap_or(0),
            maturity: o.maturity.unwrap_or(self.min_set_maturity),
            admitkey: match o.admitkey {
                Some(k) => k,
                None => self.new_wallet_key(),
            },
        };
        let ok = (1..=15).contains(&p.seats)
            && (1..=p.seats).contains(&p.unlockthreshold)
            && (1..=p.seats).contains(&p.cancelthreshold)
            && (1..=p.seats).contains(&p.slashthreshold)
            && p.ratelimitbps <= 10_000;
        if p.maturity < self.min_set_maturity {
            return err(
                -8,
                format!(
                    "maturity must be at least {} blocks (D-Q-31)",
                    self.min_set_maturity
                ),
            );
        }
        if !ok {
            return err(
                -8,
                "the set parameters are out of range (plan §15.5 row 0x01)",
            );
        }
        Ok(p)
    }

    fn act_payload(
        ty: u8,
        required: i32,
        sigs: u8,
        burn: bool,
        setid: &SetId,
        key: &PubKey,
    ) -> Vec<u8> {
        let mut v = b"YV".to_vec();
        v.extend([ty, required as i8 as u8, sigs, u8::from(burn)]);
        v.extend(setid.0);
        v.extend(key.0);
        v
    }

    fn set_create(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let o: SetCreateParams = arg(p, 0, "params")?;
        let params = self.set_params_from(&o)?;
        let payload = Self::act_payload(1, 0, 0, false, &Hash256::default(), &params.admitkey);
        let mut tx = self.act_tx(payload, vec![]);
        self.sign_wallet_inputs(&mut tx);
        let admitkey = params.admitkey;
        let txid = self.submit(tx.encode())?;
        self.pending.insert(txid, PendingAct::Create(params));
        to_json(&SetCreateResult {
            txid,
            setid: txid,
            admitkey,
        })
    }

    fn wallet_member_keys(&self, setid: &SetId, except: Option<&PubKey>) -> Vec<PubKey> {
        let h = self.next_height();
        self.set(setid)
            .map(|s| self.set_view(s, h).memberlist)
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.current && self.wallet_keys.contains(&m.key) && Some(&m.key) != except)
            .filter(|m| self.in_view(&m.key))
            .map(|m| m.key)
            .collect()
    }

    /// Whether the current call's wallet view holds `key` (no view: every wallet key).
    fn in_view(&self, key: &PubKey) -> bool {
        match self
            .current_wallet
            .as_ref()
            .and_then(|w| self.wallet_views.get(w))
        {
            Some(v) => v.contains(key),
            None => true,
        }
    }

    fn set_join(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let setid: SetId = arg(p, 0, "setid")?;
        let bond: Amount = arg(p, 1, "bondamount")?;
        let locktime: u32 = arg(p, 2, "bondlocktime")?;
        let key: Option<PubKey> = opt_arg(p, 3, "memberkey")?;
        let Some(s) = self.set(&setid).cloned() else {
            return err(-5, "unknown set (it must be confirmed)");
        };
        let active = s
            .memberlist
            .iter()
            .filter(|m| m.status == MemberStatus::Active)
            .count() as u32;
        if active >= s.set.params.seats {
            return err(-26, "16: bad-vault-act-seats");
        }
        if bond < s.set.params.bondmin {
            return err(-26, "16: bad-vault-act-bond");
        }
        let key = match key {
            Some(k) => k,
            None => self.new_wallet_key(),
        };
        if let Some(e) = self.join_refusal(&setid, &key) {
            return Err(e);
        }
        let (required, sigs) = if s.set.params.open {
            (1, 1)
        } else {
            let admit = self.wallet_keys.contains(&s.set.params.admitkey) as u8;
            (2, 1 + admit)
        };
        let payload = Self::act_payload(2, required, sigs, false, &setid, &key);
        let bond_spk = mock_bond_spk(&key, locktime);
        let mut tx = self.act_tx(
            payload,
            vec![TxOut {
                value: bond.0,
                script_pubkey: bond_spk,
            }],
        );
        let complete = i32::from(sigs) >= required;
        let mut txid = None;
        if complete {
            self.sign_wallet_inputs(&mut tx);
            let id = self.submit(tx.encode())?;
            let bondoutpoint = OutPoint::new(id, 0);
            self.pending.insert(
                id,
                PendingAct::Join {
                    setid,
                    member: key,
                    bond,
                    locktime,
                    bondoutpoint,
                },
            );
            txid = Some(id);
        }
        let bondoutpoint = OutPoint::new(txid.unwrap_or_else(|| tx.txid()), 0);
        let r = SetJoinResult {
            txid,
            act: ActResult {
                hex: HexBytes(tx.encode()),
                acttype: ActType::Join,
                complete,
                signatures: u32::from(sigs),
                required,
            },
            memberkey: key,
            bondoutpoint,
        };
        to_json(&r)
    }

    fn set_heartbeat(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let setid: SetId = arg(p, 0, "setid")?;
        let key: Option<PubKey> = opt_arg(p, 1, "memberkey")?;
        if self.set(&setid).is_none() {
            return err(-5, format!("unknown set {setid}"));
        }
        let mine = self.wallet_member_keys(&setid, None);
        let key = match key {
            Some(k) if mine.contains(&k) => k,
            Some(_) => return err(-4, "memberkey is not a current member key in this wallet"),
            None => *mine.first().ok_or((
                -4,
                "this wallet holds no current member key of the set".to_owned(),
            ))?,
        };
        let mut tx = self.act_tx(Self::act_payload(3, 1, 1, false, &setid, &key), vec![]);
        self.sign_wallet_inputs(&mut tx);
        let txid = self.submit(tx.encode())?;
        self.pending
            .insert(txid, PendingAct::Heartbeat { setid, member: key });
        to_json(&HeartbeatResult {
            txid,
            memberkey: key,
        })
    }

    fn set_leave(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let setid: SetId = arg(p, 0, "setid")?;
        let key: Option<PubKey> = opt_arg(p, 1, "memberkey")?;
        let Some(s) = self.set(&setid).cloned() else {
            return err(-5, format!("unknown set {setid}"));
        };
        let mine: Vec<PubKey> = s
            .memberlist
            .iter()
            .filter(|m| m.status == MemberStatus::Active && self.wallet_keys.contains(&m.key))
            .map(|m| m.key)
            .collect();
        let key = match key {
            Some(k) if self.wallet_keys.contains(&k) => k,
            Some(_) => return err(-4, "the member key is not in this wallet"),
            None => *mine.first().ok_or((
                -4,
                "this wallet holds no active member key of the set".to_owned(),
            ))?,
        };
        if !mine.contains(&key) {
            return err(-26, "16: bad-vault-act-remove");
        }
        let mut tx = self.act_tx(Self::act_payload(4, 1, 1, false, &setid, &key), vec![]);
        self.sign_wallet_inputs(&mut tx);
        let txid = self.submit(tx.encode())?;
        self.pending
            .insert(txid, PendingAct::Leave { setid, member: key });
        let exitheight = self.next_height();
        to_json(&LeaveResult {
            txid,
            memberkey: key,
            exitheight,
            bondspendableat: exitheight + s.set.params.maturity,
        })
    }

    /// `gettxout`: bonds of the index, template outputs, the wallet's coins; `null` otherwise
    /// (and for an output a mempool transaction spends, when `includemempool`, the default).
    fn gettxout(&self, p: &[Value]) -> RpcResult {
        let txid: Txid = arg(p, 0, "txid")?;
        let vout: u32 = arg(p, 1, "n")?;
        let mempool = opt_arg::<bool>(p, 2, "includemempool")?.unwrap_or(true);
        let op = OutPoint::new(txid, vout);
        if mempool && self.spent_in_mempool(&op) {
            return Ok(Value::Null);
        }
        let found = if let Some(b) = self.bonds.get(&op) {
            Some((b.value.0, mock_bond_spk(&b.member, b.locktime)))
        } else if let Some(t) = self.templates.get(&op) {
            let spk = match t {
                TemplateOut::Vault(v) => v.script.0.clone(),
                TemplateOut::Intent(i) => i.script.0.clone(),
            };
            Some((t.valuezat(), spk))
        } else {
            self.unspent
                .iter()
                .find(|u| u.txid == txid && u.vout == vout)
                .map(|u| (u.amount_zat, u.script_pub_key.0.clone()))
        };
        // an output of a mempool transaction (includemempool): what the node shows too
        let found = found.or_else(|| {
            (mempool && self.mempool.contains(&txid))
                .then(|| self.txs.get(&txid))
                .flatten()
                .and_then(|(raw, _)| Transaction::decode(raw).ok())
                .and_then(|t| t.outputs.get(vout as usize).cloned())
                .map(|o| (o.value, o.script_pubkey))
        });
        let Some((value, spk)) = found else {
            return Ok(Value::Null);
        };
        let wallet_address = self
            .unspent
            .iter()
            .find(|u| u.txid == txid && u.vout == vout)
            .and_then(|u| u.address.clone());
        let height = self
            .txs
            .get(&txid)
            .and_then(|(_, b)| *b)
            .and_then(|b| self.blocks.iter().find(|x| x.hash == b))
            .map_or(self.tip_height(), |b| b.height);
        Ok(json!({
            "bestblock": self.tip_hash(),
            "confirmations": if self.mempool.contains(&txid) { 0 } else { self.tip_height() - height + 1 },
            "value": Amount(value).to_string(),
            "scriptPubKey": match &wallet_address {
                Some(a) => json!({"asm": "", "hex": hex::encode(&spk), "type": "pubkeyhash",
                                  "reqSigs": 1, "addresses": [a]}),
                None => json!({"asm": "", "hex": hex::encode(&spk), "type": "scripthash"}),
            },
            "version": 4,
            "coinbase": false,
        }))
    }

    /// `sendmany "" {"address": amount, …}`: one transaction from a phantom funding coin,
    /// one output per address (a new wallet coin when the address is the wallet's), change to
    /// the wallet; mempool.
    fn sendmany(&mut self, p: &[Value]) -> RpcResult {
        let to: serde_json::Map<String, Value> = arg(p, 1, "amounts")?;
        let mut outputs = vec![];
        let mut mine = vec![];
        for (a, v) in &to {
            let amount: Amount = serde_json::from_value(v.clone())
                .map_err(|e| (-3, format!("amount for {a}: {e}")))?;
            let Some(spk) = self.address_script(a) else {
                return err(-5, format!("Invalid Ycash address: {a}"));
            };
            if self.addresses.contains_key(a) {
                mine.push((outputs.len() as u32, a.clone(), spk.clone(), amount));
            }
            outputs.push(TxOut {
                value: amount.0,
                script_pubkey: spk,
            });
        }
        let mut tx = Transaction::new_v4(vec![], outputs, 0, 0);
        self.fund(&mut tx, 0);
        self.sign_wallet_inputs(&mut tx);
        let txid = self.submit(tx.encode())?;
        for (vout, a, spk, amount) in mine {
            self.unspent.push(Unspent {
                txid,
                vout,
                generated: false,
                address: Some(a),
                account: None,
                redeem_script: None,
                script_pub_key: HexBytes(spk),
                amount,
                amount_zat: amount.0,
                confirmations: 0,
                spendable: true,
            });
        }
        to_json(&txid)
    }

    fn spent_in_mempool(&self, op: &OutPoint) -> bool {
        self.mempool.iter().any(|m| {
            self.txs
                .get(m)
                .and_then(|(r, _)| Transaction::decode(r).ok())
                .is_some_and(|t| t.inputs.iter().any(|j| &j.prevout == op))
        })
    }

    fn set_buildact(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let ty: String = arg(p, 0, "type")?;
        let o: Value = arg(p, 1, "params")?;
        let get = |k: &str| o.get(k).cloned().unwrap_or(Value::Null);
        let setid: Option<SetId> = serde_json::from_value(get("setid")).ok();
        let key: Option<PubKey> = serde_json::from_value(get("memberkey")).ok();
        let (code, acttype) = match ty.as_str() {
            "create" => (1, ActType::Create),
            "join" => (2, ActType::Join),
            "heartbeat" => (3, ActType::Heartbeat),
            "remove" => (4, ActType::Remove),
            "equivocation" => (5, ActType::Equivocation),
            "winddown" => (6, ActType::Winddown),
            _ => return err(-8, "unknown act type"),
        };
        if code == 4 && !matches!(get("burn"), Value::Null | Value::Bool(_)) {
            return err(-3, "JSON value is not a boolean as expected");
        }
        let burn = get("burn") == Value::Bool(true);
        let required: i32 = match code {
            1 => {
                let cp: SetCreateParams =
                    serde_json::from_value(o.clone()).map_err(|e| (-8, e.to_string()))?;
                self.set_params_from(&cp)?;
                0
            }
            5 => 0,
            _ => {
                let Some(id) = setid else {
                    return err(-8, "missing setid");
                };
                let Some(s) = self.set(&id) else {
                    return err(-5, format!("unknown set {id}"));
                };
                match code {
                    3 => 1,
                    2 if s.set.params.open => 1,
                    2 => 2,
                    _ => s.set.params.slashthreshold as i32,
                }
            }
        };
        let payload = Self::act_payload(
            code,
            required,
            0,
            burn,
            &setid.unwrap_or_default(),
            &key.unwrap_or(PubKey([2; 33])),
        );
        let tx = self.act_tx(payload, vec![]);
        to_json(&ActResult {
            hex: HexBytes(tx.encode()),
            acttype,
            complete: required == 0,
            signatures: 0,
            required,
        })
    }

    fn find_act(tx: &Transaction) -> Option<(usize, Vec<u8>)> {
        tx.op_returns()
            .find(|(_, d)| d.starts_with(b"YV") && d.len() == 71)
            .map(|(i, d)| (i, d.to_vec()))
    }

    fn act_type_of(code: u8) -> ActType {
        match code {
            1 => ActType::Create,
            2 => ActType::Join,
            3 => ActType::Heartbeat,
            4 => ActType::Remove,
            5 => ActType::Equivocation,
            _ => ActType::Winddown,
        }
    }

    fn set_signact(&mut self, p: &[Value]) -> RpcResult {
        let h: HexBytes = arg(p, 0, "hex")?;
        let check: Option<SetId> = opt_arg(p, 1, "setid")?;
        let mut tx = Transaction::decode(&h.0).map_err(|_| (-22, "TX decode failed".to_owned()))?;
        let Some((vout, mut d)) = Self::find_act(&tx) else {
            return err(-8, "the transaction carries no YV act");
        };
        let setid = Hash256(d[6..38].try_into().expect("32"));
        let target = PubKey(d[38..71].try_into().expect("33"));
        if d[2] != 1
            && let Some(c) = check
            && c != setid
        {
            return err(-8, format!("the act names set {setid}"));
        }
        let required = d[3] as i8 as i32;
        let mut sigs = i32::from(d[4]);
        let available = match d[2] {
            2 => {
                let admit = self.set(&setid).map(|s| s.set.params.admitkey);
                let mut n = admit
                    .filter(|k| self.wallet_keys.contains(k))
                    .map_or(0, |_| 1);
                if self.wallet_keys.contains(&target) && sigs == 0 {
                    n += 1;
                }
                n
            }
            3 => i32::from(self.wallet_keys.contains(&target)),
            4 => self.wallet_member_keys(&setid, Some(&target)).len() as i32,
            _ => self.wallet_member_keys(&setid, None).len() as i32,
        };
        sigs = (sigs + available).min(required.max(sigs));
        d[4] = sigs as u8;
        tx.outputs[vout] = TxOut::op_return(&d);
        to_json(&ActResult {
            hex: HexBytes(tx.encode()),
            acttype: Self::act_type_of(d[2]),
            complete: sigs >= required,
            signatures: sigs as u32,
            required,
        })
    }

    fn set_sendact(&mut self, p: &[Value]) -> RpcResult {
        let h: HexBytes = arg(p, 0, "hex")?;
        let mut tx = Transaction::decode(&h.0).map_err(|_| (-22, "TX decode failed".to_owned()))?;
        let Some((_, d)) = Self::find_act(&tx) else {
            return err(-8, "the transaction carries no YV act");
        };
        let setid = Hash256(d[6..38].try_into().expect("32"));
        let key = PubKey(d[38..71].try_into().expect("33"));
        // the node judges a removal's target before its co-signers
        if d[2] == 4
            && self.set(&setid).is_some()
            && let Some(e) = self.remove_refusal(&setid, &key, d[5] == 1)
        {
            return Err(e);
        }
        if i32::from(d[4]) < d[3] as i8 as i32 {
            return err(-26, "16: bad-vault-act-sigs");
        }
        if d[2] != 1 && self.set(&setid).is_none() {
            return err(-26, "16: bad-vault-act-noset");
        }
        if d[2] == 2
            && let Some(s) = self.set(&setid)
            && s.memberlist
                .iter()
                .filter(|m| m.status == MemberStatus::Active)
                .count() as u32
                >= s.set.params.seats
        {
            return err(-26, "16: bad-vault-act-seats");
        }
        if d[2] == 2
            && let Some(e) = self.join_refusal(&setid, &key)
        {
            return Err(e);
        }
        self.sign_wallet_inputs(&mut tx);
        let txid = self.submit(tx.encode())?;
        let act = match d[2] {
            2 => {
                let bond = Amount(tx.outputs.first().map_or(0, |o| o.value));
                Some(PendingAct::Join {
                    setid,
                    member: key,
                    bond,
                    locktime: 0,
                    bondoutpoint: OutPoint::new(txid, 0),
                })
            }
            3 => Some(PendingAct::Heartbeat { setid, member: key }),
            4 => Some(PendingAct::Remove {
                setid,
                member: key,
                burn: d[5] == 1,
            }),
            6 => Some(PendingAct::Winddown { setid }),
            _ => None,
        };
        if let Some(a) = act {
            self.pending.insert(txid, a);
        }
        to_json(&txid)
    }

    fn set_equivocation(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let proof: Proof = arg(p, 0, "proof")?;
        if self.set(&proof.setid).is_none() {
            return err(-8, format!("unknown set {}", proof.setid));
        }
        for (s, n) in [(&proof.siga, "siga"), (&proof.sigb, "sigb")] {
            if s.0.len() != 65 {
                return err(-8, format!("{n} must be a 65-byte recoverable signature"));
            }
        }
        if proof.rolea == proof.roleb && proof.sighasha == proof.sighashb {
            return err(-26, "16: bad-vault-act-equivocation");
        }
        let member = sig_key(&proof.siga.0).ok_or((-8, "siga".to_owned()))?;
        let mut tx = self.act_tx(
            Self::act_payload(5, 0, 0, false, &proof.setid, &member),
            vec![],
        );
        self.sign_wallet_inputs(&mut tx);
        let txid = self.submit(tx.encode())?;
        self.pending.insert(
            txid,
            PendingAct::Equivocation {
                setid: proof.setid,
                member,
            },
        );
        to_json(&txid)
    }

    fn vault_getnewowner(&mut self, p: &[Value]) -> RpcResult {
        let scheme: Option<u8> = opt_arg(p, 0, "scheme")?;
        match scheme.unwrap_or(1) {
            1 => {}
            2 => return err(-8, "FN-DSA-512 owners need Falcon active at the next block"),
            s => return err(-8, format!("unknown post-quantum scheme {s}")),
        }
        let owner = self.new_wallet_owner();
        to_json(&NewOwner {
            scheme: 1,
            keyhash: HexBytes(owner.hash().to_vec()),
            owner,
            address: Self::pq_address(&owner),
        })
    }

    fn vault_lock(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        if p.first().is_some_and(|o| o.get("ownerkey").is_some()) {
            return err(-8, "ownerkey-removed: use owner (pqkeyid)");
        }
        let o: VaultLockParams = arg(p, 0, "params")?;
        let tag = tag_bytes(&o.tag)?;
        if !(1..=65535).contains(&o.delay) || o.amount.0 <= 0 {
            return err(-8, "vault parameters out of range (plan §15.3)");
        }
        let cancelsetid = o.cancelsetid.unwrap_or(o.setid);
        if self.set(&o.setid).is_none() || self.set(&cancelsetid).is_none() {
            return err(-5, "setid and cancelsetid must be confirmed sets");
        }
        let owner = match o.owner {
            Some(k) => k,
            None => self.new_wallet_owner(),
        };
        let fields = VaultFields {
            tagtext: tag_text(&tag),
            tag: HexBytes(tag),
            setid: o.setid,
            cancelsetid,
            delay: o.delay,
            ownerheight: o.ownerheight,
            appheight: o.appheight.unwrap_or(0),
            owner,
            ownerscheme: owner.scheme(),
        };
        let script = mock_vault_script(&fields);
        self.register_script(script.clone(), KnownScript::Vault(fields));
        let mut tx = Transaction::new_v4(
            vec![],
            vec![TxOut {
                value: o.amount.0,
                script_pubkey: script.clone(),
            }],
            0,
            0,
        );
        self.fund(&mut tx, 0);
        self.sign_wallet_inputs(&mut tx);
        let txid = self.submit(tx.encode())?;
        to_json(&VaultLockResult {
            txid,
            vout: 0,
            outpoint: OutPoint::new(txid, 0),
            script: HexBytes(script),
            owner,
        })
    }

    fn recipient_script(&self, r: &Recipient) -> Result<Vec<u8>, (i64, String)> {
        match &r.to {
            RecipientTo::Address(a) => self
                .address_script(a)
                .ok_or((-5, format!("invalid transparent address: {a}"))),
            RecipientTo::Script(s) => Ok(s.0.clone()),
        }
    }

    /// `vault_buildunlock` (`app` false) and `vault_app` (`app` true).
    fn vault_build_spend(&mut self, p: &[Value], app: bool) -> RpcResult {
        self.ensure_active()?;
        let op: OutPoint = arg(p, 0, "outpoint")?;
        let recipients: Vec<Recipient> = if app {
            opt_arg(p, 1, "recipients")?.unwrap_or_default()
        } else {
            arg(p, 1, "recipients")?
        };
        let Some(TemplateOut::Vault(v)) = self.templates.get(&op).cloned() else {
            return err(-8, "not an unspent vault output");
        };
        if app {
            if v.fields.appheight == 0 {
                return err(-8, "the vault has no APP branch (appheight 0, S-4)");
            }
            if self.next_height() <= v.fields.appheight {
                return err(
                    -1,
                    format!("the APP branch opens at height {}", v.fields.appheight + 1),
                );
            }
        }
        let vault_hash = Bytes32(sha256(&v.script.0));
        let mut outputs = vec![];
        let mut intents = vec![];
        let mut sum = 0i64;
        for r in &recipients {
            let dest = self.recipient_script(r)?;
            sum += r.amount.0;
            if r.amount.0 < 0 || sum > v.valuezat {
                return err(-8, "the recipients' amounts exceed the vault's value");
            }
            let recipienthash = Bytes32(sha256(&dest));
            let fields = IntentFields {
                tag: v.fields.tag.clone(),
                tagtext: v.fields.tagtext.clone(),
                setid: v.fields.setid,
                cancelsetid: v.fields.cancelsetid,
                delay: v.fields.delay,
                owner: v.fields.owner,
                ownerscheme: v.fields.ownerscheme,
                recipienthash,
                vaulthash: vault_hash,
            };
            let script = mock_intent_script(&fields);
            self.register_script(
                script.clone(),
                KnownScript::Intent {
                    fields,
                    origin: v.script.0.clone(),
                },
            );
            self.recipients.insert(recipienthash, dest.clone());
            outputs.push(TxOut {
                value: r.amount.0,
                script_pubkey: script,
            });
            intents.push(IntentOut {
                vout: outputs.len() as u32 - 1,
                amount: r.amount,
                recipient: HexBytes(dest),
                recipienthash,
            });
        }
        if sum < v.valuezat {
            outputs.push(TxOut {
                value: v.valuezat - sum,
                script_pubkey: v.script.0.clone(),
            });
        }
        let rebuild = !app && opt_arg::<bool>(p, 2, "rebuild")?.unwrap_or(false);
        let memo_key = (self.current_wallet.clone(), op);
        if !app {
            if rebuild {
                self.builds.remove(&memo_key);
            } else if let Some((want, raw)) = self.builds.get(&memo_key).cloned() {
                if want != outputs {
                    let old = Transaction::decode(&raw).expect("remembered build");
                    return err(
                        -8,
                        format!(
                            "this wallet already built a different unlock of {op} (sighash {}): members sign once, so \
                             collect signatures on that build (call again with its recipients), or pass rebuild=true \
                             if no member has signed it",
                            Self::mock_sighash(&old, 0)
                        ),
                    );
                }
                let tx = Transaction::decode(&raw).expect("remembered build");
                let required = self
                    .set(&v.fields.setid)
                    .map_or(0, |s| s.set.params.unlockthreshold);
                return to_json(&BuildUnlockResult {
                    hex: HexBytes(raw),
                    intents,
                    required,
                    sighash: Self::mock_sighash(&tx, 0),
                    build: BuildKind::Reused,
                });
            }
        }
        let requested = outputs.clone();
        let script_sig = if app { vec![OP_1 + 3] } else { vec![] };
        let lock_time = if app { v.fields.appheight } else { 0 };
        let mut tx = Transaction::new_v4(
            vec![TxIn {
                prevout: op,
                script_sig,
                sequence: u32::MAX,
            }],
            outputs,
            lock_time,
            0,
        );
        self.fund(&mut tx, v.valuezat);
        let hex = HexBytes(tx.encode());
        if app {
            to_json(&AppResult { hex, intents })
        } else {
            let required = self
                .set(&v.fields.setid)
                .map_or(0, |s| s.set.params.unlockthreshold);
            self.builds.insert(memo_key, (requested, hex.0.clone()));
            to_json(&BuildUnlockResult {
                hex,
                intents,
                required,
                sighash: Self::mock_sighash(&tx, 0),
                build: BuildKind::New,
            })
        }
    }

    fn set_sign(&mut self, p: &[Value], role: u8) -> RpcResult {
        let h: HexBytes = arg(p, 0, "hex")?;
        let mut tx = Transaction::decode(&h.0).map_err(|_| (-22, "TX decode failed".to_owned()))?;
        let mut found = None;
        for (i, input) in tx.inputs.iter().enumerate() {
            if let Some((k, _, _)) = self.template(&input.prevout) {
                if found.is_some() {
                    return err(-8, "more than one template input (S-1)");
                }
                found = Some((i, k));
            }
        }
        let Some((idx, known)) = found else {
            return err(-8, "no unspent vault or intent input");
        };
        let setid = match (&known, role) {
            (KnownScript::Vault(f), 1) => f.setid,
            (KnownScript::Intent { fields, .. }, 2) => fields.cancelsetid,
            (_, 1) => return err(-8, "the template input is not a vault"),
            _ => return err(-8, "the template input is not an intent"),
        };
        let Some(set) = self.set(&setid).cloned() else {
            return err(-5, format!("unknown set {setid}"));
        };
        let k = if role == 1 {
            set.set.params.unlockthreshold
        } else {
            set.set.params.cancelthreshold
        } as usize;
        let sighash = Self::mock_sighash(&tx, idx);
        let prevout = tx.inputs[idx].prevout;
        let mut sigs = vec![];
        if !tx.inputs[idx].script_sig.is_empty() {
            match parse_scriptsig(&tx.inputs[idx].script_sig) {
                Some((s, sel)) if sel == role => sigs = s,
                _ => return err(-8, "the template input's scriptSig is for another branch"),
            }
        }
        let mut have = vec![];
        for s in &sigs {
            match sig_key(s) {
                Some(key) if s[34..] == sighash.0[..31] => have.push(key),
                _ => {
                    return err(
                        -8,
                        "an existing set signature does not verify (the transaction changed?)",
                    );
                }
            }
        }
        let ack = p
            .get(1)
            .and_then(|o| o.get("acknowledgerestore"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if self.restored && !ack && !self.sign_once.contains_key(&(setid, prevout)) {
            return err(
                -4,
                format!(
                    "set-sign-restored: this wallet was restored or imported a member key and has no sign-once history; \
                     import it with set_importsigned (or a wallet dump) and then set_acknowledgerestore, or pass \
                     {{\"acknowledgerestore\": true}} if this key has never signed a set spend of {prevout}"
                ),
            );
        }
        let mut recorded = false;
        let view = self
            .current_wallet
            .clone()
            .filter(|w| self.wallet_views.contains_key(w));
        let prior = match &view {
            Some(w) => self
                .view_sign_once
                .get(&(w.clone(), setid, prevout))
                .copied(),
            None => self.sign_once.get(&(setid, prevout)).copied(),
        };
        if let Some((r, sh)) = prior.as_ref() {
            if *r != role || *sh != sighash {
                return err(
                    -4,
                    format!(
                        "set-sign-once: this wallet already signed a different {} (role {r}, sighash {sh}) of {prevout} for set {setid}; \
                         a second signature is a provable equivocation (SET_EQUIVOCATION ejects the member and freezes its bond). \
                         Collect signatures on the transaction already signed",
                        if *r == 1 { "unlock" } else { "cancel" }
                    ),
                );
            }
            recorded = true;
        }
        for key in self.wallet_member_keys(&setid, None) {
            if sigs.len() >= k {
                break;
            }
            if have.contains(&key) {
                continue;
            }
            if !recorded {
                match &view {
                    Some(w) => {
                        self.view_sign_once
                            .insert((w.clone(), setid, prevout), (role, sighash));
                    }
                    None => {
                        self.sign_once.insert((setid, prevout), (role, sighash));
                    }
                }
                recorded = true;
            }
            sigs.push(mock_set_sig(&key, &sighash));
            have.push(key);
        }
        let mut ss = vec![];
        for s in &sigs {
            crate::tx::push_data(&mut ss, s);
        }
        ss.push(OP_1 + role - 1);
        tx.inputs[idx].script_sig = ss;
        let setsigs = have
            .iter()
            .zip(&sigs)
            .map(|(k, s)| SetSig {
                key: *k,
                sig: HexBytes(s.clone()),
            })
            .collect();
        to_json(&SetSigResult {
            hex: HexBytes(tx.encode()),
            complete: sigs.len() == k,
            signatures: sigs.len() as u32,
            required: k as u32,
            sighash,
            setsigs,
        })
    }

    fn vault_buildcancel(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let op: OutPoint = arg(p, 0, "intentoutpoint")?;
        let Some((KnownScript::Intent { fields, origin }, value, height)) = self.template(&op)
        else {
            return err(-8, "not an unspent intent output");
        };
        let next = self.next_height();
        let coin_height = height.unwrap_or(next);
        if next - coin_height >= fields.delay {
            return err(
                -1,
                format!(
                    "the intent matured at height {}; it can no longer be cancelled",
                    coin_height + fields.delay
                ),
            );
        }
        let rebuild = opt_arg::<bool>(p, 1, "rebuild")?.unwrap_or(false);
        if rebuild {
            self.cancels.remove(&op);
        }
        let mut build = BuildKind::Reused;
        let hex = match self.cancels.get(&op) {
            Some(h) => h.clone(),
            None => {
                build = BuildKind::New;
                let mut tx = Transaction::new_v4(
                    vec![TxIn {
                        prevout: op,
                        script_sig: vec![],
                        sequence: u32::MAX,
                    }],
                    vec![TxOut {
                        value,
                        script_pubkey: origin,
                    }],
                    0,
                    0,
                );
                self.fund(&mut tx, value);
                let raw = tx.encode();
                self.cancels.insert(op, raw.clone());
                raw
            }
        };
        let required = self
            .set(&fields.cancelsetid)
            .map_or(0, |s| s.set.params.cancelthreshold);
        let sighash = Self::mock_sighash(&Transaction::decode(&hex).expect("cancel build"), 0);
        to_json(&BuildCancelResult {
            hex: HexBytes(hex),
            required,
            cancelsetid: fields.cancelsetid,
            deadline: coin_height + fields.delay - 1,
            intentconfirmed: height.is_some(),
            sighash,
            build,
        })
    }

    /// `vault_refee` (01/V-2): every input but the template input replaced by one fresh mock
    /// wallet coin worth exactly what the outputs need beyond the template coin plus [`FEE`];
    /// the template input (with its scriptSig) moves to index 0, every output stays.
    fn vault_refee(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let h: HexBytes = arg(p, 0, "hex")?;
        let mut tx = Transaction::decode(&h.0).map_err(|_| (-22, "TX decode failed".to_owned()))?;
        let mut found = None;
        for (i, input) in tx.inputs.iter().enumerate() {
            if let Some((_, value, _)) = self.template(&input.prevout) {
                if found.is_some() {
                    return err(-8, "more than one template input (S-1)");
                }
                found = Some((i, value));
            }
        }
        let Some((idx, value)) = found else {
            return err(-8, "no unspent vault or intent input");
        };
        let template = tx.inputs[idx].clone();
        let replaced: Vec<OutPoint> = tx
            .inputs
            .iter()
            .filter(|i| i.prevout != template.prevout)
            .map(|i| i.prevout)
            .collect();
        let out: i64 = tx.outputs.iter().map(|o| o.value).sum();
        let needed = out + FEE - value;
        tx.inputs = vec![template];
        if needed > 0 {
            let prev = Hash256(self.fresh("refee"));
            let a = format!("tmMock{}", hex::encode(&prev.0[..10]));
            let spk = p2pkh(&sha256(&prev.0));
            self.addresses.insert(a.clone(), spk.clone());
            self.unspent.push(Unspent {
                txid: prev,
                vout: 0,
                generated: false,
                address: Some(a),
                account: None,
                redeem_script: None,
                script_pub_key: HexBytes(spk),
                amount: Amount(needed),
                amount_zat: needed,
                confirmations: 6,
                spendable: true,
            });
            tx.inputs.push(TxIn {
                prevout: OutPoint::new(prev, 0),
                script_sig: vec![],
                sequence: u32::MAX,
            });
        }
        to_json(&RefeeResult {
            hex: HexBytes(tx.encode()),
            sighash: Self::mock_sighash(&tx, 0),
            fee: Amount(FEE),
            replaced,
        })
    }

    fn set_listsigned(&self) -> RpcResult {
        let mut records: Vec<SignedRecord> = self
            .sign_once
            .iter()
            .map(|((setid, prevout), (role, sighash))| SignedRecord {
                setid: *setid,
                prevout: *prevout,
                role: *role,
                sighash: *sighash,
            })
            .collect();
        records.sort_by_key(|r| (r.setid.0, r.prevout.txid.0, r.prevout.vout));
        to_json(&SignedRecords {
            restored: self.restored,
            records,
        })
    }

    fn set_importsigned(&mut self, p: &[Value]) -> RpcResult {
        let records: Vec<SignedRecord> = arg(p, 0, "records")?;
        let mut present = 0;
        for r in &records {
            match self.sign_once.get(&(r.setid, r.prevout)) {
                Some(x) if *x == (r.role, r.sighash) => present += 1,
                Some(_) => {
                    return err(
                        -4,
                        format!(
                            "set-sign-once: a different record of {} for set {} is already held; nothing imported",
                            r.prevout, r.setid
                        ),
                    );
                }
                None => {}
            }
        }
        let mut imported = 0;
        for r in &records {
            if self
                .sign_once
                .insert((r.setid, r.prevout), (r.role, r.sighash))
                .is_none()
            {
                imported += 1;
            }
        }
        to_json(&ImportSignedResult { imported, present })
    }

    fn vault_send(&mut self, p: &[Value]) -> RpcResult {
        let h: HexBytes = arg(p, 0, "hex")?;
        let mut tx = Transaction::decode(&h.0).map_err(|_| (-22, "TX decode failed".to_owned()))?;
        for input in &tx.inputs {
            let Some((known, _, _)) = self.template(&input.prevout) else {
                continue;
            };
            let (sigs, sel) = parse_scriptsig(&input.script_sig).unwrap_or_default();
            let need = match (&known, sel) {
                (KnownScript::Vault(f), 1) => self
                    .set(&f.setid)
                    .map_or(u32::MAX, |s| s.set.params.unlockthreshold),
                (KnownScript::Intent { fields, .. }, 2) => self
                    .set(&fields.cancelsetid)
                    .map_or(u32::MAX, |s| s.set.params.cancelthreshold),
                (KnownScript::Vault(_), 4) => 0,
                _ => u32::MAX,
            };
            if (sigs.len() as u32) < need {
                return err(
                    -26,
                    "16: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)",
                );
            }
            if let (KnownScript::Vault(f), 1) = (&known, sel) {
                let intents: i64 = tx
                    .outputs
                    .iter()
                    .filter(|o| {
                        matches!(
                            self.scripts.get(&o.script_pubkey),
                            Some(KnownScript::Intent { .. })
                        )
                    })
                    .map(|o| o.value)
                    .sum();
                if let Some(s) = self.set(&f.setid) {
                    let view = self.set_view(s, self.next_height());
                    if view.set.unlockavailable.is_some_and(|a| a.0 < intents) {
                        return err(-26, "16: bad-txns-vault-rate");
                    }
                }
            }
        }
        self.sign_wallet_inputs(&mut tx);
        to_json(&self.submit(tx.encode())?)
    }

    fn vault_release(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let op: OutPoint = arg(p, 0, "intentoutpoint")?;
        let to: Option<String> = opt_arg(p, 1, "recipient")?;
        let Some((KnownScript::Intent { fields, .. }, value, height)) = self.template(&op) else {
            return err(-8, "not an unspent intent output");
        };
        let Some(h) = height else {
            return err(-1, "the intent is not confirmed");
        };
        if h + fields.delay > self.next_height() {
            return err(
                -1,
                format!("the intent matures at height {}", h + fields.delay),
            );
        }
        // an address of this wallet (a mock `tmMock…`/`rqMock…`, or anything alphanumeric as
        // a mock P2PKH), or the script itself in hex: P2PKH, P2SH or the 35-byte `TX_PQPKH`
        // `20 <hash> 51|52 c2`, which the node pays wherever it takes an address (D-Q-20)
        let dest = match &to {
            Some(a) => match self.address_script(a) {
                Some(s) if !a.chars().all(|c| c.is_ascii_hexdigit()) => s,
                _ => {
                    hex::decode(a).map_err(|_| (-5, format!("not an address or a script: {a}")))?
                }
            },
            None => self.recipients.get(&fields.recipienthash).cloned().ok_or((
                -8,
                "the recipient script is unknown here; pass it".to_owned(),
            ))?,
        };
        if Bytes32(sha256(&dest)) != fields.recipienthash {
            // the node (src/rpc/vault.cpp, d41026209): a 66-hex `scheme || keyhash` of a
            // registered scheme, as vault_list and z_importpqkey print it, is not a script
            if to.as_ref().is_some_and(|a| a.len() == 66)
                && dest.len() == 33
                && (dest[0] == 1 || dest[0] == 2)
            {
                return err(
                    -8,
                    "that looks like a pqkeyid: pass the address or the script, not a pqkeyid",
                );
            }
            return err(-8, "that script is not the intent's recipient");
        }
        let mut tx = Transaction::new_v4(
            vec![TxIn {
                prevout: op,
                script_sig: vec![OP_1],
                sequence: fields.delay,
            }],
            vec![TxOut {
                value,
                script_pubkey: dest,
            }],
            0,
            0,
        );
        self.fund(&mut tx, value);
        self.sign_wallet_inputs(&mut tx);
        to_json(&self.submit(tx.encode())?)
    }

    fn vault_ownerspend(&mut self, p: &[Value]) -> RpcResult {
        self.ensure_active()?;
        let op: OutPoint = arg(p, 0, "outpoint")?;
        let address: String = arg(p, 1, "address")?;
        let dest = self
            .address_script(&address)
            .ok_or((-5, "invalid transparent address".to_owned()))?;
        let Some(t) = self.templates.get(&op).cloned() else {
            return err(-8, "not an unspent output");
        };
        let next = self.next_height();
        let released =
            |s: &Self, id: &SetId| s.set(id).is_some_and(|x| s.set_view(x, next).set.released);
        let (selector, lock_time, owner) = match &t {
            TemplateOut::Vault(v) if next > v.fields.ownerheight => {
                (2u8, v.fields.ownerheight, v.fields.owner)
            }
            TemplateOut::Vault(v) if released(self, &v.fields.setid) => (3, 0, v.fields.owner),
            TemplateOut::Vault(v) => {
                return err(
                    -1,
                    format!(
                        "the owner branch opens at height {} and the set is not released",
                        v.fields.ownerheight + 1
                    ),
                );
            }
            TemplateOut::Intent(i) if released(self, &i.fields.setid) => (3, 0, i.fields.owner),
            TemplateOut::Intent(_) => return err(-1, "the intent's set is not released"),
        };
        if !self.wallet_owners.contains(&owner) {
            return err(
                -4,
                format!("owner {owner} is not a post-quantum key of this wallet"),
            );
        }
        let value = t.valuezat();
        let ss = mock_pq_owner_script_sig(&owner, selector);
        let mut tx = Transaction::new_v4(
            vec![TxIn {
                prevout: op,
                script_sig: ss,
                sequence: u32::MAX - 1,
            }],
            vec![TxOut {
                value: 0,
                script_pubkey: dest,
            }],
            lock_time,
            0,
        );
        // max(VAULT_RPC_FEE, the vault/Yellowback rate × size) capped (ycash-dd vault_ownerspend, rpcversion 8)
        let size = i64::try_from(tx.encode().len()).unwrap_or(i64::MAX);
        let fee = owner_spend_fee(self.pq_fee_rate, self.fee_price_micro_usd, size);
        if value <= fee {
            return err(-8, format!("the output does not cover the fee {fee}"));
        }
        tx.outputs[0].value = value - fee;
        let txid = self.submit(tx.encode())?;
        to_json(&OwnerSpendResult { txid, selector })
    }

    fn getblockchaininfo(&self) -> RpcResult {
        let tip = self.tip_height();
        let branch = |h: u32| {
            if self.activation_height >= 0 && i64::from(h) >= self.activation_height {
                VAULT_BRANCH_ID.to_owned()
            } else {
                self.pre_vault_branch_id.clone()
            }
        };
        let mut upgrades = Map::new();
        if self.activation_height >= 0 {
            let status = if i64::from(tip) >= self.activation_height {
                "active"
            } else {
                "pending"
            };
            upgrades.insert(
                VAULT_BRANCH_ID.into(),
                json!({"name": "Vault", "activationheight": self.activation_height, "status": status, "info": "vault primitive"}),
            );
        }
        Ok(json!({
            "chain": self.chain, "blocks": tip, "initial_block_download_complete": true, "headers": tip,
            "bestblockhash": self.tip_hash(), "difficulty": 1.0, "verificationprogress": 1.0,
            "chainwork": format!("{:064x}", tip + 1), "pruned": false, "size_on_disk": 0, "estimatedheight": tip,
            "commitments": 0, "valuePools": [], "softforks": [], "upgrades": upgrades,
            "consensus": {"chaintip": branch(tip), "nextblock": branch(tip + 1)},
        }))
    }

    fn block_by_ref(&self, s: &str) -> Option<&MockBlock> {
        if s.len() < 64 {
            return s.parse::<usize>().ok().and_then(|h| self.blocks.get(h));
        }
        let h: Hash256 = s.parse().ok()?;
        self.blocks.iter().find(|b| b.hash == h)
    }

    fn getblock(&self, p: &[Value]) -> RpcResult {
        let r: String = arg(p, 0, "hash|height")?;
        let verbosity = match p.get(1) {
            None | Some(Value::Null) => 1,
            Some(Value::Bool(b)) => i64::from(*b),
            Some(v) => v
                .as_i64()
                .ok_or((-8, "Verbosity must be in range from 0 to 2".to_owned()))?,
        };
        if !(0..=2).contains(&verbosity) {
            return err(-8, "Verbosity must be in range from 0 to 2");
        }
        let b = self
            .block_by_ref(&r)
            .ok_or((-5, "Block not found".to_owned()))?;
        if verbosity == 0 {
            // a mock "block": the header hash followed by the transactions
            let mut raw = b.hash.0.to_vec();
            for t in &b.txids {
                raw.extend(&self.txs[t].0);
            }
            return Ok(hex::encode(raw).into());
        }
        let txs: Vec<Value> = if verbosity == 2 {
            b.txids
                .iter()
                .map(|t| self.tx_json(&Transaction::decode(&self.txs[t].0).expect("valid"), None))
                .collect()
        } else {
            b.txids
                .iter()
                .map(|t| Value::String(t.to_string()))
                .collect()
        };
        let mut o = json!({
            "hash": b.hash, "confirmations": i64::from(self.tip_height()) - i64::from(b.height) + 1, "size": 1000,
            "height": b.height, "version": 4, "merkleroot": Hash256(sha256d(&b.hash.0)),
            "finalsaplingroot": "00".repeat(32), "chainhistoryroot": "00".repeat(32), "tx": txs, "time": b.time,
            "nonce": "00".repeat(32), "solution": "00", "bits": "200f0f0f", "difficulty": 1.0,
            "chainwork": format!("{:064x}", b.height + 1), "anchor": "00".repeat(32), "valuePools": [],
        });
        if b.height > 0 {
            o["previousblockhash"] = to_json(&self.blocks[b.height as usize - 1].hash)?;
        }
        if let Some(n) = self.blocks.get(b.height as usize + 1) {
            o["nextblockhash"] = to_json(&n.hash)?;
        }
        Ok(o)
    }

    fn getrawtransaction(&self, p: &[Value]) -> RpcResult {
        let txid: Txid = arg(p, 0, "txid")?;
        let verbose = match p.get(1) {
            None | Some(Value::Null) => false,
            Some(Value::Number(n)) => n.as_i64() != Some(0),
            Some(_) => return err(-1, "JSON value is not an integer as expected"),
        };
        let (raw, block) = self
            .txs
            .get(&txid)
            .ok_or((-5, "No information available about transaction".to_owned()))?;
        if !verbose {
            return Ok(hex::encode(raw).into());
        }
        let tx = Transaction::decode(raw).expect("stored transactions decode");
        Ok(self.tx_json(&tx, *block))
    }

    /// `TxToJSON`.
    fn tx_json(&self, tx: &Transaction, block: Option<BlockHash>) -> Value {
        let raw = tx.encode();
        let vin: Vec<Value> = tx
            .inputs
            .iter()
            .map(|i| {
                if i.is_coinbase() {
                    json!({"coinbase": hex::encode(&i.script_sig), "sequence": i.sequence})
                } else {
                    json!({"txid": i.prevout.txid, "vout": i.prevout.vout,
                           "scriptSig": {"asm": "", "hex": hex::encode(&i.script_sig)}, "sequence": i.sequence})
                }
            })
            .collect();
        let vout: Vec<Value> = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(n, o)| {
                let s = &o.script_pubkey;
                let ty = if s.len() == 25 && s[..3] == [0x76, 0xa9, 0x14] {
                    "pubkeyhash"
                } else if o.is_op_return() {
                    "nulldata"
                } else {
                    "nonstandard"
                };
                json!({"value": Amount(o.value), "valueZat": o.value, "valueSat": o.value, "n": n,
                       "scriptPubKey": {"asm": "", "hex": hex::encode(s), "type": ty}})
            })
            .collect();
        let mut j = json!({
            "txid": tx.txid(), "size": raw.len(), "overwintered": tx.overwintered, "version": tx.version,
            "locktime": tx.lock_time, "hex": hex::encode(&raw), "vin": vin, "vout": vout, "vjoinsplit": [],
        });
        if tx.overwintered {
            j["versiongroupid"] = format!("{:08x}", tx.version_group_id).into();
            j["expiryheight"] = tx.expiry_height.into();
        }
        if let Some(s) = &tx.sapling {
            j["valueBalance"] = json!(Amount(s.value_balance));
            j["valueBalanceZat"] = s.value_balance.into();
            j["vShieldedSpend"] = json!([]);
            j["vShieldedOutput"] = json!([]);
        }
        if let Some(b) = block
            && let Some(blk) = self.blocks.iter().find(|x| x.hash == b)
        {
            j["blockhash"] = json!(b);
            j["height"] = blk.height.into();
            j["confirmations"] = (self.tip_height() - blk.height + 1).into();
            j["time"] = blk.time.into();
            j["blocktime"] = blk.time.into();
        }
        j
    }
}

// ---------------------------------------------------------------------------------- server

/// Keys whose values are YEC amounts in this node's answers (printed as decimal numbers).
const AMOUNT_KEYS: &[&str] = &[
    "value",
    "amount",
    "lockedvalue",
    "epochbasis",
    "epochused",
    "unlockavailable",
    "bondmin",
    "bondvalue",
    "valueBalance",
];

/// JSON text with amounts as the node prints them: `"1.50000000"` at an amount key becomes the
/// number `1.50000000`.
fn node_json(v: &Value) -> String {
    fn write(out: &mut String, v: &Value, amount: bool) {
        match v {
            Value::String(s) if amount && s.parse::<Amount>().is_ok() => out.push_str(s),
            Value::Object(o) => {
                out.push('{');
                for (i, (k, x)) in o.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).expect("string"));
                    out.push(':');
                    write(out, x, AMOUNT_KEYS.contains(&k.as_str()));
                }
                out.push('}');
            }
            Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(out, x, false);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut s = String::new();
    write(&mut s, v, false);
    s
}

type Shared = Arc<Mutex<MockState>>;

fn lock(s: &Shared) -> MutexGuard<'_, MockState> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

async fn handle_wallet(
    State(st): State<Shared>,
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    handle_as(st, Some(name), headers, body).await
}

async fn handle(State(st): State<Shared>, headers: HeaderMap, body: String) -> Response {
    handle_as(st, None, headers, body).await
}

async fn handle_as(
    st: Shared,
    wallet: Option<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let reply = |status: StatusCode, body: String| {
        (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
    };
    let mut s = lock(&st);
    if let Some(code) = s.http_failures.pop_front() {
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return (status, "mock HTTP failure").into_response();
    }
    if let Some((u, p)) = &s.auth {
        use base64::Engine as _;
        let want = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        );
        if headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            != Some(want.as_str())
        {
            return (StatusCode::UNAUTHORIZED, "").into_response();
        }
    }
    let req = match crate::json::to_value(&body) {
        Ok(Value::Object(o)) => o,
        _ => {
            let e = json!({"result": null, "error": {"code": -32700, "message": "Parse error"}, "id": null});
            return reply(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let params = match req.get("params") {
        Some(Value::Array(a)) => a.clone(),
        _ => vec![],
    };
    let canned = s.canned.get_mut(&method).and_then(VecDeque::pop_front);
    s.current_wallet = wallet;
    let result = match canned {
        Some(Reply::Result(v)) => Ok(v),
        Some(Reply::Error { code, message }) => Err((code, message)),
        None => s.dispatch(&method, &params),
    };
    s.current_wallet = None;
    s.calls.push(Call {
        method,
        params,
        error: result.as_ref().err().cloned(),
    });
    drop(s);
    match result {
        Ok(v) => reply(
            StatusCode::OK,
            node_json(&json!({"result": v, "error": null, "id": id})),
        ),
        Err((code, message)) => {
            let status = if code == -32601 {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            reply(
                status,
                json!({"result": null, "error": {"code": code, "message": message}, "id": id})
                    .to_string(),
            )
        }
    }
}

/// A running mock `ycashd` on `127.0.0.1`. Dropping it stops the server.
pub struct MockYcashd {
    addr: SocketAddr,
    state: Shared,
    shutdown: Option<oneshot::Sender<()>>,
}

impl MockYcashd {
    /// Start with a fresh [`MockState`] (inside a tokio runtime).
    pub async fn start() -> std::io::Result<Self> {
        Self::start_with(MockState::new()).await
    }

    pub async fn start_with(state: MockState) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state: Shared = Arc::new(Mutex::new(state));
        let app = Router::new()
            .route("/", post(handle))
            .route("/wallet/{name}", post(handle_wallet))
            .with_state(state.clone());
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });
        Ok(MockYcashd {
            addr,
            state,
            shutdown: Some(tx),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    /// A client for this mock (with the configured credentials, if any).
    pub fn client(&self) -> YcashRpc {
        let auth = match &self.state().auth {
            Some((u, p)) => Auth::UserPass {
                user: u.clone(),
                password: p.clone().into(),
            },
            None => Auth::None,
        };
        YcashRpc::new(self.url(), auth).expect("client builds")
    }

    /// A client of the wallet view `name` ([`MockState::wallet_views`]): one simulated
    /// attestor node of a shared mock.
    pub fn wallet_client(&self, name: &str) -> YcashRpc {
        let auth = match &self.state().auth {
            Some((u, p)) => Auth::UserPass {
                user: u.clone(),
                password: p.clone().into(),
            },
            None => Auth::None,
        };
        YcashRpc::new(format!("http://{}/wallet/{name}", self.addr), auth).expect("client builds")
    }

    /// The state, locked.
    pub fn state(&self) -> MutexGuard<'_, MockState> {
        lock(&self.state)
    }
}

impl Drop for MockYcashd {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_json_prints_amounts_as_numbers() {
        let v = json!({"value": "1.50000000", "txid": "1.5", "vout": [{"amount": "0.00000001"}], "x": {"bondmin": "x"}});
        assert_eq!(
            node_json(&v),
            r#"{"txid":"1.5","value":1.50000000,"vout":[{"amount":0.00000001}],"x":{"bondmin":"x"}}"#
        );
    }

    #[test]
    fn scriptsig_parse() {
        let k = PubKey([2; 33]);
        let sig = mock_set_sig(&k, &Bytes32([9; 32]));
        let mut s = vec![];
        crate::tx::push_data(&mut s, &sig);
        s.push(OP_1);
        let (sigs, sel) = parse_scriptsig(&s).unwrap();
        assert_eq!((sigs.len(), sel), (1, 1));
        assert_eq!(sig_key(&sigs[0]), Some(k));
        assert_eq!(parse_scriptsig(&[0x52]).unwrap(), (vec![], 2));
        assert!(parse_scriptsig(&[0x55]).is_none());
        assert!(parse_scriptsig(&[]).is_none());
    }
}
