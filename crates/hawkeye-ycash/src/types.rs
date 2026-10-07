//! The vault primitive's RPC shapes, field for field as `ycash-dd/doc/vault-rpc.md` ("Shapes"),
//! `doc/vault-rpc-contract.json` and `src/rpc/vault.cpp` define them. Field names are the wire
//! names. `yec` fields are [`Amount`], `zat` fields `i64`, `hash` fields [`Hash256`] (txids and set
//! ids, reversed on the wire) or [`Bytes32`] (sighashes, `recipienthash`, `vaulthash`, raw order).

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::amount::Amount;
use crate::primitives::{Bytes32, Hash256, HexBytes, OutPoint, PubKey, SetId, Txid};

// ---------------------------------------------------------------------------------- shapes

/// `SetParams`: a set's `SET_CREATE` parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetParams {
    pub seats: u32,
    pub unlockthreshold: u32,
    pub cancelthreshold: u32,
    pub slashthreshold: u32,
    pub open: bool,
    pub ratelimitbps: u32,
    pub ratewindow: u32,
    pub livenesswindow: u32,
    pub bondmin: Amount,
    pub bondlockmin: u32,
    pub maturity: u32,
    pub admitkey: PubKey,
}

/// `Set`: one set's parameters and state (`set_list` rows).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Set {
    pub setid: SetId,
    /// The height the predicates were evaluated at (default: the next block).
    pub height: u32,
    #[serde(flatten)]
    pub params: SetParams,
    pub createheight: u32,
    /// 0 = no wind-down.
    pub winddownheight: u32,
    pub lockedvalue: Amount,
    pub epoch: i64,
    pub epochbasis: Amount,
    pub epochused: Amount,
    /// Present only when the set is rate limited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlockavailable: Option<Amount>,
    pub members: u32,
    pub active: u32,
    pub current: u32,
    pub dormant: bool,
    pub released: bool,
}

/// `set_getinfo`'s result: `Set` plus `memberlist`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetInfo {
    #[serde(flatten)]
    pub set: Set,
    pub memberlist: Vec<Member>,
}

/// `Member.status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberStatus {
    Active,
    Removed,
    Ejected,
    Withdrawn,
}

/// `Member`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub key: PubKey,
    pub status: MemberStatus,
    pub current: bool,
    pub live: bool,
    pub joinheight: u32,
    pub lastact: u32,
    pub bondoutpoint: OutPoint,
    pub bondvalue: Amount,
    pub bondlocktime: u32,
    pub bondfrozen: bool,
    /// This node's wallet holds the key.
    pub wallet: bool,
}

/// `VaultFields`: a V template's parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFields {
    /// The 4-byte tag in hex (`57594543` for `WYEC`).
    pub tag: HexBytes,
    pub tagtext: String,
    pub setid: SetId,
    pub cancelsetid: SetId,
    pub delay: u32,
    pub ownerheight: u32,
    pub appheight: u32,
    pub ownerkey: PubKey,
}

/// `IntentFields`: an I template's parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentFields {
    pub tag: HexBytes,
    pub tagtext: String,
    pub setid: SetId,
    pub cancelsetid: SetId,
    pub delay: u32,
    pub ownerkey: PubKey,
    /// SHA256 of the recipient script (raw order).
    pub recipienthash: Bytes32,
    /// SHA256 of the originating vault's script (raw order).
    pub vaulthash: Bytes32,
}

/// A `vault_list` row of kind `vault`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultOut {
    pub txid: Txid,
    pub vout: u32,
    pub outpoint: OutPoint,
    pub value: Amount,
    pub valuezat: i64,
    pub height: u32,
    pub script: HexBytes,
    #[serde(flatten)]
    pub fields: VaultFields,
    /// The owner key is in this wallet.
    pub wallet: bool,
}

/// A `vault_list` row of kind `intent`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentOutput {
    pub txid: Txid,
    pub vout: u32,
    pub outpoint: OutPoint,
    pub value: Amount,
    pub valuezat: i64,
    pub height: u32,
    pub script: HexBytes,
    #[serde(flatten)]
    pub fields: IntentFields,
    /// `height + delay`.
    pub matureheight: u32,
    pub mature: bool,
    /// The next block is still inside the cancel window.
    pub cancellable: bool,
    /// The script of the vault it was unlocked from.
    pub origin: HexBytes,
    pub wallet: bool,
}

/// `TemplateOut`: a `vault_list` row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum TemplateOut {
    Vault(VaultOut),
    Intent(IntentOutput),
}

impl TemplateOut {
    pub fn outpoint(&self) -> OutPoint {
        match self {
            TemplateOut::Vault(v) => v.outpoint,
            TemplateOut::Intent(i) => i.outpoint,
        }
    }
    pub fn valuezat(&self) -> i64 {
        match self {
            TemplateOut::Vault(v) => v.valuezat,
            TemplateOut::Intent(i) => i.valuezat,
        }
    }
    pub fn height(&self) -> u32 {
        match self {
            TemplateOut::Vault(v) => v.height,
            TemplateOut::Intent(i) => i.height,
        }
    }
    pub fn script(&self) -> &HexBytes {
        match self {
            TemplateOut::Vault(v) => &v.script,
            TemplateOut::Intent(i) => &i.script,
        }
    }
    pub fn as_vault(&self) -> Option<&VaultOut> {
        match self {
            TemplateOut::Vault(v) => Some(v),
            TemplateOut::Intent(_) => None,
        }
    }
    pub fn as_intent(&self) -> Option<&IntentOutput> {
        match self {
            TemplateOut::Intent(i) => Some(i),
            TemplateOut::Vault(_) => None,
        }
    }
}

/// `ActType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActType {
    Create,
    Join,
    Heartbeat,
    Remove,
    Equivocation,
    Winddown,
}

impl ActType {
    pub fn as_str(self) -> &'static str {
        match self {
            ActType::Create => "create",
            ActType::Join => "join",
            ActType::Heartbeat => "heartbeat",
            ActType::Remove => "remove",
            ActType::Equivocation => "equivocation",
            ActType::Winddown => "winddown",
        }
    }
}

/// `Proof`: a `SET_EQUIVOCATION` proof (two set signatures by one member over two different
/// spends of `prevout`). Roles 1 unlock / 2 cancel; sighashes raw, signatures 65-byte recoverable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub setid: SetId,
    pub prevout: OutPoint,
    pub rolea: u8,
    pub sighasha: Bytes32,
    pub siga: HexBytes,
    pub roleb: u8,
    pub sighashb: Bytes32,
    pub sigb: HexBytes,
}

/// `ActBody`: a decoded act (`vault_decodescript` of a `YV` OP_RETURN).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "acttype", rename_all = "lowercase")]
pub enum ActBody {
    Create(SetParams),
    Join {
        setid: SetId,
        memberkey: PubKey,
        bondlocktime: u32,
        bondvout: u32,
    },
    Heartbeat {
        setid: SetId,
        memberkey: PubKey,
    },
    /// `burn` is an integer (0/1) here, a bool in `set_buildact`'s parameters.
    Remove {
        setid: SetId,
        memberkey: PubKey,
        burn: u8,
    },
    Equivocation(Proof),
    Winddown {
        setid: SetId,
    },
}

/// `ActResult`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActResult {
    pub hex: HexBytes,
    #[serde(rename = "type")]
    pub acttype: ActType,
    pub complete: bool,
    pub signatures: u32,
    /// Signatures the act needs; `-1` from `set_signact` of a join whose member key is not in
    /// the wallet (the member must sign first, src/rpc/vault.cpp:767).
    pub required: i32,
}

/// One set signature of a `SetSigResult`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSig {
    pub key: PubKey,
    pub sig: HexBytes,
}

/// `SetSigResult`: `set_signunlock` / `set_signcancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSigResult {
    pub hex: HexBytes,
    pub complete: bool,
    pub signatures: u32,
    pub required: u32,
    /// The template input's ZIP-243 sighash (raw order), as `set_equivocation` takes it.
    pub sighash: Bytes32,
    pub setsigs: Vec<SetSig>,
}

/// `IntentOut`: an intent a build created.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentOut {
    pub vout: u32,
    pub amount: Amount,
    /// The recipient script.
    pub recipient: HexBytes,
    pub recipienthash: Bytes32,
}

/// Where a `Recipient` pays: exactly one of `address` or `script`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecipientTo {
    Address(String),
    Script(HexBytes),
}

/// `Recipient` = `{"address"?: address, "script"?: hex, "amount": yec}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub to: RecipientTo,
    pub amount: Amount,
}

impl Recipient {
    pub fn address(address: impl Into<String>, amount: Amount) -> Self {
        Recipient {
            to: RecipientTo::Address(address.into()),
            amount,
        }
    }
    pub fn script(script: impl Into<Vec<u8>>, amount: Amount) -> Self {
        Recipient {
            to: RecipientTo::Script(HexBytes(script.into())),
            amount,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RecipientWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    script: Option<HexBytes>,
    amount: Amount,
}

impl Serialize for Recipient {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (address, script) = match &self.to {
            RecipientTo::Address(a) => (Some(a.clone()), None),
            RecipientTo::Script(h) => (None, Some(h.clone())),
        };
        RecipientWire {
            address,
            script,
            amount: self.amount,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Recipient {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = RecipientWire::deserialize(d)?;
        let to = match (w.address, w.script) {
            (Some(a), None) => RecipientTo::Address(a),
            (None, Some(s)) => RecipientTo::Script(s),
            _ => {
                return Err(D::Error::custom(
                    "a recipient needs exactly one of \"address\" or \"script\"",
                ));
            }
        };
        Ok(Recipient {
            to,
            amount: w.amount,
        })
    }
}

// ---------------------------------------------------------------------------------- read RPCs

/// `vault_getinfo`'s `dbtip`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbTip {
    pub hash: Hash256,
    pub height: u32,
}

/// `vault_getinfo`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInfo {
    /// `"6d5b7a31"`.
    pub branchid: String,
    /// -1 if unscheduled.
    pub activationheight: i64,
    /// Active at the next block.
    pub active: bool,
    /// The tip.
    pub height: i64,
    /// The block the set state is at (null before the first active block).
    pub dbtip: Option<DbTip>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vaults: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intents: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockedvalue: Option<Amount>,
    /// SHA256d over every state record: equal on two nodes on the same chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statehash: Option<Hash256>,
}

/// `vault_list`'s kind filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TemplateKind {
    Vault,
    Intent,
}

/// `vault_list`'s filter (every field optional; `setid` matches either set of the template).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultListFilter {
    /// 1–4 ASCII characters or 8 hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setid: Option<SetId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<PubKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<TemplateKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mine: Option<bool>,
}

/// An act signature in a decoded act.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActSigOut {
    pub sig: HexBytes,
}

/// A decoded `YV` act.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedAct {
    Act {
        body: Box<ActBody>,
        signatures: Vec<ActSigOut>,
        payload: HexBytes,
    },
    /// The act does not decode; `error` is the reason.
    Error { error: String },
}

/// `vault_decodescript`'s result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedScript {
    Vault(VaultFields),
    Intent(IntentFields),
    /// A template skeleton with a non-minimal push or an out-of-range field.
    Malformed,
    Act(DecodedAct),
    /// A member bond redeem script, with its P2SH `scriptpubkey` and `address`.
    Bond {
        locktime: u32,
        memberkey: PubKey,
        scriptpubkey: HexBytes,
        address: String,
    },
    None,
}

fn insert_all(o: &mut Map<String, Value>, v: Value) -> Result<(), serde_json::Error> {
    match v {
        Value::Object(m) => {
            o.extend(m);
            Ok(())
        }
        _ => Err(serde_json::Error::custom("expected an object")),
    }
}

impl Serialize for DecodedScript {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let mut o = Map::new();
        let r: Result<(), serde_json::Error> = (|| {
            match self {
                DecodedScript::Vault(f) => {
                    o.insert("type".into(), "vault".into());
                    insert_all(&mut o, serde_json::to_value(f)?)?;
                }
                DecodedScript::Intent(f) => {
                    o.insert("type".into(), "intent".into());
                    insert_all(&mut o, serde_json::to_value(f)?)?;
                }
                DecodedScript::Malformed => {
                    o.insert("type".into(), "malformed".into());
                }
                DecodedScript::Act(DecodedAct::Error { error }) => {
                    o.insert("type".into(), "act".into());
                    o.insert("error".into(), error.clone().into());
                }
                DecodedScript::Act(DecodedAct::Act {
                    body,
                    signatures,
                    payload,
                }) => {
                    o.insert("type".into(), "act".into());
                    insert_all(&mut o, serde_json::to_value(body)?)?;
                    o.insert("signatures".into(), serde_json::to_value(signatures)?);
                    o.insert("payload".into(), serde_json::to_value(payload)?);
                }
                DecodedScript::Bond {
                    locktime,
                    memberkey,
                    scriptpubkey,
                    address,
                } => {
                    o.insert("type".into(), "bond".into());
                    o.insert("locktime".into(), (*locktime).into());
                    o.insert("memberkey".into(), serde_json::to_value(memberkey)?);
                    o.insert("scriptpubkey".into(), serde_json::to_value(scriptpubkey)?);
                    o.insert("address".into(), address.clone().into());
                }
                DecodedScript::None => {
                    o.insert("type".into(), "none".into());
                }
            }
            Ok(())
        })();
        r.map_err(S::Error::custom)?;
        Value::Object(o).serialize(s)
    }
}

impl<'de> Deserialize<'de> for DecodedScript {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut o = Map::<String, Value>::deserialize(d)?;
        let ty = match o.remove("type") {
            Some(Value::String(t)) => t,
            _ => return Err(D::Error::custom("vault_decodescript: no \"type\"")),
        };
        fn de<T: serde::de::DeserializeOwned, E: serde::de::Error>(
            v: Map<String, Value>,
        ) -> Result<T, E> {
            serde_json::from_value(Value::Object(v)).map_err(E::custom)
        }
        Ok(match ty.as_str() {
            "vault" => DecodedScript::Vault(de::<_, D::Error>(o)?),
            "intent" => DecodedScript::Intent(de::<_, D::Error>(o)?),
            "malformed" => DecodedScript::Malformed,
            "none" => DecodedScript::None,
            "bond" => {
                #[derive(Deserialize)]
                struct B {
                    locktime: u32,
                    memberkey: PubKey,
                    scriptpubkey: HexBytes,
                    address: String,
                }
                let b: B = de::<_, D::Error>(o)?;
                DecodedScript::Bond {
                    locktime: b.locktime,
                    memberkey: b.memberkey,
                    scriptpubkey: b.scriptpubkey,
                    address: b.address,
                }
            }
            "act" => {
                if let Some(e) = o.remove("error") {
                    let error = e
                        .as_str()
                        .ok_or_else(|| D::Error::custom("act error is not a string"))?
                        .to_owned();
                    DecodedScript::Act(DecodedAct::Error { error })
                } else {
                    let signatures = o
                        .remove("signatures")
                        .ok_or_else(|| D::Error::missing_field("signatures"))?;
                    let payload = o
                        .remove("payload")
                        .ok_or_else(|| D::Error::missing_field("payload"))?;
                    DecodedScript::Act(DecodedAct::Act {
                        body: Box::new(de::<_, D::Error>(o)?),
                        signatures: serde_json::from_value(signatures).map_err(D::Error::custom)?,
                        payload: serde_json::from_value(payload).map_err(D::Error::custom)?,
                    })
                }
            }
            other => {
                return Err(D::Error::custom(format!(
                    "vault_decodescript: unknown type {other:?}"
                )));
            }
        })
    }
}

// ---------------------------------------------------------------------------------- act RPCs

/// `set_create`'s parameters (and `set_buildact "create"`'s). Unset fields take the node's
/// defaults: `cancelthreshold` 1, `slashthreshold` = `unlockthreshold`, `open` false,
/// `ratelimitbps` 0, `ratewindow` 144, `livenesswindow` 1000, `bondmin` 1, `bondlockmin` 0,
/// `maturity` 0, `admitkey` a new wallet key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetCreateParams {
    pub seats: u32,
    pub unlockthreshold: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelthreshold: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slashthreshold: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratelimitbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratewindow: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub livenesswindow: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bondmin: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bondlockmin: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maturity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitkey: Option<PubKey>,
}

/// `set_create`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetCreateResult {
    pub txid: Txid,
    /// = `txid`.
    pub setid: SetId,
    pub admitkey: PubKey,
}

/// `set_join`'s result: `ActResult` plus `txid` (when complete and broadcast), `memberkey` and
/// `bondoutpoint`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetJoinResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<Txid>,
    #[serde(flatten)]
    pub act: ActResult,
    pub memberkey: PubKey,
    pub bondoutpoint: OutPoint,
}

/// `set_heartbeat`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResult {
    pub txid: Txid,
    pub memberkey: PubKey,
}

/// `set_buildact`'s act and parameters (type is the first parameter, the object the second).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildAct {
    Create(SetCreateParams),
    Join {
        setid: SetId,
        bondamount: Amount,
        bondlocktime: u32,
        memberkey: Option<PubKey>,
    },
    Heartbeat {
        setid: SetId,
        memberkey: PubKey,
    },
    /// `burn`: freeze the bond (a bool on this side; the decoded act carries 0/1).
    Remove {
        setid: SetId,
        memberkey: PubKey,
        burn: bool,
    },
    Equivocation(Proof),
    Winddown {
        setid: SetId,
    },
}

impl BuildAct {
    pub fn act_type(&self) -> ActType {
        match self {
            BuildAct::Create(_) => ActType::Create,
            BuildAct::Join { .. } => ActType::Join,
            BuildAct::Heartbeat { .. } => ActType::Heartbeat,
            BuildAct::Remove { .. } => ActType::Remove,
            BuildAct::Equivocation(_) => ActType::Equivocation,
            BuildAct::Winddown { .. } => ActType::Winddown,
        }
    }

    /// The `params` object.
    pub fn params(&self) -> serde_json::Result<Value> {
        use serde_json::json;
        Ok(match self {
            BuildAct::Create(p) => serde_json::to_value(p)?,
            BuildAct::Join {
                setid,
                bondamount,
                bondlocktime,
                memberkey,
            } => {
                let mut v =
                    json!({"setid": setid, "bondamount": bondamount, "bondlocktime": bondlocktime});
                if let Some(k) = memberkey {
                    v["memberkey"] = serde_json::to_value(k)?;
                }
                v
            }
            BuildAct::Heartbeat { setid, memberkey } => {
                json!({"setid": setid, "memberkey": memberkey})
            }
            BuildAct::Remove {
                setid,
                memberkey,
                burn,
            } => json!({"setid": setid, "memberkey": memberkey, "burn": burn}),
            BuildAct::Equivocation(p) => serde_json::to_value(p)?,
            BuildAct::Winddown { setid } => json!({"setid": setid}),
        })
    }
}

// ---------------------------------------------------------------------------------- vault RPCs

/// `vault_lock`'s parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultLockParams {
    /// 1–4 ASCII characters or 8 hex digits (`"WYEC"`).
    pub tag: String,
    pub setid: SetId,
    /// Default: `setid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelsetid: Option<SetId>,
    /// 1–65535.
    pub delay: u32,
    pub ownerheight: u32,
    /// Default 0 (no APP branch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appheight: Option<u32>,
    pub amount: Amount,
    /// Default: a new wallet key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownerkey: Option<PubKey>,
}

/// `vault_lock`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultLockResult {
    pub txid: Txid,
    /// Always 0.
    pub vout: u32,
    pub outpoint: OutPoint,
    pub script: HexBytes,
    pub ownerkey: PubKey,
}

/// `vault_buildunlock`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildUnlockResult {
    /// The unsigned UNLOCK spend: template input `vin[0]` with an empty scriptSig, fee inputs
    /// unsigned, intents, the re-lock, change.
    pub hex: HexBytes,
    pub intents: Vec<IntentOut>,
    /// The set's `unlockthreshold`.
    pub required: u32,
}

/// `vault_buildcancel`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildCancelResult {
    pub hex: HexBytes,
    pub required: u32,
    pub cancelsetid: SetId,
    /// The last height a cancel can confirm at.
    pub deadline: u32,
    /// false: the intent is still in the mempool.
    pub intentconfirmed: bool,
}

/// `vault_ownerspend`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerSpendResult {
    pub txid: Txid,
    /// 2 (owner branch after `ownerheight`) or 3 (set released).
    pub selector: u8,
}

/// `vault_app`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppResult {
    pub hex: HexBytes,
    pub intents: Vec<IntentOut>,
}
