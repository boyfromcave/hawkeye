//! The lock policy (plan §4.1, L-policy; NEAR plan §2.1): when a confirmed bridge vault output
//! is a mintable lock. Every attestor evaluates it independently; a lock that fails is never
//! minted.
//!
//! One policy serves either bridge: [`LockPolicy::evaluate_for`] takes the [`BridgeKind`], which
//! selects the vault tag (`WYEC` / `NYEC`) and the destination encoding (an Ethereum address /
//! `"NR1"` ‖ a NEAR account id); every other rule is the same. [`LockPolicy::evaluate`] is the
//! Ethereum bridge's.

use thiserror::Error;

use crate::bridge::BridgeKind;
use crate::bytes::{Hash32, OutPoint};
use crate::eth::EthAddress;
use crate::lock::{Destination, lock_id};
use crate::script::is_op_return;
use crate::template::{VaultParams, parse_vault};

/// One transaction output: value in zatoshi and scriptPubKey.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxOut {
    /// Value in zatoshi.
    pub value: u64,
    /// The scriptPubKey.
    pub script_pubkey: Vec<u8>,
}

/// The facts about a candidate lock the policy needs, as the Ycash adapter observed them.
#[derive(Debug, Clone, Copy)]
pub struct LockFacts<'a> {
    /// The lock transaction's txid, internal byte order.
    pub txid: Hash32,
    /// The index of the candidate V output.
    pub vout: u32,
    /// Every output of the lock transaction, in order.
    pub outputs: &'a [TxOut],
    /// The height of the block that contains the lock transaction.
    pub coin_height: u32,
    /// Confirmations of that block (1 = in the tip).
    pub confirmations: u32,
    /// Whether that block is on the attestor's active chain now.
    pub on_active_chain: bool,
}

/// The operator's lock policy parameters (config, plan §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPolicy {
    /// The attestor set: the V's `setId` and `cancelSetId` (HK-2).
    pub set_id: Hash32,
    /// The configured challenge window `D`, the V's `delay`.
    pub delay: u16,
    /// `MIN_OWNER_AGE`: `ownerHeight − coinHeight` at least this (§3.1).
    pub min_owner_age: u32,
    /// `MIN_LOCK` in zatoshi.
    pub min_lock: u64,
    /// `MAX_LOCK` in zatoshi.
    pub max_lock: u64,
    /// `C_Y`.
    pub min_confirmations: u32,
}

/// A lock that passed the policy: what the mint signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintableLock {
    /// The lock's V output.
    pub outpoint: OutPoint,
    /// `SHA256(outpoint)`.
    pub lock_id: Hash32,
    /// The V's value in zatoshi (= wYEC base units).
    pub amount: u64,
    /// The mint recipient (the destination's last 20 bytes).
    pub to: EthAddress,
    /// The vault's parameters.
    pub vault: VaultParams,
}

/// A lock of either bridge that passed the policy: what the mint signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mintable {
    /// The lock's V output.
    pub outpoint: OutPoint,
    /// `SHA256(outpoint)`.
    pub lock_id: Hash32,
    /// The V's value in zatoshi (= wYEC base units).
    pub amount: u64,
    /// The mint recipient the destination `OP_RETURN` names.
    pub destination: Destination,
    /// The vault's parameters.
    pub vault: VaultParams,
}

/// Why a candidate is not a mintable lock (plan §4.1 rules 1–5).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LockRejection {
    /// The output index is not in the transaction.
    #[error("no output {0}")]
    NoSuchOutput(u32),
    /// Rule 1: the output is not exactly a V.
    #[error("not a vault: {0}")]
    NotVault(crate::Error),
    /// Rule 1: the tag is not the bridge's (`WYEC` Ethereum, `NYEC` NEAR).
    #[error("tag is not the bridge's (WYEC / NYEC)")]
    WrongTag,
    /// Rule 1: `setId` is not the attestor set.
    #[error("setId is not the attestor set")]
    WrongSet,
    /// Rule 1: `cancelSetId` is not the attestor set.
    #[error("cancelSetId is not the attestor set")]
    WrongCancelSet,
    /// Rule 1: `delay` is not the configured window.
    #[error("delay {got} is not the configured {want}")]
    WrongDelay {
        /// The V's delay.
        got: u16,
        /// The configured delay.
        want: u16,
    },
    /// Rule 1: `appHeight` is not 0.
    #[error("appHeight {0} is not 0")]
    AppHeightSet(u32),
    /// Rule 2: the owner branch opens too soon.
    #[error("ownerHeight {owner_height} − lock height {coin_height} < MIN_OWNER_AGE {min}")]
    OwnerAgeTooShort {
        /// The V's `ownerHeight`.
        owner_height: u32,
        /// The lock's height.
        coin_height: u32,
        /// `MIN_OWNER_AGE`.
        min: u32,
    },
    /// Rule 3 (HK-3): the transaction has more than one V output of the bridge's tag.
    #[error("{0} vault outputs of the bridge's tag in the transaction")]
    MultipleVaults(usize),
    /// Rule 3: the transaction has no `OP_RETURN`.
    #[error("no destination OP_RETURN")]
    NoDestination,
    /// Rule 3: the transaction has more than one `OP_RETURN`.
    #[error("{0} OP_RETURN outputs in the transaction")]
    MultipleOpReturns(usize),
    /// Rule 3: the `OP_RETURN` is not a destination.
    #[error("bad destination: {0}")]
    BadDestination(crate::Error),
    /// Rule 4: below `MIN_LOCK`.
    #[error("value {value} < MIN_LOCK {min}")]
    BelowMinLock {
        /// The V's value.
        value: u64,
        /// `MIN_LOCK`.
        min: u64,
    },
    /// Rule 4: above `MAX_LOCK`.
    #[error("value {value} > MAX_LOCK {max}")]
    AboveMaxLock {
        /// The V's value.
        value: u64,
        /// `MAX_LOCK`.
        max: u64,
    },
    /// Rule 5: fewer than `C_Y` confirmations.
    #[error("{got} confirmations < {want}")]
    Unconfirmed {
        /// Confirmations now.
        got: u32,
        /// `C_Y`.
        want: u32,
    },
    /// Rule 5: the block left the active chain.
    #[error("not on the active chain")]
    NotOnActiveChain,
}

impl LockPolicy {
    /// Evaluate rules 1–5 for the Ethereum bridge (`WYEC`, 32-byte address destination) in
    /// order; the first failure is returned.
    pub fn evaluate(&self, f: &LockFacts<'_>) -> Result<MintableLock, LockRejection> {
        let m = self.evaluate_for(BridgeKind::Ethereum, f)?;
        let Destination::Ethereum(to) = m.destination else {
            unreachable!("an Ethereum evaluation parses an Ethereum destination")
        };
        Ok(MintableLock {
            outpoint: m.outpoint,
            lock_id: m.lock_id,
            amount: m.amount,
            to,
            vault: m.vault,
        })
    }

    /// Evaluate rules 1–5 for bridge `kind` in order; the first failure is returned. `kind`
    /// selects the tag of rules 1 and 3 and the destination encoding of rule 3.
    pub fn evaluate_for(
        &self,
        kind: BridgeKind,
        f: &LockFacts<'_>,
    ) -> Result<Mintable, LockRejection> {
        let tag = kind.tag();
        let out = f
            .outputs
            .get(f.vout as usize)
            .ok_or(LockRejection::NoSuchOutput(f.vout))?;
        // 1. the V
        let v = parse_vault(&out.script_pubkey).map_err(LockRejection::NotVault)?;
        if v.tag != tag {
            return Err(LockRejection::WrongTag);
        }
        if v.set_id != self.set_id {
            return Err(LockRejection::WrongSet);
        }
        if v.cancel_set_id != self.set_id {
            return Err(LockRejection::WrongCancelSet);
        }
        if v.delay != self.delay {
            return Err(LockRejection::WrongDelay {
                got: v.delay,
                want: self.delay,
            });
        }
        if v.app_height != 0 {
            return Err(LockRejection::AppHeightSet(v.app_height));
        }
        // 2. minimum owner age
        if v.owner_height.saturating_sub(f.coin_height) < self.min_owner_age
            || v.owner_height < f.coin_height
        {
            return Err(LockRejection::OwnerAgeTooShort {
                owner_height: v.owner_height,
                coin_height: f.coin_height,
                min: self.min_owner_age,
            });
        }
        // 3. one V of the bridge's tag, one destination OP_RETURN
        let vaults = f
            .outputs
            .iter()
            .filter(|o| parse_vault(&o.script_pubkey).is_ok_and(|p| p.tag == tag))
            .count();
        if vaults != 1 {
            return Err(LockRejection::MultipleVaults(vaults));
        }
        let returns: Vec<&TxOut> = f
            .outputs
            .iter()
            .filter(|o| is_op_return(&o.script_pubkey))
            .collect();
        let destination = match returns.as_slice() {
            [] => return Err(LockRejection::NoDestination),
            [one] => Destination::parse(kind, &one.script_pubkey)
                .map_err(LockRejection::BadDestination)?,
            many => return Err(LockRejection::MultipleOpReturns(many.len())),
        };
        // 4. value bounds
        if out.value < self.min_lock {
            return Err(LockRejection::BelowMinLock {
                value: out.value,
                min: self.min_lock,
            });
        }
        if out.value > self.max_lock {
            return Err(LockRejection::AboveMaxLock {
                value: out.value,
                max: self.max_lock,
            });
        }
        // 5. depth and chain
        if f.confirmations < self.min_confirmations {
            return Err(LockRejection::Unconfirmed {
                got: f.confirmations,
                want: self.min_confirmations,
            });
        }
        if !f.on_active_chain {
            return Err(LockRejection::NotOnActiveChain);
        }
        let outpoint = OutPoint::new(f.txid, f.vout);
        Ok(Mintable {
            outpoint,
            lock_id: lock_id(&outpoint),
            amount: out.value,
            destination,
            vault: v,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{destination_script, near_destination_script};
    use crate::near::AccountId;
    use crate::script::{op_return_script, p2pkh_script};
    use crate::template::{TAG_NYEC, TAG_WYEC};

    const SET: Hash32 = [0x5e; 32];
    const TO: EthAddress = EthAddress([0x42; 20]);

    fn policy() -> LockPolicy {
        LockPolicy {
            set_id: SET,
            delay: 6,
            min_owner_age: 1000,
            min_lock: 100,
            max_lock: 1_000_000,
            min_confirmations: 10,
        }
    }

    fn vault() -> VaultParams {
        VaultParams {
            tag: TAG_WYEC,
            set_id: SET,
            cancel_set_id: SET,
            delay: 6,
            owner_height: 1100,
            app_height: 0,
            owner_key: [2; 33],
        }
    }

    fn outputs(v: VaultParams, value: u64) -> Vec<TxOut> {
        vec![
            TxOut {
                value,
                script_pubkey: v.script().unwrap(),
            },
            TxOut {
                value: 0,
                script_pubkey: destination_script(&TO),
            },
            TxOut {
                value: 5000,
                script_pubkey: p2pkh_script(&[1; 20]),
            },
        ]
    }

    fn eval(outs: &[TxOut], conf: u32, active: bool) -> Result<MintableLock, LockRejection> {
        policy().evaluate(&LockFacts {
            txid: [0xab; 32],
            vout: 0,
            outputs: outs,
            coin_height: 100,
            confirmations: conf,
            on_active_chain: active,
        })
    }

    #[test]
    fn accepts_a_good_lock() {
        let m = eval(&outputs(vault(), 5000), 10, true).unwrap();
        assert_eq!(m.amount, 5000);
        assert_eq!(m.to, TO);
        assert_eq!(m.vault, vault());
        assert_eq!(m.lock_id, lock_id(&OutPoint::new([0xab; 32], 0)));
    }

    #[test]
    fn each_rule_rejects() {
        use LockRejection as R;
        let bad = |v: VaultParams| eval(&outputs(v, 5000), 10, true).unwrap_err();
        assert_eq!(
            bad(VaultParams {
                tag: *b"YED\0",
                ..vault()
            }),
            R::WrongTag
        );
        assert_eq!(
            bad(VaultParams {
                set_id: [1; 32],
                ..vault()
            }),
            R::WrongSet
        );
        assert_eq!(
            bad(VaultParams {
                cancel_set_id: [1; 32],
                ..vault()
            }),
            R::WrongCancelSet
        );
        assert_eq!(
            bad(VaultParams {
                delay: 7,
                ..vault()
            }),
            R::WrongDelay { got: 7, want: 6 }
        );
        assert_eq!(
            bad(VaultParams {
                app_height: 5,
                ..vault()
            }),
            R::AppHeightSet(5)
        );
        assert!(matches!(
            bad(VaultParams {
                owner_height: 1099,
                ..vault()
            }),
            R::OwnerAgeTooShort { .. }
        ));
        assert!(matches!(
            bad(VaultParams {
                owner_height: 50,
                ..vault()
            }),
            R::OwnerAgeTooShort { .. }
        ));

        assert_eq!(
            eval(&outputs(vault(), 99), 10, true).unwrap_err(),
            R::BelowMinLock {
                value: 99,
                min: 100
            }
        );
        assert!(matches!(
            eval(&outputs(vault(), 1_000_001), 10, true).unwrap_err(),
            R::AboveMaxLock { .. }
        ));
        assert_eq!(
            eval(&outputs(vault(), 5000), 9, true).unwrap_err(),
            R::Unconfirmed { got: 9, want: 10 }
        );
        assert_eq!(
            eval(&outputs(vault(), 5000), 10, false).unwrap_err(),
            R::NotOnActiveChain
        );

        let mut o = outputs(vault(), 5000);
        o[0].script_pubkey = p2pkh_script(&[0; 20]);
        assert!(matches!(eval(&o, 10, true).unwrap_err(), R::NotVault(_)));

        let mut o = outputs(vault(), 5000);
        o.push(o[0].clone());
        assert_eq!(eval(&o, 10, true).unwrap_err(), R::MultipleVaults(2));

        let mut o = outputs(vault(), 5000);
        o.remove(1);
        assert_eq!(eval(&o, 10, true).unwrap_err(), R::NoDestination);

        let mut o = outputs(vault(), 5000);
        o.push(TxOut {
            value: 0,
            script_pubkey: op_return_script(b"x"),
        });
        assert_eq!(eval(&o, 10, true).unwrap_err(), R::MultipleOpReturns(2));

        let mut o = outputs(vault(), 5000);
        o[1].script_pubkey = op_return_script(&[0x11; 32]);
        assert!(matches!(
            eval(&o, 10, true).unwrap_err(),
            R::BadDestination(_)
        ));

        let o = outputs(vault(), 5000);
        let f = LockFacts {
            txid: [0; 32],
            vout: 9,
            outputs: &o,
            coin_height: 1,
            confirmations: 99,
            on_active_chain: true,
        };
        assert_eq!(policy().evaluate(&f).unwrap_err(), R::NoSuchOutput(9));
    }

    #[test]
    fn a_second_vault_of_another_tag_is_allowed() {
        let mut o = outputs(vault(), 5000);
        o.push(TxOut {
            value: 1,
            script_pubkey: VaultParams {
                tag: *b"YED\0",
                ..vault()
            }
            .script()
            .unwrap(),
        });
        assert!(eval(&o, 10, true).is_ok());
    }

    fn near_outputs(v: VaultParams, value: u64, to: &str) -> Vec<TxOut> {
        let mut o = outputs(v, value);
        o[1].script_pubkey = near_destination_script(&AccountId::parse(to).unwrap());
        o
    }

    fn eval_near(outs: &[TxOut]) -> Result<Mintable, LockRejection> {
        policy().evaluate_for(
            BridgeKind::Near,
            &LockFacts {
                txid: [0xab; 32],
                vout: 0,
                outputs: outs,
                coin_height: 100,
                confirmations: 10,
                on_active_chain: true,
            },
        )
    }

    #[test]
    fn near_locks() {
        use LockRejection as R;
        let nv = VaultParams {
            tag: TAG_NYEC,
            ..vault()
        };
        let m = eval_near(&near_outputs(nv, 5000, "alice.near")).unwrap();
        assert_eq!(
            m.destination,
            Destination::Near(AccountId::parse("alice.near").unwrap())
        );
        assert_eq!(m.amount, 5000);
        assert_eq!(m.lock_id, lock_id(&OutPoint::new([0xab; 32], 0)));
        assert_eq!(m.vault, nv);
        // implicit accounts are destinations too
        let implicit = "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de";
        assert!(eval_near(&near_outputs(nv, 5000, implicit)).is_ok());
        assert!(eval_near(&near_outputs(nv, 5000, &format!("0x{}", "ab".repeat(20)))).is_ok());

        // a WYEC vault is not a NEAR lock, and an NYEC vault is not an Ethereum one
        assert_eq!(
            eval_near(&near_outputs(vault(), 5000, "alice.near")).unwrap_err(),
            R::WrongTag
        );
        assert_eq!(eval(&outputs(nv, 5000), 10, true).unwrap_err(), R::WrongTag);
        // an Ethereum destination on an NYEC vault, an NR1 destination on a WYEC vault
        assert!(matches!(
            eval_near(&outputs(nv, 5000)).unwrap_err(),
            R::BadDestination(_)
        ));
        assert!(matches!(
            eval(&near_outputs(vault(), 5000, "alice.near"), 10, true).unwrap_err(),
            R::BadDestination(_)
        ));
        // an invalid account id is refused (never minted; the owner recovers)
        let mut o = near_outputs(nv, 5000, "alice.near");
        o[1].script_pubkey = op_return_script(b"NR1Alice.near");
        assert!(matches!(eval_near(&o).unwrap_err(), R::BadDestination(_)));
        // HK-3 counts vaults of the bridge's tag only
        let mut o = near_outputs(nv, 5000, "alice.near");
        o.push(TxOut {
            value: 1,
            script_pubkey: vault().script().unwrap(),
        });
        assert!(eval_near(&o).is_ok());
        o.push(o[0].clone());
        assert_eq!(eval_near(&o).unwrap_err(), R::MultipleVaults(2));
        // the Ethereum path through evaluate_for is evaluate's
        let e = policy()
            .evaluate_for(
                BridgeKind::Ethereum,
                &LockFacts {
                    txid: [0xab; 32],
                    vout: 0,
                    outputs: &outputs(vault(), 5000),
                    coin_height: 100,
                    confirmations: 10,
                    on_active_chain: true,
                },
            )
            .unwrap();
        assert_eq!(e.destination, Destination::Ethereum(TO));
        assert_eq!(TAG_WYEC, BridgeKind::Ethereum.tag());
    }
}
