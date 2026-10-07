//! Intent classification (plan §3.2, HK-4, §5.3): every `WYEC` intent seen on Ycash is matched
//! to a finalized burn or a roll through its `HKB1` memo, or it is unmatched and gets cancelled.
//!
//! The matcher is pure: the engine supplies the intent's transaction outputs, the V it spent (for
//! rolls), and a lookup of burns with their consumption state from its ledger. Consumption ("a
//! burn is consumed by the first intent carrying its memo that is mined and not cancelled") is
//! the engine's bookkeeping; the matcher only reads it.

use crate::bytes::Hash32;
use crate::memo::{Deployment, HawkeyeMemo, MemoKind, is_memo_script, parse_memo_script};
use crate::policy::TxOut;
use crate::recipient::YcashRecipient;
use crate::template::{IntentParams, TAG_WYEC, VaultParams};

/// A finalized `BurnToYcash` event as the ledger holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Burn {
    /// The burn nonce.
    pub nonce: u64,
    /// The Ethereum transaction hash.
    pub tx_hash: Hash32,
    /// The amount in wYEC base units (= zatoshi).
    pub amount: u64,
    /// The raw `ycashRecipient` bytes32.
    pub recipient: [u8; 32],
    /// The intent that consumed it, if any.
    pub consumed_by: Option<Consumer>,
}

/// The intent that consumed a burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Consumer {
    /// The consuming intent's txid (internal order).
    pub txid: Hash32,
    /// The Ycash height at which that intent was first seen (mempool or block).
    pub first_seen: u32,
}

/// An intent observed on Ycash (in the mempool or a block).
#[derive(Debug, Clone, Copy)]
pub struct ObservedIntent<'a> {
    /// The unlock transaction's txid (internal order).
    pub txid: Hash32,
    /// The Ycash height at which it was first seen.
    pub first_seen: u32,
    /// The intent output's parameters.
    pub intent: &'a IntentParams,
    /// The intent output's value in zatoshi.
    pub value: u64,
    /// Every output of the unlock transaction.
    pub outputs: &'a [TxOut],
    /// The V the unlock spent, when known (needed to verify a roll).
    pub spent_vault: Option<&'a VaultParams>,
}

/// The configuration the matcher checks against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchContext {
    /// The bridge deployment memos must name.
    pub deployment: Deployment,
    /// The attestor set (intents of other sets are foreign).
    pub set_id: Hash32,
    /// `TAKEOVER` blocks (§5.2): two intents for one burn first seen within this many blocks of
    /// each other are a benign race.
    pub takeover: u32,
    /// The least `ownerHeight` a roll's new vault may have (the engine passes
    /// `tip + MIN_OWNER_AGE`).
    pub min_roll_owner_height: u32,
}

/// Why an intent is unmatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmatched {
    /// The unlock carries no `HKB1` memo.
    NoMemo,
    /// More than one memo (HK-8: one burn ↔ one intent).
    MultipleMemos,
    /// A memo that claims `HKB1` and does not decode.
    MalformedMemo,
    /// The memo names another deployment (chain id or bridge).
    WrongDeployment,
    /// The memo names a burn nonce the ledger does not have as finalized, or whose txhash
    /// differs.
    UnknownBurn,
    /// The burn was already consumed by another intent.
    ConsumedBurn {
        /// The consuming intent.
        by: Consumer,
        /// Both intents first seen within `TAKEOVER` blocks: cancel, but do not slash.
        benign_race: bool,
    },
    /// The intent's value differs from the burn's amount.
    WrongValue {
        /// The burn's amount.
        expected: u64,
        /// The intent's value.
        got: u64,
    },
    /// The burn's recipient does not decode (an orphaned burn is never released, §3.4).
    OrphanedBurn,
    /// The intent's `recipientHash` is not the burn recipient's.
    WrongRecipient,
    /// A roll memo without the spent V, or one that does not rebuild to the intent's
    /// recipient, or whose vault does not hash to the intent's `vaultHash`.
    BadRoll,
    /// A roll whose new `ownerHeight` is below `min_roll_owner_height`.
    RollTooShort {
        /// The new vault's `ownerHeight`.
        owner_height: u32,
    },
}

impl Unmatched {
    /// Whether the signer of this intent should face a slash case (§2.3): every unmatched
    /// intent is cancelled, but a benign race is not slashed.
    pub fn slashable(&self) -> bool {
        !matches!(
            self,
            Self::ConsumedBurn {
                benign_race: true,
                ..
            }
        )
    }
}

/// The classification of an observed intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Not a `WYEC` intent of the attestor set: not ours to judge.
    Foreign,
    /// Pays finalized burn `nonce` (value and recipient checked).
    MatchedBurn {
        /// The burn nonce.
        nonce: u64,
    },
    /// A roll into `new_vault` (recipient checked).
    MatchedRoll {
        /// The vault the release will create.
        new_vault: VaultParams,
    },
    /// Cancel it.
    Unmatched(Unmatched),
}

/// Two intents for one burn first seen `a` and `b` are a benign race if within `takeover`
/// blocks of each other (§5.2).
pub fn is_benign_race(a: u32, b: u32, takeover: u32) -> bool {
    a.abs_diff(b) <= takeover
}

/// Classify an observed intent (§3.2). `lookup` returns the finalized burn with a nonce.
pub fn classify_intent(
    ctx: &MatchContext,
    obs: &ObservedIntent<'_>,
    lookup: impl Fn(u64) -> Option<Burn>,
) -> Classification {
    use Classification::Unmatched as U;
    if obs.intent.tag != TAG_WYEC
        || obs.intent.set_id != ctx.set_id
        || obs.intent.cancel_set_id != ctx.set_id
    {
        return Classification::Foreign;
    }
    let memo_outputs: Vec<&TxOut> = obs
        .outputs
        .iter()
        .filter(|o| is_memo_script(&o.script_pubkey))
        .collect();
    let memo: HawkeyeMemo = match memo_outputs.as_slice() {
        [] => return U(Unmatched::NoMemo),
        [one] => match parse_memo_script(&one.script_pubkey) {
            Ok(Some(m)) => m,
            _ => return U(Unmatched::MalformedMemo),
        },
        _ => return U(Unmatched::MultipleMemos),
    };
    if memo.deployment != ctx.deployment {
        return U(Unmatched::WrongDeployment);
    }
    match memo.kind {
        MemoKind::BurnRelease => {
            let Some(burn) = lookup(memo.reference).filter(|b| b.tx_hash == memo.data) else {
                return U(Unmatched::UnknownBurn);
            };
            if let Some(by) = burn.consumed_by.filter(|c| c.txid != obs.txid) {
                return U(Unmatched::ConsumedBurn {
                    by,
                    benign_race: is_benign_race(by.first_seen, obs.first_seen, ctx.takeover),
                });
            }
            if obs.value != burn.amount {
                return U(Unmatched::WrongValue {
                    expected: burn.amount,
                    got: obs.value,
                });
            }
            let Ok(recipient) = YcashRecipient::from_bytes32(&burn.recipient) else {
                return U(Unmatched::OrphanedBurn);
            };
            if recipient.recipient_hash() != obs.intent.recipient_hash {
                return U(Unmatched::WrongRecipient);
            }
            Classification::MatchedBurn { nonce: burn.nonce }
        }
        MemoKind::Roll => {
            let Some(spent) = obs.spent_vault else {
                return U(Unmatched::BadRoll);
            };
            if spent.script_hash().ok() != Some(obs.intent.vault_hash) {
                return U(Unmatched::BadRoll);
            }
            let Ok(new_vault) = memo.rolled_vault(spent) else {
                return U(Unmatched::BadRoll);
            };
            if memo.data != obs.intent.recipient_hash {
                return U(Unmatched::BadRoll);
            }
            if new_vault.owner_height < ctx.min_roll_owner_height {
                return U(Unmatched::RollTooShort {
                    owner_height: new_vault.owner_height,
                });
            }
            Classification::MatchedRoll { new_vault }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::EthAddress;
    use crate::script::op_return_script;
    use crate::template::intent_for;

    const SET: Hash32 = [0x5e; 32];

    fn ctx() -> MatchContext {
        MatchContext {
            deployment: Deployment {
                chain_id: 31337,
                bridge: EthAddress([0xb0; 20]),
            },
            set_id: SET,
            takeover: 3,
            min_roll_owner_height: 5000,
        }
    }

    fn vault() -> VaultParams {
        VaultParams {
            tag: TAG_WYEC,
            set_id: SET,
            cancel_set_id: SET,
            delay: 6,
            owner_height: 1000,
            app_height: 0,
            owner_key: [2; 33],
        }
    }

    fn recipient() -> YcashRecipient {
        YcashRecipient::p2pkh([0x77; 20])
    }

    fn burn(consumed_by: Option<Consumer>) -> Burn {
        Burn {
            nonce: 9,
            tx_hash: [0xee; 32],
            amount: 5000,
            recipient: recipient().to_bytes32(),
            consumed_by,
        }
    }

    struct Case {
        intent: IntentParams,
        outputs: Vec<TxOut>,
        value: u64,
    }

    impl Case {
        fn burn_release(memo: HawkeyeMemo) -> Self {
            Self::with(
                intent_for(&vault(), &recipient().script()).unwrap(),
                memo,
                5000,
            )
        }
        fn with(intent: IntentParams, memo: HawkeyeMemo, value: u64) -> Self {
            Self {
                outputs: vec![
                    TxOut {
                        value,
                        script_pubkey: intent.script().unwrap(),
                    },
                    TxOut {
                        value: 0,
                        script_pubkey: memo.to_script(),
                    },
                ],
                intent,
                value,
            }
        }
        fn classify(&self, first_seen: u32, burns: &[Burn]) -> Classification {
            let v = vault();
            classify_intent(
                &ctx(),
                &ObservedIntent {
                    txid: [0x01; 32],
                    first_seen,
                    intent: &self.intent,
                    value: self.value,
                    outputs: &self.outputs,
                    spent_vault: Some(&v),
                },
                |n| burns.iter().copied().find(|b| b.nonce == n),
            )
        }
    }

    fn memo9() -> HawkeyeMemo {
        HawkeyeMemo::burn_release(ctx().deployment, 9, [0xee; 32])
    }

    #[test]
    fn matched_burn() {
        let c = Case::burn_release(memo9());
        assert_eq!(
            c.classify(10, &[burn(None)]),
            Classification::MatchedBurn { nonce: 9 }
        );
        // consumed by this very intent is still a match
        let me = Consumer {
            txid: [0x01; 32],
            first_seen: 10,
        };
        assert_eq!(
            c.classify(10, &[burn(Some(me))]),
            Classification::MatchedBurn { nonce: 9 }
        );
    }

    #[test]
    fn unmatched_reasons() {
        use Classification::Unmatched as U;
        let c = Case::burn_release(memo9());
        assert_eq!(c.classify(10, &[]), U(Unmatched::UnknownBurn));
        let other_hash = Burn {
            tx_hash: [0; 32],
            ..burn(None)
        };
        assert_eq!(c.classify(10, &[other_hash]), U(Unmatched::UnknownBurn));

        let earlier = Consumer {
            txid: [0x02; 32],
            first_seen: 8,
        };
        assert_eq!(
            c.classify(10, &[burn(Some(earlier))]),
            U(Unmatched::ConsumedBurn {
                by: earlier,
                benign_race: true
            })
        );
        assert_eq!(
            c.classify(20, &[burn(Some(earlier))]),
            U(Unmatched::ConsumedBurn {
                by: earlier,
                benign_race: false
            })
        );

        let wrong_value = Case::with(c.intent, memo9(), 4999);
        assert_eq!(
            wrong_value.classify(10, &[burn(None)]),
            U(Unmatched::WrongValue {
                expected: 5000,
                got: 4999
            })
        );

        let thief = intent_for(&vault(), &YcashRecipient::p2pkh([0x66; 20]).script()).unwrap();
        assert_eq!(
            Case::with(thief, memo9(), 5000).classify(10, &[burn(None)]),
            U(Unmatched::WrongRecipient)
        );

        let orphan = Burn {
            recipient: [0; 32],
            ..burn(None)
        };
        assert_eq!(c.classify(10, &[orphan]), U(Unmatched::OrphanedBurn));

        let sepolia = HawkeyeMemo::burn_release(
            Deployment {
                chain_id: 11_155_111,
                ..ctx().deployment
            },
            9,
            [0xee; 32],
        );
        assert_eq!(
            Case::burn_release(sepolia).classify(10, &[burn(None)]),
            U(Unmatched::WrongDeployment)
        );

        let mut no_memo = Case::burn_release(memo9());
        no_memo.outputs.pop();
        assert_eq!(no_memo.classify(10, &[burn(None)]), U(Unmatched::NoMemo));

        let mut two = Case::burn_release(memo9());
        two.outputs.push(two.outputs[1].clone());
        assert_eq!(two.classify(10, &[burn(None)]), U(Unmatched::MultipleMemos));

        let mut bad = Case::burn_release(memo9());
        bad.outputs[1].script_pubkey = op_return_script(b"HKB1junk");
        assert_eq!(bad.classify(10, &[burn(None)]), U(Unmatched::MalformedMemo));

        assert!(Unmatched::NoMemo.slashable());
        assert!(
            !Unmatched::ConsumedBurn {
                by: earlier,
                benign_race: true
            }
            .slashable()
        );
    }

    #[test]
    fn foreign() {
        let mut i = intent_for(&vault(), &recipient().script()).unwrap();
        i.set_id = [1; 32];
        assert_eq!(
            Case::with(i, memo9(), 5000).classify(10, &[burn(None)]),
            Classification::Foreign
        );
        let mut i = intent_for(&vault(), &recipient().script()).unwrap();
        i.tag = *b"YED\0";
        assert_eq!(
            Case::with(i, memo9(), 5000).classify(10, &[burn(None)]),
            Classification::Foreign
        );
    }

    #[test]
    fn rolls() {
        use Classification::Unmatched as U;
        let new = VaultParams {
            owner_height: 6000,
            ..vault()
        };
        let memo = HawkeyeMemo::roll(ctx().deployment, &new).unwrap();
        let intent = intent_for(&vault(), &new.script().unwrap()).unwrap();
        let c = Case::with(intent, memo, 123);
        assert_eq!(
            c.classify(10, &[]),
            Classification::MatchedRoll { new_vault: new }
        );

        // too short a horizon
        let short = VaultParams {
            owner_height: 4000,
            ..vault()
        };
        let c = Case::with(
            intent_for(&vault(), &short.script().unwrap()).unwrap(),
            HawkeyeMemo::roll(ctx().deployment, &short).unwrap(),
            1,
        );
        assert_eq!(
            c.classify(10, &[]),
            U(Unmatched::RollTooShort { owner_height: 4000 })
        );

        // the memo names one vault, the intent pays another
        let elsewhere = VaultParams {
            owner_key: [3; 33],
            ..new
        };
        let c = Case::with(
            intent_for(&vault(), &elsewhere.script().unwrap()).unwrap(),
            memo,
            1,
        );
        assert_eq!(c.classify(10, &[]), U(Unmatched::BadRoll));

        // without the spent vault a roll cannot be verified
        let intent = intent_for(&vault(), &new.script().unwrap()).unwrap();
        let outs = Case::with(intent, memo, 1).outputs;
        let r = classify_intent(
            &ctx(),
            &ObservedIntent {
                txid: [1; 32],
                first_seen: 1,
                intent: &intent,
                value: 1,
                outputs: &outs,
                spent_vault: None,
            },
            |_| None,
        );
        assert_eq!(r, U(Unmatched::BadRoll));

        // a spent vault that is not the intent's vaultHash
        let wrong_spent = VaultParams {
            owner_height: 999,
            ..vault()
        };
        let r = classify_intent(
            &ctx(),
            &ObservedIntent {
                txid: [1; 32],
                first_seen: 1,
                intent: &intent,
                value: 1,
                outputs: &outs,
                spent_vault: Some(&wrong_spent),
            },
            |_| None,
        );
        assert_eq!(r, U(Unmatched::BadRoll));
    }

    #[test]
    fn benign_race_window() {
        assert!(is_benign_race(10, 13, 3));
        assert!(is_benign_race(13, 10, 3));
        assert!(!is_benign_race(10, 14, 3));
        assert!(is_benign_race(5, 5, 0));
    }
}
