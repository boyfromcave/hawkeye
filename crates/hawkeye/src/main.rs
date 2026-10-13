//! The `hawkeye` binary: see `hawkeye --help`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hawkeye::config::{Config, Settings, base_dir};
use hawkeye::{cli, daemon, keys};

#[derive(Parser)]
#[command(name = "hawkeye", version, about = "Hawkeye: the wYEC bridge attestor")]
struct Args {
    /// The config file (hawkeye.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Accept a group/world-readable config (with a secret), keystore, key file or ledger on
    /// mainnet (elsewhere they are only warned about).
    #[arg(long, global = true)]
    insecure_file_permissions: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (attestor + watcher + heartbeat + API).
    Run {
        /// Off mainnet: start the follower at `[ycash] start_height` even though the set has older
        /// vaults of the bridge's tag. Such an attestor never saw those locks and challenges (and
        /// opens fraud cases against) honest proposals for them (audit 05/L-5). Refused on mainnet.
        #[arg(long)]
        i_accept_blind_start: bool,
        /// Start even though `audit-ledger` finds an unlock this member signed with no record in
        /// this ledger (a restored or copied ledger): this attestor may then sign a second spend
        /// of that vault, a provable equivocation (docs/operations.md §5).
        #[arg(long)]
        i_accept_equivocation_risk: bool,
    },
    /// Read-only: compare the ledger's sign-once records with the node (docs/operations.md §5).
    /// Exits non-zero when an unlock this member signed has no record here. Opens the ledger
    /// without migrating it; run it with the daemon stopped or running.
    AuditLedger {
        /// As JSON.
        #[arg(long)]
        json: bool,
    },
    /// Exposures (audit 05/L-5): signed locks that left the active chain, minted or not. While
    /// one is unacknowledged the daemon pauses its own mint-side acts (off regtest).
    Exposure {
        #[command(subcommand)]
        cmd: ExposureCmd,
    },
    /// Print a summary of the ledger, the node and the chain.
    Status {
        /// As JSON.
        #[arg(long)]
        json: bool,
        /// The effective parameters, the set's and the contract's, each against its mainnet floor
        /// (`OK` / `BELOW FLOOR`; audit 05/M-4).
        #[arg(long)]
        params: bool,
    },
    /// Import the member key into the node wallet (no rescan).
    Enroll,
    /// `"wallet"` mode (07/F-5): give the node wallet this attestor's sign-once history and clear
    /// its restore marker (`set_importsigned` of the ledger's unlock and cancel records, then
    /// `set_acknowledgerestore`), after `audit-ledger` passes. The operator's statement that no
    /// other copy of the member key has signed: run it once after enrolment and the `SET_JOIN`, or
    /// after a restore (docs/operations.md §4, §5).
    AcknowledgeRestore,
    /// Clear the ledger's restore flag (review L-2: `alarm ledger-restored`) after confirming no
    /// unlock this member signed is missing from it (`audit-ledger`, and the other attestors'
    /// answers): fresh unlocks then go back to asking only each burn's previous leaders. Resets
    /// the ledger's high-water mark to its current record count.
    AcknowledgeLedgerRestore,
    /// The owner's override (2026-10-13) for a member that is permanently gone (a lost host and
    /// disk): declare, signed by this attestor's member key, that `member` holds no signed unlock
    /// that could ever be revived. The declaration is recorded in this ledger and sent to every
    /// peer (`POST /members/gone`); once at least `unlockThreshold` distinct current members other
    /// than it have declared it gone, a takeover no longer waits for that member's answer before
    /// signing a fresh vault. Logged at `warn`. Run by each attestor that agrees; prefer removing
    /// the member on Ycash (`SET_REMOVE`), after which its answer is not needed anyway.
    DeclareLeaderGone {
        /// The member's 33-byte compressed key (66 hex).
        member: String,
        /// Why (kept with the declaration).
        #[arg(long, default_value = "permanently unreachable")]
        reason: String,
    },
    /// Key helpers.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Depositor: lock YEC in a vault of the bridge's tag (WYEC / NYEC) with a destination on
    /// the foreign chain.
    Lock {
        /// YEC (also accepted positionally).
        #[arg(long = "amount", value_name = "YEC")]
        amount: Option<String>,
        /// YEC, positional form.
        #[arg(value_name = "AMOUNT", conflicts_with = "amount")]
        amount_pos: Option<String>,
        /// The account to mint to: an Ethereum address (Ethereum bridge) or a NEAR account id
        /// (NEAR bridge).
        #[arg(long)]
        dest: String,
        /// ownerHeight − tip (default MIN_OWNER_AGE + ROLL_MARGIN + 10).
        #[arg(long)]
        owner_age: Option<u32>,
        /// The vault owner: a post-quantum (SLH-DSA) address or pqkeyid (default: a new
        /// owner key of the node wallet, `vault_getnewowner`).
        #[arg(long)]
        owner: Option<String>,
    },
    /// Holder: burn wYEC to a Ycash address (transparent, or plain-YEC post-quantum sq…/tq…/rq…).
    Burn {
        /// YEC (also accepted positionally).
        #[arg(long = "amount", value_name = "YEC")]
        amount: Option<String>,
        /// YEC, positional form.
        #[arg(value_name = "AMOUNT", conflicts_with = "amount")]
        amount_pos: Option<String>,
        /// The Ycash recipient: a transparent address (s1…/s2…/s3…, testnet sm…/s2…) or a
        /// plain-YEC post-quantum address (sq…/tq…/rq…; scheme 2 warns until Falcon is active).
        /// Never a PQ owner address (yb…/yt…/yr…) and never shielded.
        #[arg(long)]
        recipient: String,
        /// Ethereum: the holder's key (default: the config's secret_hex).
        #[arg(long)]
        eth_key: Option<String>,
        /// NEAR: the holder's credentials JSON (`account_id`, `public_key`, `private_key`;
        /// default: the config's relayer key file).
        #[arg(long)]
        near_key: Option<PathBuf>,
        /// Send a burn above the attestor set's per-window cap anyway (it is not released
        /// until the set raises its rate limit; later burns are not held up by it).
        #[arg(long)]
        allow_over_cap: bool,
    },
    /// DRILL ONLY: sign an unlock with no burn behind it (or, with --replay-burn, a second
    /// unlock for an already-released burn, carrying its valid memo).
    RogueUnlock {
        /// YEC (also accepted positionally).
        #[arg(long = "amount", value_name = "YEC")]
        amount: Option<String>,
        /// YEC, positional form.
        #[arg(value_name = "AMOUNT", conflicts_with = "amount")]
        amount_pos: Option<String>,
        /// The Ycash t-address (default: a new address of this node's wallet; with
        /// --replay-burn, the burn's own recipient).
        #[arg(long)]
        to: Option<String>,
        /// Drill D-3: replay finalized burn NONCE from this attestor's ledger (its recipient,
        /// its amount unless given, its HKB1 memo).
        #[arg(long, value_name = "NONCE")]
        replay_burn: Option<u64>,
    },
    /// DRILL ONLY (D-5): sign a Mint for a lockId with no lock behind it and open an optimistic
    /// proposal with it (proposeMint), for the other attestors to challenge and slash.
    RogueMint {
        /// YEC (also accepted positionally).
        #[arg(long = "amount", value_name = "YEC")]
        amount: Option<String>,
        /// YEC, positional form.
        #[arg(value_name = "AMOUNT", conflicts_with = "amount")]
        amount_pos: Option<String>,
        /// The recipient (default on Ethereum: this attestor's own address; required on NEAR).
        #[arg(long)]
        to: Option<String>,
        /// The lockId, 32 bytes hex (default: an invented one no lock has).
        #[arg(long)]
        lock_id: Option<String>,
    },
    /// Owner: vault_ownerspend of every vault/intent of the bridge's tag this wallet owns.
    Recover,
    /// Attestor: leave the set (set_leave: the member's own SET_REMOVE, no burn). The bond stays
    /// locked and slashable for the set's maturity (>= 16,128 blocks on mainnet), then
    /// `withdraw-bond` returns it. Stop the daemon first.
    Leave,
    /// Attestor: after `leave` and the set's maturity, spend the bond to --to (default a new
    /// address of the node wallet).
    WithdrawBond {
        /// The Ycash t-address to pay the bond to.
        #[arg(long)]
        to: Option<String>,
    },
    /// Attestor: split the node wallet's funds into N fresh fee coins (one `sendmany` to N new
    /// wallet addresses), so N cancels can be funded in one block (plan §5.5).
    SplitCoins {
        /// How many coins.
        #[arg(long, default_value_t = 16)]
        count: u32,
        /// YEC per coin (default 0.01).
        #[arg(long, value_name = "YEC")]
        amount: Option<String>,
    },
}

#[derive(Subcommand)]
enum ExposureCmd {
    /// List the unacknowledged exposures.
    List,
    /// Acknowledge the exposure of a lock (after the set paused the bridge or lowered its cap and
    /// the supply was reconciled): the daemon stops pausing for it.
    Ack {
        /// The lockId, 0x-hex.
        lock_id: String,
        /// What was done about it (kept with the acknowledgement).
        #[arg(long)]
        note: String,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Print the member key, its Ethereum address and its NEAR guardian key.
    Derive {
        /// 64 hex digits.
        #[arg(long)]
        secret: String,
    },
    /// Write a key (64 hex digits from an environment variable) as an encrypted keystore v3,
    /// created owner-only (0600).
    Encrypt {
        /// The keystore file to create (must not exist).
        #[arg(long)]
        out: PathBuf,
        /// The variable holding the key.
        #[arg(long, default_value = "HAWKEYE_SECRET")]
        secret_env: String,
        /// The variable holding the password.
        #[arg(long, default_value = "HAWKEYE_KEYSTORE_PASSWORD")]
        password_env: String,
    },
}

fn init_logging(level: &str, json: bool) {
    let level: tracing::Level = level.parse().unwrap_or(tracing::Level::INFO);
    let b = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false);
    if json {
        b.json().flatten_event(true).init();
    } else {
        b.init();
    }
}

fn need(flag: &Option<String>, pos: &Option<String>) -> Result<String> {
    flag.clone()
        .or_else(|| pos.clone())
        .context("give the amount: --amount <YEC>")
}

fn settings(args: &Args) -> Result<Settings> {
    let path = args
        .config
        .as_ref()
        .context("this command needs --config <path.toml>")?;
    Config::read(path)?.settings(&base_dir(path))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Cmd::Keys {
        cmd: KeysCmd::Derive { secret },
    } = &args.cmd
    {
        let k = keys::parse_secret(secret)?;
        println!("{}", serde_json::to_string(&keys::key_info(&k))?);
        return Ok(());
    }
    if let Cmd::Keys {
        cmd:
            KeysCmd::Encrypt {
                out,
                secret_env,
                password_env,
            },
    } = &args.cmd
    {
        let k = keys::parse_secret(
            &std::env::var(secret_env).with_context(|| format!("the key variable {secret_env}"))?,
        )?;
        let pw = std::env::var(password_env)
            .with_context(|| format!("the password variable {password_env}"))?;
        keys::encrypt_keystore(&k, out, &pw)?;
        println!("{}", serde_json::to_string(&keys::key_info(&k))?);
        return Ok(());
    }
    let s = settings(&args)?;
    init_logging(&s.log_level, s.log_json);
    for w in &s.warnings {
        tracing::warn!(event = "config_warning", detail = %w);
    }
    if s.insecure_rpc && s.params.mainnet {
        tracing::error!(
            event = "insecure_rpc",
            url = %s.ycash_url,
            "mainnet: the ycashd RPC credentials cross the network in clear ([ycash] \
             allow_insecure_rpc)"
        );
    }
    let path = args.config.as_ref().expect("settings() needs --config");
    for w in s.check_file_permissions(path, args.insecure_file_permissions)? {
        tracing::warn!(event = "file_permissions", detail = %w);
    }
    match &args.cmd {
        Cmd::Run {
            i_accept_blind_start,
            i_accept_equivocation_risk,
        } => {
            let mut s = s;
            s.params.accept_blind_start = *i_accept_blind_start;
            daemon::run(&s, *i_accept_equivocation_risk).await
        }
        Cmd::AuditLedger { json } => cli::audit_ledger(&s, *json).await,
        Cmd::Exposure {
            cmd: ExposureCmd::List,
        } => cli::exposure_list(&s),
        Cmd::Exposure {
            cmd: ExposureCmd::Ack { lock_id, note },
        } => cli::exposure_ack(&s, lock_id, note),
        Cmd::Status { json, params: true } => cli::status_params(&s, *json).await,
        Cmd::Status { json, .. } => cli::status(&s, *json).await,
        Cmd::Enroll => cli::enroll(&s).await,
        Cmd::AcknowledgeRestore => cli::acknowledge_restore(&s).await,
        Cmd::AcknowledgeLedgerRestore => cli::acknowledge_ledger_restore(&s),
        Cmd::DeclareLeaderGone { member, reason } => {
            cli::declare_leader_gone(&s, member, reason).await
        }
        Cmd::Lock {
            amount,
            amount_pos,
            dest,
            owner_age,
            owner,
        } => {
            cli::lock(
                &s,
                &need(amount, amount_pos)?,
                dest,
                *owner_age,
                owner.as_deref(),
            )
            .await
        }
        Cmd::Burn {
            amount,
            amount_pos,
            recipient,
            eth_key,
            near_key,
            allow_over_cap,
        } => {
            cli::burn(
                &s,
                &need(amount, amount_pos)?,
                recipient,
                eth_key.as_deref(),
                near_key.as_deref(),
                *allow_over_cap,
            )
            .await
        }
        Cmd::RogueUnlock {
            amount,
            amount_pos,
            to,
            replay_burn,
        } => {
            let amount = amount.clone().or_else(|| amount_pos.clone());
            cli::rogue_unlock(&s, amount.as_deref(), to.as_deref(), *replay_burn).await
        }
        Cmd::RogueMint {
            amount,
            amount_pos,
            to,
            lock_id,
        } => {
            cli::rogue_mint(
                &s,
                &need(amount, amount_pos)?,
                to.as_deref(),
                lock_id.as_deref(),
            )
            .await
        }
        Cmd::Recover => cli::recover(&s).await,
        Cmd::Leave => cli::leave(&s).await,
        Cmd::WithdrawBond { to } => cli::withdraw_bond(&s, to.as_deref()).await,
        Cmd::SplitCoins { count, amount } => cli::split_coins(&s, *count, amount.as_deref()).await,
        Cmd::Keys { .. } => unreachable!(),
    }
}
