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
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (attestor + watcher + heartbeat + API).
    Run,
    /// Print a summary of the ledger, the node and the chain.
    Status {
        /// As JSON.
        #[arg(long)]
        json: bool,
    },
    /// Import the member key into the node wallet (no rescan).
    Enroll,
    /// Key helpers.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Depositor: lock YEC in a WYEC vault with an Ethereum destination.
    Lock {
        /// YEC (also accepted positionally).
        #[arg(long = "amount", value_name = "YEC")]
        amount: Option<String>,
        /// YEC, positional form.
        #[arg(value_name = "AMOUNT", conflicts_with = "amount")]
        amount_pos: Option<String>,
        /// The Ethereum address to mint to.
        #[arg(long)]
        dest: String,
        /// ownerHeight − tip (default MIN_OWNER_AGE + ROLL_MARGIN + 10).
        #[arg(long)]
        owner_age: Option<u32>,
    },
    /// Holder: burn wYEC to a Ycash transparent address.
    Burn {
        /// YEC (also accepted positionally).
        #[arg(long = "amount", value_name = "YEC")]
        amount: Option<String>,
        /// YEC, positional form.
        #[arg(value_name = "AMOUNT", conflicts_with = "amount")]
        amount_pos: Option<String>,
        /// The Ycash t-address.
        #[arg(long)]
        recipient: String,
        /// The holder's Ethereum key (default: the config's secret_hex).
        #[arg(long)]
        eth_key: Option<String>,
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
        /// The Ethereum recipient (default: this attestor's own address).
        #[arg(long)]
        to: Option<String>,
        /// The lockId, 32 bytes hex (default: an invented one no lock has).
        #[arg(long)]
        lock_id: Option<String>,
    },
    /// Owner: vault_ownerspend of every WYEC vault/intent this wallet owns.
    Recover,
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Print the member key and Ethereum address of a secret.
    Derive {
        /// 64 hex digits.
        #[arg(long)]
        secret: String,
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
    let s = settings(&args)?;
    init_logging(&s.log_level, s.log_json);
    match &args.cmd {
        Cmd::Run => daemon::run(&s).await,
        Cmd::Status { json } => cli::status(&s, *json).await,
        Cmd::Enroll => cli::enroll(&s).await,
        Cmd::Lock {
            amount,
            amount_pos,
            dest,
            owner_age,
        } => cli::lock(&s, &need(amount, amount_pos)?, dest, *owner_age).await,
        Cmd::Burn {
            amount,
            amount_pos,
            recipient,
            eth_key,
        } => {
            cli::burn(
                &s,
                &need(amount, amount_pos)?,
                recipient,
                eth_key.as_deref(),
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
        Cmd::Keys { .. } => unreachable!(),
    }
}
