//! `near-admin`: the NEAR set-up transactions of the devnet (`devnet/hawkeye-devnet --foreign
//! near`) and of the sandbox CI job, signed with `hawkeye-near`'s own codec (NEAR plan NH5). Not
//! part of the daemon: Hawkeye never creates accounts or deploys.
//!
//! ```text
//! near-admin create-account --rpc URL --signer KEY.json --account ID --amount NEAR --out KEY.json
//! near-admin deploy         --rpc URL --signer KEY.json --wasm FILE [--init METHOD --args JSON]
//! near-admin call           --rpc URL --signer KEY.json --contract ID --method M [--args JSON]
//!                           [--deposit YOCTO] [--gas-tgas N]
//! near-admin transfer       --rpc URL --signer KEY.json --to ID --amount NEAR
//! ```
//!
//! `KEY.json` is a NEAR credentials file (`account_id`, `public_key`, `private_key` or
//! `secret_key`); the sandbox's `validator_key.json` (`test.near`) is one. Each command prints one
//! JSON line: `{"tx", "receipt_block", "gas_burnt", "value"}` (and `create-account` the new
//! account and public key). A failed transaction exits 1 with the error on stderr.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::Path;
use std::process::ExitCode;

use hawkeye_core::AccountId;
use hawkeye_near::KeyFile;
use hawkeye_near::admin::{Admin, parse_near};
use hawkeye_near::rpc::{TxOutcome, b58};
use hawkeye_near::tx::TGAS;
use serde_json::{Value, json};

type Res<T> = Result<T, String>;

fn usage() -> String {
    "usage: near-admin create-account|deploy|call|transfer --rpc URL --signer KEY.json [...] \
     (see the doc comment of crates/hawkeye-near/examples/near-admin.rs)"
        .into()
}

fn flags(args: &[String]) -> Res<HashMap<String, String>> {
    let mut m = HashMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let name = k
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument {k:?}; {}", usage()))?;
        let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
        m.insert(name.to_owned(), v.clone());
    }
    Ok(m)
}

fn need<'a>(m: &'a HashMap<String, String>, k: &str) -> Res<&'a str> {
    m.get(k)
        .map(String::as_str)
        .ok_or_else(|| format!("--{k} is required"))
}

fn account(s: &str) -> Res<AccountId> {
    AccountId::parse(s).map_err(|e| format!("account {s:?}: {e}"))
}

fn json_arg(m: &HashMap<String, String>) -> Res<Value> {
    match m.get("args") {
        Some(a) => serde_json::from_str(a).map_err(|e| format!("--args: {e}")),
        None => Ok(json!({})),
    }
}

fn outcome(o: &TxOutcome) -> Value {
    let value = serde_json::from_slice::<Value>(&o.value)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&o.value).into_owned()));
    json!({"tx": b58(&o.tx_hash), "receipt_block": b58(&o.receipt_block),
           "gas_burnt": o.gas_burnt, "value": value})
}

fn seed() -> Res<[u8; 32]> {
    let mut s = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut s))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    Ok(s)
}

async fn run(args: Vec<String>) -> Res<Value> {
    let (cmd, rest) = args.split_first().ok_or_else(usage)?;
    let m = flags(rest)?;
    let signer = KeyFile::read(Path::new(need(&m, "signer")?)).map_err(|e| e.to_string())?;
    let admin = Admin::new(need(&m, "rpc")?, signer).map_err(|e| e.to_string())?;
    let e = |e: hawkeye_near::Error| format!("{cmd}: {e}");
    match cmd.as_str() {
        "create-account" => {
            let id = account(need(&m, "account")?)?;
            let amount = parse_near(need(&m, "amount")?).map_err(|x| x.to_string())?;
            let out = need(&m, "out")?;
            let (key, o) = admin
                .create_account_with_seed(&id, amount, &seed()?)
                .await
                .map_err(e)?;
            std::fs::write(out, key.to_json() + "\n").map_err(|x| format!("{out}: {x}"))?;
            let mut v = outcome(&o);
            v["account_id"] = json!(id.as_str());
            v["public_key"] = json!(key.public_key_text());
            v["key_file"] = json!(out);
            Ok(v)
        }
        "deploy" => {
            let wasm = need(&m, "wasm")?;
            let code = std::fs::read(wasm).map_err(|x| format!("{wasm}: {x}"))?;
            let size = code.len();
            let args = json_arg(&m)?;
            let init = m.get("init").map(|method| (method.as_str(), &args));
            let o = admin.deploy(code, init).await.map_err(e)?;
            let mut v = outcome(&o);
            v["account_id"] = json!(admin.account_id().as_str());
            v["wasm_bytes"] = json!(size);
            Ok(v)
        }
        "call" => {
            let contract = account(need(&m, "contract")?)?;
            let deposit: u128 = m
                .get("deposit")
                .map_or(Ok(0), |d| d.parse())
                .map_err(|x| format!("--deposit: {x}"))?;
            let gas: u64 = m
                .get("gas-tgas")
                .map_or(Ok(100), |g| g.parse())
                .map_err(|x| format!("--gas-tgas: {x}"))?;
            let o = admin
                .call(
                    &contract,
                    need(&m, "method")?,
                    &json_arg(&m)?,
                    deposit,
                    gas * TGAS,
                )
                .await
                .map_err(e)?;
            Ok(outcome(&o))
        }
        "transfer" => {
            let to = account(need(&m, "to")?)?;
            let amount = parse_near(need(&m, "amount")?).map_err(|x| x.to_string())?;
            Ok(outcome(&admin.transfer(&to, amount).await.map_err(e)?))
        }
        _ => Err(usage()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(run(args)) {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("near-admin: {msg}");
            ExitCode::FAILURE
        }
    }
}
