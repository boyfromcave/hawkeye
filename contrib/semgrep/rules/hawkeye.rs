// Tests for contrib/semgrep/rules/hawkeye.yaml: `semgrep --test contrib/semgrep/rules`.
// Never compiled; the annotations say which line each rule must (ruleid) or must not (ok) flag.

fn interface(ycash: &YcashRpc) {
    // ruleid: hawkeye.interface.yed-rpc
    ycash.call("yed_getinfo", &[]);
    // ok: hawkeye.interface.yed-rpc
    ycash.call("vault_getinfo", &[]);
    // ok: hawkeye.interface.yed-rpc
    ycash.call("set_getinfo", &[]);
}

fn primitives(sk: &SigningKey, signer: &PrivateKeySigner, digest: &[u8; 32]) {
    // ruleid: hawkeye.signing.primitive-outside-signing-modules
    let (sig, rec) = sk.sign_prehash_recoverable(digest).unwrap();
    // ruleid: hawkeye.signing.primitive-outside-signing-modules
    let s = signer.sign_hash_sync(&digest.into()).unwrap();
    // ok: hawkeye.signing.primitive-outside-signing-modules
    let ok = hawkeye_core::setsig::sign_compact(&key, digest);
}

fn sign_once(ctx: &Ctx, t: &mut Tx, foreign: &dyn Foreign, key: &SecretKey, d: &Hash32) {
    // ok: hawkeye.signing.outside-sign-once
    let rec = t.sign_once_mint(&lock_id, value, &to, d, |d| foreign.sign(&key, d))?;
    // ok: hawkeye.signing.outside-sign-once
    let rec = t.sign_once_ycash(&k, hex, |h| {
        let r = block_on(ycash.set_signact(&h, Some(&set)))?;
        Ok((r.hex, h))
    })?;
    // ruleid: hawkeye.signing.outside-sign-once
    let sig = foreign.sign(&key, d)?;
    // ruleid: hawkeye.signing.outside-sign-once
    let sig = hawkeye_core::eth::sign_digest(&key, d)?;
    // ruleid: hawkeye.signing.outside-sign-once
    let r = block_on(ycash.set_signunlock(&h))?;
}

fn rng() {
    // ruleid: hawkeye.crypto.non-crypto-rng
    let mut r = SmallRng::from_entropy();
    // ruleid: hawkeye.crypto.non-crypto-rng
    let mut r = StdRng::seed_from_u64(42);
    // ruleid: hawkeye.crypto.non-crypto-rng
    let n = fastrand::u64(..);
    // ok: hawkeye.crypto.non-crypto-rng
    let k = SigningKey::random(&mut OsRng);
}

fn logging(secret: &SecretKey, key: &SecretKey) {
    // ruleid: hawkeye.secrets.logged-key-material
    tracing::info!("loaded {:?}", secret);
    // ruleid: hawkeye.secrets.logged-key-material
    println!("{}", hex::encode(secret_hex));
    // ruleid: hawkeye.secrets.logged-key-material
    debug!("key bytes {:?}", key.to_bytes());
    // ok: hawkeye.secrets.logged-key-material
    info!("member key {}", hex::encode(key.public_key()));
    // ok: hawkeye.secrets.logged-key-material
    info!("guardian {}", key.eth_address());
}

fn peer_auth(key: &SecretKey, msg: &Hash32) {
    // ok: hawkeye.signing.outside-sign-once
    let sig = hawkeye_core::peerauth::sign(&key, msg)?;
}

fn set_signing(t: &mut Tx, signer: &SetSigning, hex: &str) {
    // ruleid: hawkeye.signing.outside-sign-once
    let o = signer.sign(&hex)?;
    // ok: hawkeye.signing.outside-sign-once
    let rec = t.sign_once_unlock_at(&key, None, &hex, Some(branch), Some(h), |h| {
        let o = signer.sign(h)?;
        Ok((o.hex, o.sighash))
    })?;
}
