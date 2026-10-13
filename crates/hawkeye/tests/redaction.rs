//! Audit 05/I-1 guard: every struct or enum in `crates/*/src` that derives `Debug` holds its
//! secrets (fields named `secret*`, `password*`, `*_secret`, `*_password`, `private_key*`) as
//! `Redacted<…>`, so the next secret field cannot be printed by a `debug!(?x)` either. Fields that
//! only *name* a secret's location (`*_env`, `*_file`, `*_path`) are not secrets.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn is_secret_name(name: &str) -> bool {
    let reference = ["_env", "_file", "_path"].iter().any(|s| name.ends_with(s));
    let secret = name.starts_with("secret")
        || name.starts_with("password")
        || name.starts_with("private_key")
        || name.ends_with("_secret")
        || name.ends_with("_password");
    secret && !reference
}

/// `(file:line, field)` of every secret-named field of a `Debug`-deriving item not typed
/// `Redacted`.
fn unredacted(src: &str, file: &str) -> Vec<String> {
    let mut bad = vec![];
    let mut derives_debug = false;
    let mut in_item = false;
    for (n, line) in src.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("#[derive(") {
            derives_debug = t.contains("Debug");
            continue;
        }
        if t.starts_with("#[") || t.starts_with("///") || t.starts_with("//") {
            continue;
        }
        let item = ["struct ", "enum "].iter().any(|k| {
            t.starts_with(k)
                || t.contains(&format!("pub {k}"))
                || t.contains(&format!("pub(crate) {k}"))
        });
        if item {
            in_item = derives_debug && !t.ends_with(';');
            derives_debug = false;
            continue;
        }
        if !in_item {
            continue;
        }
        if line.starts_with('}') {
            in_item = false;
            continue;
        }
        let field = t
            .trim_start_matches("pub(crate) ")
            .trim_start_matches("pub ");
        if let Some((name, ty)) = field.split_once(':')
            && !name.contains(' ')
            && !name.contains('(')
            && is_secret_name(name.trim())
            && !ty.contains("Redacted")
        {
            bad.push(format!("{file}:{}: {}", n + 1, name.trim()));
        }
    }
    bad
}

#[test]
fn secret_fields_of_debug_types_are_redacted() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = vec![];
    for c in std::fs::read_dir(&crates).unwrap() {
        let src = c.unwrap().path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    assert!(files.len() > 20, "found the sources: {}", files.len());
    let mut bad = vec![];
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        bad.extend(unredacted(&text, &f.display().to_string()));
    }
    assert!(
        bad.is_empty(),
        "secret fields printed by a derived Debug: {bad:#?}"
    );
}

#[test]
fn the_guard_catches_a_plain_secret() {
    let src = "#[derive(Debug, Clone)]\npub struct K {\n    pub secret_hex: Option<String>,\n    pub password_env: String,\n}\n";
    assert_eq!(unredacted(src, "x.rs"), ["x.rs:3: secret_hex"]);
    let ok = "#[derive(Debug)]\npub struct K {\n    pub secret_hex: Option<Redacted<String>>,\n}\n";
    assert!(unredacted(ok, "x.rs").is_empty());
    let no_debug = "#[derive(Deserialize)]\nstruct J {\n    private_key: Option<String>,\n}\n";
    assert!(unredacted(no_debug, "x.rs").is_empty());
}
