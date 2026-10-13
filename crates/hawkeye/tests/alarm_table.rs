//! The runbook's alarm table (`docs/operations.md` §9) names exactly the alarms the daemon can
//! raise (remedial report 05/M-3 §6.1): every `alarm(` call in `crates/hawkeye/src` with a literal
//! name, plus the `slash-case-<id>` family, against the first column of the table.

use std::collections::BTreeSet;
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

/// The names raised in `src`: the first string literal after `.alarm(` (a `format!` name keeps
/// its literal prefix up to the first `{`, as `slash-case-<id>`).
fn raised(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (i, _) in src.match_indices(".alarm(") {
        let rest = &src[i + ".alarm(".len()..];
        let Some(q) = rest.find('"') else { continue };
        // the name is the call's first argument: nothing but whitespace, `&format!(` before it
        let lead = rest[..q].trim();
        if !(lead.is_empty() || lead == "&format!(") {
            continue;
        }
        let lit = &rest[q + 1..];
        let end = lit.find('"').unwrap();
        let name = &lit[..end];
        let name = match name.find('{') {
            Some(b) => format!("{}<id>", &name[..b]),
            None => name.to_owned(),
        };
        out.insert(name);
    }
    out
}

/// The first column of §9's alarm table.
fn documented(md: &str) -> BTreeSet<String> {
    let start = md
        .find("| Alarm | Severity | Meaning | Action |")
        .expect("§9 alarm table");
    md[start..]
        .lines()
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .map(|l| {
            let cell = l.split('|').nth(1).unwrap().trim();
            cell.trim_matches('`').to_owned()
        })
        .collect()
}

#[test]
fn the_runbook_lists_every_alarm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![];
    rust_files(&root.join("src"), &mut files);
    let mut code = BTreeSet::new();
    for f in &files {
        code.extend(raised(&std::fs::read_to_string(f).unwrap()));
    }
    assert!(code.len() >= 15, "found the alarms: {code:?}");
    let md = std::fs::read_to_string(root.join("../../docs/operations.md")).unwrap();
    let docs = documented(&md);
    let undocumented: Vec<_> = code.difference(&docs).collect();
    let stale: Vec<_> = docs.difference(&code).collect();
    assert!(
        undocumented.is_empty() && stale.is_empty(),
        "docs/operations.md §9 is out of step with the code: raised but not in the table \
         {undocumented:?}; in the table but never raised {stale:?}"
    );
}

#[test]
fn the_extractor_reads_both_forms() {
    let src = r#"self.alarm("supply", x); self.alarm(
        "gas-low",
        y); self.alarm(&format!("slash-case-{}", c.id), z); fn alarm(&mut self, name: &str) {}"#;
    let got: Vec<String> = raised(src).into_iter().collect();
    assert_eq!(got, ["gas-low", "slash-case-<id>", "supply"]);
}
