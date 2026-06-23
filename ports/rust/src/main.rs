//! attestport (Rust port) — air-gap supply-chain SBOM + provenance.
//!
//! Mirrors the primary Python CLI's `sbom`, `attest`, and `verify` commands
//! using the same canonical-JSON + HMAC-SHA256 scheme so attestations
//! interoperate across the Python, Node, Go, and Rust implementations on a
//! shared key. No crates.io dependencies — SHA-256 and HMAC are vendored below
//! so the binary builds and runs fully offline / air-gapped.
//!
//!   attestport sbom   <dir>
//!   attestport attest <artifact> [--key K]
//!   attestport verify <artifact> <attestation.json> [--key K]
//!   attestport --version

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::exit;

const TOOL_NAME: &str = "attestport";
const TOOL_VERSION: &str = "0.1.0";

// --------------------------------------------------------------------------- //
// SHA-256 (vendored, public-domain style reimplementation)
// --------------------------------------------------------------------------- //
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{:02x}", b)).collect()
}

fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    let mut k = if key.len() > 64 { sha256(key).to_vec() } else { key.to_vec() };
    k.resize(64, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = ipad;
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);
    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    sha256_hex(&outer)
}

// --------------------------------------------------------------------------- //
// Minimal JSON value + canonical serialization
// --------------------------------------------------------------------------- //
#[derive(Clone)]
enum J {
    S(String),
    N(f64),
    B(bool),
    A(Vec<J>),
    O(BTreeMap<String, J>),
}

fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn canonical(v: &J) -> String {
    match v {
        J::S(s) => jstr(s),
        J::N(n) => {
            if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        J::B(b) => b.to_string(),
        J::A(a) => format!("[{}]", a.iter().map(canonical).collect::<Vec<_>>().join(",")),
        J::O(o) => format!(
            "{{{}}}",
            o.iter().map(|(k, val)| format!("{}:{}", jstr(k), canonical(val))).collect::<Vec<_>>().join(",")
        ),
    }
}

fn pretty(v: &J, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    let pad1 = "  ".repeat(indent + 1);
    match v {
        J::A(a) if !a.is_empty() => format!(
            "[\n{}\n{}]",
            a.iter().map(|e| format!("{}{}", pad1, pretty(e, indent + 1))).collect::<Vec<_>>().join(",\n"),
            pad
        ),
        J::O(o) if !o.is_empty() => format!(
            "{{\n{}\n{}}}",
            o.iter().map(|(k, val)| format!("{}{}: {}", pad1, jstr(k), pretty(val, indent + 1))).collect::<Vec<_>>().join(",\n"),
            pad
        ),
        other => canonical(other),
    }
}

// --------------------------------------------------------------------------- //
// SBOM
// --------------------------------------------------------------------------- //
struct Component {
    name: String,
    version: String,
    ecosystem: String,
    purl: String,
    pinned: bool,
}

fn purl(eco: &str, name: &str, version: &str) -> String {
    let safe = name.replace('@', "%40");
    if version.is_empty() {
        format!("pkg:{}/{}", eco, safe)
    } else {
        format!("pkg:{}/{}@{}", eco, safe, version)
    }
}

fn is_unpinned(spec: &str) -> bool {
    spec.contains('<') || spec.contains('>') || spec.contains('~') || spec.contains('^')
        || spec.contains('*') || spec.contains(',') || spec.contains(" - ") || spec.contains("||")
}

fn parse_requirements(text: &str) -> Vec<Component> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        let line = line.split(';').next().unwrap_or("").trim();
        // name is leading [A-Za-z0-9_.-]+
        let name: String = line.chars().take_while(|c| c.is_ascii_alphanumeric() || "_.-".contains(*c)).collect();
        if name.is_empty() {
            continue;
        }
        let spec = line[name.len()..].trim().to_string();
        let pinned = spec.starts_with("==") && !is_unpinned(&spec[2..]);
        let version = if spec.starts_with("==") {
            spec[2..].trim().to_string()
        } else {
            spec.trim_start_matches(|c| "=<>~!^ ".contains(c)).to_string()
        };
        let pv = if pinned { version.clone() } else { String::new() };
        out.push(Component { name: name.clone(), version, ecosystem: "pypi".into(), purl: purl("pypi", &name, &pv), pinned });
    }
    out
}

fn detect_components(dir: &Path) -> Result<Vec<Component>, String> {
    if !dir.is_dir() {
        return Err(format!("not a directory: {}", dir.display()));
    }
    let mut comps = Vec::new();
    let req = dir.join("requirements.txt");
    if req.is_file() {
        if let Ok(t) = fs::read_to_string(&req) {
            comps.extend(parse_requirements(&t));
        }
    }
    comps.sort_by(|a, b| {
        (a.ecosystem.clone() + &a.name.to_lowercase() + &a.version)
            .cmp(&(b.ecosystem.clone() + &b.name.to_lowercase() + &b.version))
    });
    Ok(comps)
}

const SKIP: [&str; 11] = [".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache", "target", ".idea", ".vscode"];

fn hash_tree(dir: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    fn walk(base: &Path, dir: &Path, files: &mut Vec<(String, String)>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if p.is_dir() {
                    if !SKIP.contains(&name.as_str()) {
                        walk(base, &p, files);
                    }
                } else if p.is_file() {
                    if let Ok(data) = fs::read(&p) {
                        let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                        files.push((rel, sha256_hex(&data)));
                    }
                }
            }
        }
    }
    walk(dir, dir, &mut files);
    files.sort();
    files
}

fn merkle(files: &[(String, String)]) -> String {
    let arr = J::A(files.iter().map(|(p, h)| J::A(vec![J::S(p.clone()), J::S(h.clone())])).collect());
    sha256_hex(canonical(&arr).as_bytes())
}

fn generate_sbom(dir: &Path) -> Result<J, String> {
    let comps = detect_components(dir)?;
    let files = hash_tree(dir);
    let root = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "project".into());
    let digest = merkle(&files);
    let u = sha256_hex(format!("{}|{}", root, digest).as_bytes());
    let serial = format!("urn:uuid:{}-{}-{}-{}-{}", &u[0..8], &u[8..12], &u[12..16], &u[16..20], &u[20..32]);

    let components: Vec<J> = comps.iter().map(|c| {
        let mut m = BTreeMap::new();
        m.insert("type".into(), J::S("library".into()));
        m.insert("name".into(), J::S(c.name.clone()));
        m.insert("version".into(), J::S(c.version.clone()));
        m.insert("bom-ref".into(), J::S(c.purl.clone()));
        m.insert("purl".into(), J::S(c.purl.clone()));
        let mut eco = BTreeMap::new();
        eco.insert("name".into(), J::S("attestport:ecosystem".into()));
        eco.insert("value".into(), J::S(c.ecosystem.clone()));
        let mut pin = BTreeMap::new();
        pin.insert("name".into(), J::S("attestport:pinned".into()));
        pin.insert("value".into(), J::S(if c.pinned { "true".into() } else { "false".into() }));
        m.insert("properties".into(), J::A(vec![J::O(eco), J::O(pin)]));
        J::O(m)
    }).collect();

    let mut tool = BTreeMap::new();
    tool.insert("vendor".into(), J::S("Cognis Digital".into()));
    tool.insert("name".into(), J::S(TOOL_NAME.into()));
    tool.insert("version".into(), J::S(TOOL_VERSION.into()));
    let mut rootc = BTreeMap::new();
    rootc.insert("type".into(), J::S("application".into()));
    rootc.insert("name".into(), J::S(root.clone()));
    rootc.insert("bom-ref".into(), J::S(format!("root:{}", root)));
    let mut meta = BTreeMap::new();
    meta.insert("tools".into(), J::A(vec![J::O(tool)]));
    meta.insert("component".into(), J::O(rootc));

    let mut bom = BTreeMap::new();
    bom.insert("bomFormat".into(), J::S("CycloneDX".into()));
    bom.insert("specVersion".into(), J::S("1.5".into()));
    bom.insert("serialNumber".into(), J::S(serial));
    bom.insert("version".into(), J::N(1.0));
    bom.insert("metadata".into(), J::O(meta));
    bom.insert("components".into(), J::A(components));
    Ok(J::O(bom))
}

// --------------------------------------------------------------------------- //
// attest / verify
// --------------------------------------------------------------------------- //
fn resolve_key(key: &str) -> Vec<u8> {
    if !key.is_empty() {
        return key.as_bytes().to_vec();
    }
    if let Ok(env) = env::var("ATTESTPORT_KEY") {
        if !env.is_empty() {
            return env.into_bytes();
        }
    }
    b"attestport-insecure-demo-key".to_vec()
}

fn subject_digest(artifact: &Path) -> String {
    if artifact.is_dir() {
        merkle(&hash_tree(artifact))
    } else {
        sha256_hex(&fs::read(artifact).unwrap_or_default())
    }
}

fn build_statement(artifact: &Path) -> J {
    let mut digest = BTreeMap::new();
    digest.insert("sha256".into(), J::S(subject_digest(artifact)));
    let mut subj = BTreeMap::new();
    subj.insert("name".into(), J::S(artifact.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()));
    subj.insert("digest".into(), J::O(digest));
    let mut builder = BTreeMap::new();
    builder.insert("id".into(), J::S("attestport:local".into()));
    let mut pred = BTreeMap::new();
    pred.insert("buildType".into(), J::S("https://cognis.digital/attestport/buildtype/v1".into()));
    pred.insert("builder".into(), J::O(builder));
    let mut inv = BTreeMap::new();
    inv.insert("configSource".into(), J::O(BTreeMap::new()));
    pred.insert("invocation".into(), J::O(inv));
    pred.insert("materials".into(), J::A(vec![]));
    let mut st = BTreeMap::new();
    st.insert("_type".into(), J::S("https://in-toto.io/Statement/v1".into()));
    st.insert("predicateType".into(), J::S("https://slsa.dev/provenance/v1".into()));
    st.insert("subject".into(), J::A(vec![J::O(subj)]));
    st.insert("predicate".into(), J::O(pred));
    J::O(st)
}

fn attest(artifact: &Path, key: &str) -> Result<J, String> {
    if !artifact.exists() {
        return Err(format!("artifact not found: {}", artifact.display()));
    }
    let statement = build_statement(artifact);
    let payload = canonical(&statement);
    let sig = hmac_sha256_hex(&resolve_key(key), payload.as_bytes());
    let mut sigmap = BTreeMap::new();
    sigmap.insert("algorithm".into(), J::S("hmac-sha256".into()));
    sigmap.insert("value".into(), J::S(sig));
    sigmap.insert("payloadSha256".into(), J::S(sha256_hex(payload.as_bytes())));
    if let J::O(mut m) = statement {
        m.insert("signature".into(), J::O(sigmap));
        Ok(J::O(m))
    } else {
        unreachable!()
    }
}

// tiny JSON parser, just enough to read an attestation we wrote
mod parse {
    use super::J;
    use std::collections::BTreeMap;
    pub fn parse(s: &str) -> Option<J> {
        let b = s.as_bytes();
        let mut i = 0;
        let v = val(b, &mut i)?;
        Some(v)
    }
    fn ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && (b[*i] as char).is_whitespace() {
            *i += 1;
        }
    }
    fn val(b: &[u8], i: &mut usize) -> Option<J> {
        ws(b, i);
        match b.get(*i)? {
            b'{' => obj(b, i),
            b'[' => arr(b, i),
            b'"' => Some(J::S(string(b, i)?)),
            b't' => { *i += 4; Some(J::B(true)) }
            b'f' => { *i += 5; Some(J::B(false)) }
            b'n' => { *i += 4; Some(J::S(String::new())) }
            _ => num(b, i),
        }
    }
    fn string(b: &[u8], i: &mut usize) -> Option<String> {
        *i += 1;
        let mut out = String::new();
        while *i < b.len() {
            let c = b[*i];
            *i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = b[*i];
                    *i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = std::str::from_utf8(&b[*i..*i + 4]).ok()?;
                            let cp = u32::from_str_radix(hex, 16).ok()?;
                            *i += 4;
                            out.push(char::from_u32(cp).unwrap_or('?'));
                        }
                        _ => {}
                    }
                }
                _ => out.push(c as char),
            }
        }
        None
    }
    fn num(b: &[u8], i: &mut usize) -> Option<J> {
        let start = *i;
        while *i < b.len() && (b[*i].is_ascii_digit() || b"-+.eE".contains(&b[*i])) {
            *i += 1;
        }
        std::str::from_utf8(&b[start..*i]).ok()?.parse::<f64>().ok().map(J::N)
    }
    fn arr(b: &[u8], i: &mut usize) -> Option<J> {
        *i += 1;
        let mut out = Vec::new();
        loop {
            ws(b, i);
            if b.get(*i) == Some(&b']') {
                *i += 1;
                return Some(J::A(out));
            }
            out.push(val(b, i)?);
            ws(b, i);
            if b.get(*i) == Some(&b',') {
                *i += 1;
            }
        }
    }
    fn obj(b: &[u8], i: &mut usize) -> Option<J> {
        *i += 1;
        let mut m = BTreeMap::new();
        loop {
            ws(b, i);
            if b.get(*i) == Some(&b'}') {
                *i += 1;
                return Some(J::O(m));
            }
            let k = string(b, i)?;
            ws(b, i);
            if b.get(*i) == Some(&b':') {
                *i += 1;
            }
            let v = val(b, i)?;
            m.insert(k, v);
            ws(b, i);
            if b.get(*i) == Some(&b',') {
                *i += 1;
            }
        }
    }
}

fn jget<'a>(v: &'a J, key: &str) -> Option<&'a J> {
    if let J::O(m) = v {
        m.get(key)
    } else {
        None
    }
}
fn jstr_of(v: &J) -> String {
    if let J::S(s) = v {
        s.clone()
    } else {
        String::new()
    }
}

fn verify(artifact: &Path, att: &J, key: &str) -> (bool, Vec<String>) {
    let mut problems = Vec::new();
    let sig = match jget(att, "signature") {
        Some(s) => s,
        None => return (false, vec!["no signature".into()]),
    };
    // strip signature, recompute
    let statement = if let J::O(m) = att {
        let mut m2 = m.clone();
        m2.remove("signature");
        J::O(m2)
    } else {
        att.clone()
    };
    let payload = canonical(&statement);
    let expected = hmac_sha256_hex(&resolve_key(key), payload.as_bytes());
    let actual_sig = sig.clone();
    if jstr_of(jget(&actual_sig, "value").unwrap_or(&J::S(String::new()))) != expected {
        problems.push("signature mismatch".into());
    }
    if !artifact.exists() {
        problems.push(format!("artifact not found: {}", artifact.display()));
    } else {
        let actual = subject_digest(artifact);
        let claimed = jget(att, "subject")
            .and_then(|s| if let J::A(a) = s { a.first() } else { None })
            .and_then(|s0| jget(s0, "digest"))
            .and_then(|d| jget(d, "sha256"))
            .map(jstr_of)
            .unwrap_or_default();
        if claimed != actual {
            problems.push("subject digest mismatch".into());
        }
    }
    (problems.is_empty(), problems)
}

// --------------------------------------------------------------------------- //
// CLI
// --------------------------------------------------------------------------- //
fn flag_val(args: &[String], name: &str) -> String {
    for i in 0..args.len() {
        if args[i] == name && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    String::new()
}

fn positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            i += 2;
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}

fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: attestport {{sbom|attest|verify|--version}}");
        return 2;
    }
    let cmd = &args[0];
    let rest = &args[1..];
    let pos = positional(rest);
    match cmd.as_str() {
        "--version" | "-v" => {
            println!("{} {}", TOOL_NAME, TOOL_VERSION);
            0
        }
        "sbom" => match generate_sbom(Path::new(&pos[0])) {
            Ok(bom) => {
                println!("{}", pretty(&bom, 0));
                0
            }
            Err(e) => {
                eprintln!("error: {}", e);
                2
            }
        },
        "attest" => match attest(Path::new(&pos[0]), &flag_val(rest, "--key")) {
            Ok(att) => {
                println!("{}", pretty(&att, 0));
                0
            }
            Err(e) => {
                eprintln!("error: {}", e);
                2
            }
        },
        "verify" => {
            let data = match fs::read_to_string(&pos[1]) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return 2;
                }
            };
            let att = match parse::parse(&data) {
                Some(a) => a,
                None => {
                    eprintln!("error: cannot parse attestation");
                    return 2;
                }
            };
            let (ok, problems) = verify(Path::new(&pos[0]), &att, &flag_val(rest, "--key"));
            if ok {
                println!("VERIFY: PASS");
                0
            } else {
                println!("VERIFY: FAIL");
                for p in problems {
                    println!("  - {}", p);
                }
                1
            }
        }
        _ => {
            eprintln!("unknown command: {}", cmd);
            2
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    exit(run(&args));
}

// --------------------------------------------------------------------------- //
// Tests
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty_vector() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_abc() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_hmac_known() {
        // HMAC-SHA256(key="key", "The quick brown fox jumps over the lazy dog")
        assert_eq!(
            hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_canonical_order_independent() {
        let mut a = BTreeMap::new();
        a.insert("b".to_string(), J::N(1.0));
        a.insert("a".to_string(), J::N(2.0));
        assert_eq!(canonical(&J::O(a)), "{\"a\":2,\"b\":1}");
    }

    #[test]
    fn test_pinned_detection() {
        let comps = parse_requirements("a==1.0\nb>=2\nc\n");
        let by: BTreeMap<_, _> = comps.iter().map(|c| (c.name.clone(), c.pinned)).collect();
        assert_eq!(by["a"], true);
        assert_eq!(by["b"], false);
        assert_eq!(by["c"], false);
    }

    #[test]
    fn test_sbom_and_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ap-rust-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
        let bom = generate_sbom(&dir).unwrap();
        assert_eq!(jstr_of(jget(&bom, "bomFormat").unwrap()), "CycloneDX");
        let att = attest(&dir, "k").unwrap();
        let (ok, _) = verify(&dir, &att, "k");
        assert!(ok);
        let (bad, _) = verify(&dir, &att, "other");
        assert!(!bad);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_purl_scoped() {
        assert_eq!(purl("npm", "@scope/x", "1.0.0"), "pkg:npm/%40scope/x@1.0.0");
    }
}
