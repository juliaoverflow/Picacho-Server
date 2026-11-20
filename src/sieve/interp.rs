//! Sieve interpreter: runs a parsed script against one message and returns
//! the actions to take. Pure (no I/O): everything the script may look at is
//! in `Env`.
use super::parse::{Arg, Command, Script, Test};
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    FileInto { folder: String, flags: Vec<String>, create: bool },
    Keep { flags: Vec<String> },
    Redirect { addr: String },
    Reject { reason: String },
    Discard,
    Vacation(Vacation),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Vacation {
    pub seconds: i64,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub addresses: Vec<String>,
    pub mime: bool,
    pub handle: String,
    pub reason: String,
}

/// What the script can see.
pub struct Env<'a> {
    /// Header fields in message order: (lower-case name, decoded unfolded value).
    pub headers: Vec<(String, String)>,
    pub body_text: &'a str,
    pub raw: &'a [u8],
    pub size: u64,
    pub envelope_from: String,
    pub envelope_to: String,
    /// The account's folders (for mailboxexists).
    pub folders: Vec<String>,
    /// Other scripts of the account (for include).
    pub scripts: HashMap<String, Script>,
    /// 0 = not scanned; 1..=10 per RFC 5235.
    pub spamtest: u8,
    /// 0 = not scanned, 1 = clean, 5 = infected.
    pub virustest: u8,
    pub now: chrono::DateTime<chrono::Utc>,
}

pub struct Outcome {
    pub actions: Vec<Action>,
    /// Implicit keep still applies.
    pub keep: bool,
    /// Flags for the implicit keep (imap4flags).
    pub flags: Vec<String>,
    pub errors: Vec<String>,
}

struct Run<'a, 'e> {
    env: &'e Env<'a>,
    requires: BTreeSet<String>,
    vars: HashMap<String, String>,
    matches: Vec<String>,
    flags: BTreeSet<String>,
    actions: Vec<Action>,
    cancel_keep: bool,
    stopped: bool,
    steps: usize,
    included: BTreeSet<String>,
    depth: usize,
    returned: bool,
}

const MAX_STEPS: usize = 100_000;
const MAX_ACTIONS: usize = 64;

pub fn run(script: &Script, env: &Env<'_>) -> Outcome {
    let mut r = Run {
        env,
        requires: script.requires.iter().cloned().collect(),
        vars: HashMap::new(),
        matches: vec![],
        flags: BTreeSet::new(),
        actions: vec![],
        cancel_keep: false,
        stopped: false,
        steps: 0,
        included: BTreeSet::new(),
        depth: 0,
        returned: false,
    };
    let mut errors = vec![];
    if let Err(e) = r.block(&script.commands) {
        errors.push(e);
        // RFC 5228 2.10.6: on a runtime error, fall back to implicit keep.
        r.actions.retain(|a| !matches!(a, Action::Discard));
        r.cancel_keep = false;
    }
    let flags: Vec<String> = r.flags.iter().cloned().collect();
    Outcome { actions: r.actions, keep: !r.cancel_keep, flags, errors }
}

// ------------------------------------------------------------------ helpers

#[derive(Clone, Copy, PartialEq)]
enum Comparator {
    Octet,
    CaseMap,
    Numeric,
}

#[derive(Clone, PartialEq)]
enum MatchType {
    Is,
    Contains,
    Matches,
    Regex,
    Value(String),
    Count(String),
}

struct Opts {
    comparator: Comparator,
    mtype: MatchType,
    part: String,
    positional: Vec<Arg>,
    tags: Vec<String>,
    tag_values: HashMap<String, Arg>,
}

/// Split tagged arguments from positional ones. `with_value` lists tags
/// followed by an argument.
fn opts(args: &[Arg], with_value: &[&str]) -> Opts {
    let mut o = Opts { comparator: Comparator::CaseMap, mtype: MatchType::Is, part: "all".into(), positional: vec![], tags: vec![], tag_values: HashMap::new() };
    let mut i = 0;
    while i < args.len() {
        match &args[i] {
            Arg::Tag(t) => {
                let t = t.as_str();
                match t {
                    "is" => o.mtype = MatchType::Is,
                    "contains" => o.mtype = MatchType::Contains,
                    "matches" => o.mtype = MatchType::Matches,
                    "regex" => o.mtype = MatchType::Regex,
                    "value" | "count" => {
                        let op = match args.get(i + 1) {
                            Some(Arg::Str(s)) => s.to_ascii_lowercase(),
                            _ => "eq".into(),
                        };
                        i += 1;
                        o.mtype = if t == "value" { MatchType::Value(op) } else { MatchType::Count(op) };
                    }
                    "comparator" => {
                        if let Some(Arg::Str(c)) = args.get(i + 1) {
                            o.comparator = match c.as_str() {
                                "i;octet" => Comparator::Octet,
                                "i;ascii-numeric" => Comparator::Numeric,
                                _ => Comparator::CaseMap,
                            };
                        }
                        i += 1;
                    }
                    "all" | "localpart" | "domain" | "user" | "detail" => o.part = t.to_string(),
                    _ if with_value.contains(&t) => {
                        if let Some(v) = args.get(i + 1) {
                            o.tag_values.insert(t.to_string(), v.clone());
                        }
                        i += 1;
                    }
                    _ => o.tags.push(t.to_string()),
                }
            }
            a => o.positional.push(a.clone()),
        }
        i += 1;
    }
    o
}

fn numeric(s: &str) -> Option<u64> {
    let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if d.is_empty() {
        None
    } else {
        d.parse().ok().or(Some(u64::MAX))
    }
}

fn compare(cmp: Comparator, a: &str, b: &str) -> std::cmp::Ordering {
    match cmp {
        Comparator::Octet => a.as_bytes().cmp(b.as_bytes()),
        Comparator::CaseMap => a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()),
        Comparator::Numeric => match (numeric(a), numeric(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
        },
    }
}

fn relational(op: &str, ord: std::cmp::Ordering) -> bool {
    use std::cmp::Ordering::*;
    match op {
        "gt" => ord == Greater,
        "ge" => ord != Less,
        "lt" => ord == Less,
        "le" => ord != Greater,
        "ne" => ord != Equal,
        _ => ord == Equal,
    }
}

/// `:matches` glob with `*` and `?`, recording what each wildcard matched.
fn glob(pat: &[char], s: &[char], fold: bool, caps: &mut Vec<String>) -> bool {
    fn eq(a: char, b: char, fold: bool) -> bool {
        if fold {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    }
    fn go(p: &[char], s: &[char], fold: bool, caps: &mut Vec<String>, budget: &mut u32) -> bool {
        *budget = budget.saturating_sub(1);
        if *budget == 0 {
            return false;
        }
        match p.first() {
            None => s.is_empty(),
            Some('*') => {
                for k in 0..=s.len() {
                    caps.push(s[..k].iter().collect());
                    if go(&p[1..], &s[k..], fold, caps, budget) {
                        return true;
                    }
                    caps.pop();
                }
                false
            }
            Some('?') => {
                if s.is_empty() {
                    return false;
                }
                caps.push(s[0].to_string());
                if go(&p[1..], &s[1..], fold, caps, budget) {
                    return true;
                }
                caps.pop();
                false
            }
            Some('\\') if p.len() > 1 => !s.is_empty() && eq(p[1], s[0], fold) && go(&p[2..], &s[1..], fold, caps, budget),
            Some(c) => !s.is_empty() && eq(*c, s[0], fold) && go(&p[1..], &s[1..], fold, caps, budget),
        }
    }
    let mut budget = 200_000;
    go(pat, s, fold, caps, &mut budget)
}

fn match_one(o: &Opts, value: &str, key: &str, caps: &mut Vec<String>) -> bool {
    let fold = o.comparator == Comparator::CaseMap;
    match &o.mtype {
        MatchType::Is => compare(o.comparator, value, key) == std::cmp::Ordering::Equal,
        MatchType::Contains => {
            if fold {
                value.to_ascii_lowercase().contains(&key.to_ascii_lowercase())
            } else {
                value.contains(key)
            }
        }
        MatchType::Matches => {
            let p: Vec<char> = key.chars().collect();
            let s: Vec<char> = value.chars().collect();
            let mut c = vec![];
            if glob(&p, &s, fold, &mut c) {
                *caps = std::iter::once(value.to_string()).chain(c).collect();
                true
            } else {
                false
            }
        }
        MatchType::Regex => {
            let Ok(re) = regex::RegexBuilder::new(key).case_insensitive(fold).size_limit(1 << 20).build() else { return false };
            match re.captures(value) {
                Some(c) => {
                    *caps = c.iter().map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default()).collect();
                    true
                }
                None => false,
            }
        }
        MatchType::Value(op) => relational(op, compare(o.comparator, value, key)),
        MatchType::Count(_) => false,
    }
}

/// Apply a match over values × keys (with :count handled on the number of values).
fn match_any(o: &Opts, values: &[String], keys: &[String], caps: &mut Vec<String>) -> bool {
    if let MatchType::Count(op) = &o.mtype {
        let n = values.len().to_string();
        return keys.iter().any(|k| relational(op, compare(Comparator::Numeric, &n, k)));
    }
    for v in values {
        for k in keys {
            if match_one(o, v, k, caps) {
                return true;
            }
        }
    }
    false
}

/// Addresses in a header value: `"Name" <a@b>, c@d` -> [a@b, c@d].
pub fn addresses(v: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    let mut angle = false;
    let mut depth = 0;
    let push = |cur: &mut String, out: &mut Vec<String>| {
        let s = cur.trim();
        if let (Some(a), Some(b)) = (s.rfind('<'), s.rfind('>')) {
            if a < b {
                out.push(s[a + 1..b].trim().to_string());
                cur.clear();
                return;
            }
        }
        let bare: String = s.split_whitespace().find(|w| w.contains('@')).unwrap_or(s).trim_matches(|c| c == '<' || c == '>' || c == '"').to_string();
        if !bare.is_empty() {
            out.push(bare);
        }
        cur.clear();
    };
    for c in v.chars() {
        match c {
            '"' if depth == 0 => {
                quoted = !quoted;
                cur.push(c);
            }
            '(' if !quoted => depth += 1,
            ')' if !quoted && depth > 0 => depth -= 1,
            _ if depth > 0 => {}
            '<' if !quoted => {
                angle = true;
                cur.push(c);
            }
            '>' if !quoted => {
                angle = false;
                cur.push(c);
            }
            ',' if !quoted && !angle => push(&mut cur, &mut out),
            ';' if !quoted && !angle => push(&mut cur, &mut out), // end of a group
            ':' if !quoted && !angle && !cur.contains('@') => cur.clear(), // group name
            _ => cur.push(c),
        }
    }
    push(&mut cur, &mut out);
    out
}

fn address_part(addr: &str, part: &str) -> Option<String> {
    let (local, domain) = addr.rsplit_once('@').unwrap_or((addr, ""));
    Some(match part {
        "localpart" => local.to_string(),
        "domain" => domain.to_string(),
        "user" => local.split_once('+').map(|(u, _)| u).unwrap_or(local).to_string(),
        "detail" => local.split_once('+')?.1.to_string(),
        _ => addr.to_string(),
    })
}

fn parse_date(v: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let v = v.trim();
    chrono::DateTime::parse_from_rfc2822(v).ok().or_else(|| {
        // Strip trailing comments like "(PST)".
        let cut = v.find('(').map(|i| &v[..i]).unwrap_or(v).trim();
        chrono::DateTime::parse_from_rfc2822(cut).ok()
    })
}

fn date_part(d: &chrono::DateTime<chrono::FixedOffset>, part: &str) -> Option<String> {
    use chrono::{Datelike, Timelike};
    Some(match part {
        "year" => format!("{:04}", d.year()),
        "month" => format!("{:02}", d.month()),
        "day" => format!("{:02}", d.day()),
        "date" => d.format("%Y-%m-%d").to_string(),
        "julian" => {
            let epoch = chrono::NaiveDate::from_ymd_opt(1858, 11, 17)?;
            (d.date_naive() - epoch).num_days().to_string()
        }
        "hour" => format!("{:02}", d.hour()),
        "minute" => format!("{:02}", d.minute()),
        "second" => format!("{:02}", d.second()),
        "time" => d.format("%H:%M:%S").to_string(),
        "iso8601" => d.to_rfc3339(),
        "std11" => d.to_rfc2822(),
        "zone" => d.format("%z").to_string(),
        "weekday" => d.weekday().num_days_from_sunday().to_string(),
        _ => return None,
    })
}

fn zone(z: &str) -> Option<chrono::FixedOffset> {
    let z = z.trim();
    if z.len() != 5 {
        return None;
    }
    let sign = if z.starts_with('-') { -1 } else { 1 };
    let h: i32 = z[1..3].parse().ok()?;
    let m: i32 = z[3..5].parse().ok()?;
    chrono::FixedOffset::east_opt(sign * (h * 3600 + m * 60))
}

impl Run<'_, '_> {
    fn has(&self, ext: &str) -> bool {
        self.requires.contains(ext)
    }

    /// Expand variables and encoded characters in a string argument.
    fn expand(&self, s: &str) -> String {
        if !s.contains("${") {
            return s.to_string();
        }
        let vars = self.has("variables");
        let enc = self.has("encoded-character");
        let mut out = String::with_capacity(s.len());
        let b: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < b.len() {
            if b[i] == '$' && b.get(i + 1) == Some(&'{') {
                if let Some(end) = b[i + 2..].iter().position(|c| *c == '}') {
                    let inner: String = b[i + 2..i + 2 + end].iter().collect();
                    let lower = inner.to_ascii_lowercase();
                    let mut replaced = None;
                    if enc {
                        if let Some(h) = lower.strip_prefix("hex:") {
                            let bytes: Option<Vec<u8>> = h.split_whitespace().map(|x| u8::from_str_radix(x, 16).ok()).collect();
                            replaced = bytes.and_then(|b| String::from_utf8(b).ok());
                        } else if let Some(u) = lower.strip_prefix("unicode:") {
                            let chars: Option<String> = u.split_whitespace().map(|x| u32::from_str_radix(x, 16).ok().and_then(char::from_u32)).collect();
                            replaced = chars;
                        }
                    }
                    if replaced.is_none() && vars {
                        if let Ok(n) = inner.parse::<usize>() {
                            replaced = Some(self.matches.get(n).cloned().unwrap_or_default());
                        } else if inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') && !inner.is_empty() {
                            replaced = Some(self.vars.get(&lower).cloned().unwrap_or_default());
                        }
                    }
                    if let Some(r) = replaced {
                        out.push_str(&r);
                        i += 3 + end;
                        continue;
                    }
                }
            }
            out.push(b[i]);
            i += 1;
        }
        out
    }

    fn strs(&self, a: Option<&Arg>) -> Vec<String> {
        a.and_then(|a| a.strings()).unwrap_or_default().iter().map(|s| self.expand(s)).collect()
    }

    fn str1(&self, a: Option<&Arg>) -> String {
        self.strs(a).into_iter().next().unwrap_or_default()
    }

    fn header_values(&self, names: &[String]) -> Vec<String> {
        let names: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        self.env.headers.iter().filter(|(n, _)| names.contains(n)).map(|(_, v)| v.clone()).collect()
    }

    fn set_matches(&mut self, caps: Vec<String>) {
        if self.has("variables") && !caps.is_empty() {
            self.matches = caps;
        }
    }

    fn test(&mut self, t: &Test) -> Result<bool, String> {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            return Err("script ran too long".into());
        }
        let mut caps = vec![];
        let r = match t.name.as_str() {
            "true" => true,
            "false" => false,
            "not" => !self.test(t.tests.first().ok_or("not needs a test")?)?,
            "allof" => {
                for x in &t.tests {
                    if !self.test(x)? {
                        return Ok(false);
                    }
                }
                true
            }
            "anyof" => {
                for x in &t.tests {
                    if self.test(x)? {
                        return Ok(true);
                    }
                }
                false
            }
            "exists" => {
                let names = self.strs(t.args.first());
                names.iter().all(|n| self.env.headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(n)))
            }
            "size" => {
                let o = opts(&t.args, &[]);
                let n = match o.positional.first() {
                    Some(Arg::Num(n)) => *n,
                    _ => return Err("size needs a number".into()),
                };
                if o.tags.iter().any(|x| x == "over") {
                    self.env.size > n
                } else {
                    self.env.size < n
                }
            }
            "header" => {
                let o = opts(&t.args, &["index"]);
                let names = self.strs(o.positional.first());
                let keys = self.strs(o.positional.get(1));
                let mut vals = self.header_values(&names);
                self.apply_index(&o, &mut vals);
                match_any(&o, &vals, &keys, &mut caps)
            }
            "address" | "envelope" => {
                let o = opts(&t.args, &["index"]);
                let names = self.strs(o.positional.first());
                let keys = self.strs(o.positional.get(1));
                let addrs: Vec<String> = if t.name == "envelope" {
                    names
                        .iter()
                        .filter_map(|n| match n.to_ascii_lowercase().as_str() {
                            "from" => Some(self.env.envelope_from.clone()),
                            "to" => Some(self.env.envelope_to.clone()),
                            _ => None,
                        })
                        .collect()
                } else {
                    let mut vals = self.header_values(&names);
                    self.apply_index(&o, &mut vals);
                    vals.iter().flat_map(|v| addresses(v)).collect()
                };
                let parts: Vec<String> = addrs
                    .iter()
                    .filter_map(|a| if a.is_empty() && o.part != "all" { None } else { address_part(a, &o.part) })
                    .collect();
                match_any(&o, &parts, &keys, &mut caps)
            }
            "body" => {
                let o = opts(&t.args, &["content"]);
                let keys = self.strs(o.positional.first());
                let text = if o.tags.iter().any(|x| x == "raw") {
                    let raw = self.env.raw;
                    let start = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(raw.len());
                    String::from_utf8_lossy(&raw[start..]).to_string()
                } else {
                    self.env.body_text.to_string()
                };
                let mut o2 = o;
                if o2.mtype == MatchType::Is {
                    // :is on a body compares the whole text.
                }
                if matches!(o2.mtype, MatchType::Value(_) | MatchType::Count(_)) {
                    o2.mtype = MatchType::Contains;
                }
                keys.iter().any(|k| match_one(&o2, &text, k, &mut caps))
            }
            "string" => {
                let o = opts(&t.args, &[]);
                let src = self.strs(o.positional.first());
                let keys = self.strs(o.positional.get(1));
                let src: Vec<String> = if matches!(o.mtype, MatchType::Count(_)) { src.into_iter().filter(|s| !s.is_empty()).collect() } else { src };
                match_any(&o, &src, &keys, &mut caps)
            }
            "hasflag" => {
                let o = opts(&t.args, &[]);
                let (vars, keys) = if o.positional.len() >= 2 {
                    (Some(self.strs(o.positional.first())), self.strs(o.positional.get(1)))
                } else {
                    (None, self.strs(o.positional.first()))
                };
                let flags: Vec<String> = match vars {
                    Some(v) => v.iter().flat_map(|n| self.vars.get(&n.to_ascii_lowercase()).cloned().unwrap_or_default().split_whitespace().map(|s| s.to_string()).collect::<Vec<_>>()).collect(),
                    None => self.flags.iter().cloned().collect(),
                };
                match_any(&o, &flags, &keys, &mut caps)
            }
            "mailboxexists" => {
                let names = self.strs(t.args.first());
                names.iter().all(|n| self.env.folders.iter().any(|f| f.eq_ignore_ascii_case(n) || (n.eq_ignore_ascii_case("inbox") && f.eq_ignore_ascii_case("inbox"))))
            }
            "spamtest" | "virustest" => {
                let o = opts(&t.args, &[]);
                let keys = self.strs(o.positional.first());
                let v = if t.name == "spamtest" { self.env.spamtest } else { self.env.virustest };
                let mut o2 = o;
                o2.comparator = Comparator::Numeric;
                match_any(&o2, &[v.to_string()], &keys, &mut caps)
            }
            "date" | "currentdate" => {
                let o = opts(&t.args, &["zone", "index"]);
                let (date, part, keys) = if t.name == "date" {
                    let names = self.strs(o.positional.first());
                    let mut vals = self.header_values(&names);
                    self.apply_index(&o, &mut vals);
                    let d = vals.first().and_then(|v| parse_date(v));
                    (d, self.str1(o.positional.get(1)), self.strs(o.positional.get(2)))
                } else {
                    (Some(self.env.now.fixed_offset()), self.str1(o.positional.first()), self.strs(o.positional.get(1)))
                };
                let Some(mut d) = date else { return Ok(false) };
                if !o.tags.iter().any(|x| x == "originalzone") {
                    let z = o.tag_values.get("zone").and_then(|a| a.strings()).and_then(|v| v.first().cloned());
                    let off = z.as_deref().and_then(zone).unwrap_or_else(|| chrono::FixedOffset::east_opt(0).unwrap());
                    d = d.with_timezone(&off);
                }
                match date_part(&d, &part.to_ascii_lowercase()) {
                    Some(v) => match_any(&o, &[v], &keys, &mut caps),
                    None => false,
                }
            }
            other => return Err(format!("unknown test {other}")),
        };
        if r {
            self.set_matches(caps);
        }
        Ok(r)
    }

    fn apply_index(&self, o: &Opts, vals: &mut Vec<String>) {
        if let Some(Arg::Num(n)) = o.tag_values.get("index") {
            let n = *n as usize;
            if n == 0 || n > vals.len() {
                vals.clear();
                return;
            }
            let idx = if o.tags.iter().any(|t| t == "last") { vals.len() - n } else { n - 1 };
            *vals = vec![vals[idx].clone()];
        }
    }

    fn add_action(&mut self, a: Action) -> Result<(), String> {
        if self.actions.len() >= MAX_ACTIONS {
            return Err("too many actions".into());
        }
        if !self.actions.contains(&a) {
            self.actions.push(a);
        }
        Ok(())
    }

    fn flag_args(&self, o: &Opts) -> Vec<String> {
        let list = if o.positional.len() >= 2 { self.strs(o.positional.get(1)) } else { self.strs(o.positional.first()) };
        list.iter().flat_map(|s| s.split_whitespace().map(|x| x.to_string()).collect::<Vec<_>>()).collect()
    }

    fn block(&mut self, cmds: &[Command]) -> Result<(), String> {
        let mut last_if: Option<bool> = None;
        for c in cmds {
            if self.stopped || self.returned {
                return Ok(());
            }
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Err("script ran too long".into());
            }
            match c.name.as_str() {
                "require" => {}
                "if" => {
                    let ok = self.test(&c.tests[0])?;
                    if ok {
                        self.block(c.block.as_deref().unwrap_or(&[]))?;
                    }
                    last_if = Some(ok);
                    continue;
                }
                "elsif" => {
                    if last_if == Some(false) {
                        let ok = self.test(&c.tests[0])?;
                        if ok {
                            self.block(c.block.as_deref().unwrap_or(&[]))?;
                        }
                        last_if = Some(ok);
                    }
                    continue;
                }
                "else" => {
                    if last_if == Some(false) {
                        self.block(c.block.as_deref().unwrap_or(&[]))?;
                    }
                    last_if = None;
                    continue;
                }
                "stop" => {
                    self.stopped = true;
                }
                "return" => {
                    self.returned = true;
                }
                "keep" => {
                    let o = opts(&c.args, &["flags"]);
                    let flags = self.explicit_flags(&o);
                    self.add_action(Action::Keep { flags })?;
                    self.cancel_keep = true;
                }
                "discard" => {
                    self.cancel_keep = true;
                    self.add_action(Action::Discard)?;
                }
                "fileinto" => {
                    let o = opts(&c.args, &["flags"]);
                    let folder = self.str1(o.positional.first());
                    let flags = self.explicit_flags(&o);
                    let create = o.tags.iter().any(|t| t == "create");
                    self.add_action(Action::FileInto { folder, flags, create })?;
                    if !o.tags.iter().any(|t| t == "copy") {
                        self.cancel_keep = true;
                    }
                }
                "redirect" => {
                    let o = opts(&c.args, &[]);
                    let addr = self.str1(o.positional.first());
                    if crate::util::normalize_address(&addr).is_none() {
                        return Err(format!("redirect: invalid address {addr}"));
                    }
                    self.add_action(Action::Redirect { addr })?;
                    if !o.tags.iter().any(|t| t == "copy") {
                        self.cancel_keep = true;
                    }
                }
                "reject" | "ereject" => {
                    let reason = self.str1(c.args.iter().find(|a| matches!(a, Arg::Str(_) | Arg::List(_))));
                    self.add_action(Action::Reject { reason })?;
                    self.cancel_keep = true;
                }
                "setflag" | "addflag" | "removeflag" => {
                    let o = opts(&c.args, &[]);
                    let var = if o.positional.len() >= 2 { Some(self.str1(o.positional.first()).to_ascii_lowercase()) } else { None };
                    let flags = self.flag_args(&o);
                    let mut set: BTreeSet<String> = match &var {
                        Some(v) => self.vars.get(v).cloned().unwrap_or_default().split_whitespace().map(|s| s.to_string()).collect(),
                        None => self.flags.clone(),
                    };
                    match c.name.as_str() {
                        "setflag" => set = flags.into_iter().collect(),
                        "addflag" => set.extend(flags),
                        _ => {
                            for f in flags {
                                set.retain(|x| !x.eq_ignore_ascii_case(&f));
                            }
                        }
                    }
                    match var {
                        Some(v) => {
                            self.vars.insert(v, set.into_iter().collect::<Vec<_>>().join(" "));
                        }
                        None => self.flags = set,
                    }
                }
                "set" => {
                    let o = opts(&c.args, &[]);
                    let name = self.str1(o.positional.first()).to_ascii_lowercase();
                    let mut v = self.str1(o.positional.get(1));
                    // Modifiers apply in precedence order (RFC 5229 4.1).
                    let has = |m: &str| o.tags.iter().any(|t| t == m);
                    if has("lower") {
                        v = v.to_lowercase();
                    }
                    if has("upper") {
                        v = v.to_uppercase();
                    }
                    if has("lowerfirst") {
                        let mut ch = v.chars();
                        v = ch.next().map(|f| f.to_lowercase().collect::<String>() + ch.as_str()).unwrap_or_default();
                    }
                    if has("upperfirst") {
                        let mut ch = v.chars();
                        v = ch.next().map(|f| f.to_uppercase().collect::<String>() + ch.as_str()).unwrap_or_default();
                    }
                    if has("quotewildcard") {
                        v = v.replace('\\', "\\\\").replace('*', "\\*").replace('?', "\\?");
                    }
                    if has("length") {
                        v = v.chars().count().to_string();
                    }
                    self.vars.insert(name, v);
                }
                "vacation" => {
                    let o = opts(&c.args, &["days", "seconds", "subject", "from", "addresses", "handle"]);
                    let num = |k: &str| match o.tag_values.get(k) {
                        Some(Arg::Num(n)) => Some(*n as i64),
                        _ => None,
                    };
                    let seconds = num("seconds").or(num("days").map(|d| d * 86400)).unwrap_or(7 * 86400);
                    let sv = |k: &str| o.tag_values.get(k).map(|a| self.str1(Some(a)));
                    let reason = self.str1(o.positional.first());
                    let handle = sv("handle").unwrap_or_else(|| crate::util::sha256_hex(format!("{reason}{:?}", sv("subject")).as_bytes())[..16].to_string());
                    self.add_action(Action::Vacation(Vacation {
                        seconds: seconds.clamp(0, 365 * 86400),
                        subject: sv("subject"),
                        from: sv("from"),
                        addresses: o.tag_values.get("addresses").map(|a| self.strs(Some(a))).unwrap_or_default(),
                        mime: o.tags.iter().any(|t| t == "mime"),
                        handle,
                        reason,
                    }))?;
                }
                "include" => {
                    let o = opts(&c.args, &[]);
                    let name = self.str1(o.positional.first());
                    let once = o.tags.iter().any(|t| t == "once");
                    let optional = o.tags.iter().any(|t| t == "optional");
                    if once && self.included.contains(&name) {
                        continue;
                    }
                    if self.depth >= 8 {
                        return Err("include nested too deeply".into());
                    }
                    match self.env.scripts.get(&name) {
                        Some(s) => {
                            self.included.insert(name);
                            let saved = std::mem::replace(&mut self.requires, s.requires.iter().cloned().collect());
                            self.depth += 1;
                            let r = self.block(&s.commands);
                            self.depth -= 1;
                            self.requires = saved;
                            self.returned = false;
                            r?;
                        }
                        None if optional => {}
                        None => return Err(format!("include: no script named {name}")),
                    }
                }
                "global" => {}
                other => return Err(format!("unknown command {other}")),
            }
            last_if = None;
        }
        Ok(())
    }

    fn explicit_flags(&self, o: &Opts) -> Vec<String> {
        match o.tag_values.get("flags") {
            Some(a) => self.strs(Some(a)).iter().flat_map(|s| s.split_whitespace().map(|x| x.to_string()).collect::<Vec<_>>()).collect(),
            None => self.flags.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse::parse;
    use super::*;

    fn env<'a>(raw: &'a [u8], body: &'a str) -> Env<'a> {
        Env {
            headers: vec![
                ("from".into(), "\"Alice\" <alice+lists@example.com>".into()),
                ("to".into(), "bob@example.org".into()),
                ("subject".into(), "[dev] Weekly report".into()),
                ("date".into(), "Tue, 1 Jul 2025 10:00:00 +0200".into()),
                ("x-spam-flag".into(), "NO".into()),
            ],
            body_text: body,
            raw,
            size: raw.len() as u64,
            envelope_from: "alice@example.com".into(),
            envelope_to: "bob+tag@example.org".into(),
            folders: vec!["INBOX".into(), "Lists".into()],
            scripts: HashMap::new(),
            spamtest: 2,
            virustest: 1,
            now: chrono::Utc::now(),
        }
    }

    #[test]
    fn fileinto_and_keep() {
        let s = parse(r#"require ["fileinto", "variables", "subaddress", "envelope", "imap4flags", "relational", "comparator-i;ascii-numeric", "spamtest", "date"];
if header :matches "subject" "[*] *" { fileinto "Lists/${1}"; }
if address :detail "from" "lists" { addflag "\\Flagged"; }
if envelope :user "to" "bob" { set "who" "${0}"; }
if spamtest :value "ge" :comparator "i;ascii-numeric" "5" { discard; }
if date :value "ge" "date" "year" "2020" { addflag "$Recent2020"; }
"#)
        .unwrap();
        let raw = b"Subject: x\r\n\r\nhello";
        let o = run(&s, &env(raw, "hello"));
        assert!(o.errors.is_empty(), "{:?}", o.errors);
        assert_eq!(o.actions, vec![Action::FileInto { folder: "Lists/dev".into(), flags: vec![], create: false }]);
        assert!(!o.keep);
        assert!(o.flags.contains(&"\\Flagged".to_string()));
        assert!(o.flags.contains(&"$Recent2020".to_string()));
    }

    #[test]
    fn copy_redirect_vacation() {
        let s = parse(r#"require ["copy", "vacation", "body"];
redirect :copy "archive@example.net";
if body :contains "urgent" { stop; }
vacation :days 3 :subject "Away" "I'm away";
"#)
        .unwrap();
        let o = run(&s, &env(b"", "not urgent at all"));
        assert!(o.keep);
        assert_eq!(o.actions.len(), 1);
        let o = run(&s, &env(b"", "nothing special"));
        assert!(matches!(&o.actions[1], Action::Vacation(v) if v.seconds == 3 * 86400 && v.subject.as_deref() == Some("Away")));
    }

    #[test]
    fn address_parsing() {
        assert_eq!(addresses("\"Doe, J\" <j@x.com>, k@y.org (Kay), Group: a@b.c, d@e.f;"), vec!["j@x.com", "k@y.org", "a@b.c", "d@e.f"]);
    }

    #[test]
    fn regex_and_count() {
        let s = parse(r#"require ["regex", "relational", "variables", "comparator-i;ascii-numeric"];
if header :regex "subject" "^\\[([a-z]+)\\]" { set "tag" "${1}"; }
if header :count "ge" :comparator "i;ascii-numeric" "to" "1" { set "n" "many"; }
if string :is "${tag}" "dev" { discard; }
"#)
        .unwrap();
        let o = run(&s, &env(b"", ""));
        assert_eq!(o.actions, vec![Action::Discard]);
    }
}
