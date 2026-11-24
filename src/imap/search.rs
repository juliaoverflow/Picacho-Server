//! SEARCH: key parsing and evaluation.
use super::proto::Arg;
use super::seq::{has_flag, SeqSet};
use chrono::{NaiveDate, TimeZone};

#[derive(Debug, Clone)]
pub enum Key {
    All,
    Flag(&'static str, bool),
    Keyword(String, bool),
    New,
    Old,
    Recent(bool),
    Header(String, Vec<u8>),
    Body(Vec<u8>),
    Text(Vec<u8>),
    Before(NaiveDate),
    On(NaiveDate),
    Since(NaiveDate),
    SentBefore(NaiveDate),
    SentOn(NaiveDate),
    SentSince(NaiveDate),
    Larger(i64),
    Smaller(i64),
    Uid(SeqSet),
    Seq(SeqSet),
    Not(Box<Key>),
    Or(Box<Key>, Box<Key>),
    And(Vec<Key>),
    /// CONDSTORE: messages with mod-sequence >= n.
    ModSeq(i64),
    /// WITHIN: internal date older / younger than n seconds.
    Older(i64),
    Younger(i64),
    /// SEARCHRES (RFC 5182): the result saved by an earlier `RETURN (SAVE)`.
    Saved,
    /// OBJECTID (RFC 8474).
    EmailId(i64),
    ThreadId(i64),
    /// SAVEDATE (RFC 8514): when the message was put in the mailbox.
    SavedBefore(NaiveDate),
    SavedOn(NaiveDate),
    SavedSince(NaiveDate),
    /// SEARCH=FUZZY (RFC 6203): text keys inside match loosely.
    Fuzzy(Box<Key>),
}

impl Key {
    /// Whether the criteria use MODSEQ (enables CONDSTORE).
    pub fn uses_modseq(&self) -> bool {
        match self {
            Key::ModSeq(_) => true,
            Key::Not(k) | Key::Fuzzy(k) => k.uses_modseq(),
            Key::Or(a, b) => a.uses_modseq() || b.uses_modseq(),
            Key::And(v) => v.iter().any(|k| k.uses_modseq()),
            _ => false,
        }
    }

    /// Whether evaluating needs the message content.
    pub fn needs_content(&self) -> bool {
        match self {
            Key::Header(..) | Key::Body(_) | Key::Text(_) | Key::SentBefore(_) | Key::SentOn(_) | Key::SentSince(_) => true,
            Key::Not(k) | Key::Fuzzy(k) => k.needs_content(),
            Key::Or(a, b) => a.needs_content() || b.needs_content(),
            Key::And(v) => v.iter().any(|k| k.needs_content()),
            _ => false,
        }
    }
}

pub fn parse_date(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s, "%d-%b-%Y").ok()
}

pub struct KeyParser<'a> {
    args: &'a [Arg],
    pub i: usize,
}

impl<'a> KeyParser<'a> {
    pub fn new(args: &'a [Arg]) -> Self {
        Self { args, i: 0 }
    }

    fn next(&mut self) -> Result<&'a Arg, String> {
        let a = self.args.get(self.i).ok_or("Missing search argument")?;
        self.i += 1;
        Ok(a)
    }

    fn astring(&mut self) -> Result<Vec<u8>, String> {
        self.next()?.bytes().ok_or_else(|| "Expected string".to_string())
    }

    fn date(&mut self) -> Result<NaiveDate, String> {
        let s = self.next()?.string().ok_or("Expected date")?;
        parse_date(&s).ok_or_else(|| "Invalid date".to_string())
    }

    fn number(&mut self) -> Result<i64, String> {
        let s = self.next()?.as_atom().ok_or("Expected number")?.to_string();
        s.parse::<i64>().map_err(|_| "Invalid number".to_string())
    }

    pub fn parse_all(&mut self) -> Result<Key, String> {
        let mut keys = vec![];
        while self.i < self.args.len() {
            keys.push(self.key()?);
        }
        if keys.is_empty() {
            return Err("Missing search criteria".into());
        }
        Ok(if keys.len() == 1 { keys.pop().unwrap() } else { Key::And(keys) })
    }

    pub fn key(&mut self) -> Result<Key, String> {
        let a = self.next()?;
        let atom = match a {
            Arg::List(items) => {
                let mut sub = KeyParser::new(items);
                return sub.parse_all();
            }
            Arg::Atom(s) => s.to_ascii_uppercase(),
            Arg::Str(_) | Arg::Lit(_) | Arg::Lit8(_) => return Err("Unexpected string in search".into()),
        };
        Ok(match atom.as_str() {
            "ALL" => Key::All,
            "ANSWERED" => Key::Flag("\\Answered", true),
            "UNANSWERED" => Key::Flag("\\Answered", false),
            "DELETED" => Key::Flag("\\Deleted", true),
            "UNDELETED" => Key::Flag("\\Deleted", false),
            "DRAFT" => Key::Flag("\\Draft", true),
            "UNDRAFT" => Key::Flag("\\Draft", false),
            "FLAGGED" => Key::Flag("\\Flagged", true),
            "UNFLAGGED" => Key::Flag("\\Flagged", false),
            "SEEN" => Key::Flag("\\Seen", true),
            "UNSEEN" => Key::Flag("\\Seen", false),
            "NEW" => Key::New,
            "OLD" => Key::Old,
            "RECENT" => Key::Recent(true),
            "KEYWORD" => Key::Keyword(self.next()?.string().ok_or("Expected keyword")?, true),
            "UNKEYWORD" => Key::Keyword(self.next()?.string().ok_or("Expected keyword")?, false),
            "BCC" | "CC" | "FROM" | "SUBJECT" | "TO" => Key::Header(atom.to_ascii_lowercase(), self.astring()?),
            "HEADER" => {
                let name = String::from_utf8_lossy(&self.astring()?).to_ascii_lowercase();
                Key::Header(name, self.astring()?)
            }
            "BODY" => Key::Body(self.astring()?),
            "TEXT" => Key::Text(self.astring()?),
            "BEFORE" => Key::Before(self.date()?),
            "ON" => Key::On(self.date()?),
            "SINCE" => Key::Since(self.date()?),
            "SENTBEFORE" => Key::SentBefore(self.date()?),
            "SENTON" => Key::SentOn(self.date()?),
            "SENTSINCE" => Key::SentSince(self.date()?),
            "LARGER" => Key::Larger(self.number()?),
            "SMALLER" => Key::Smaller(self.number()?),
            "UID" => match self.next()?.as_atom().ok_or("Expected UID set")? {
                "$" => Key::Saved,
                set => Key::Uid(SeqSet::parse(set).ok_or("Invalid UID set")?),
            },
            "$" => Key::Saved,
            "EMAILID" | "THREADID" => {
                let v = self.next()?.string().ok_or("Expected an object id")?;
                let prefix = if atom == "EMAILID" { 'e' } else { 't' };
                // Unknown ids match nothing.
                let n = v.strip_prefix(prefix).and_then(|n| n.parse::<i64>().ok()).unwrap_or(-1);
                if atom == "EMAILID" { Key::EmailId(n) } else { Key::ThreadId(n) }
            }
            "SAVEDBEFORE" => Key::SavedBefore(self.date()?),
            "SAVEDON" => Key::SavedOn(self.date()?),
            "SAVEDSINCE" => Key::SavedSince(self.date()?),
            "SAVEDATESUPPORTED" => Key::All,
            "FUZZY" => Key::Fuzzy(Box::new(self.key()?)),
            "NOT" => Key::Not(Box::new(self.key()?)),
            "MODSEQ" => {
                // Optional entry name and type (e.g. "/flags/\\seen" all) are accepted and ignored.
                if matches!(self.args.get(self.i), Some(Arg::Str(_)) | Some(Arg::Lit(_)) | Some(Arg::Lit8(_))) {
                    self.i += 1;
                    let t = self.next()?.as_atom().unwrap_or("").to_ascii_lowercase();
                    if !matches!(t.as_str(), "priv" | "shared" | "all") {
                        return Err("Invalid MODSEQ entry type".into());
                    }
                }
                Key::ModSeq(self.number()?)
            }
            "OLDER" => Key::Older(self.number()?),
            "YOUNGER" => Key::Younger(self.number()?),
            "OR" => {
                let a = self.key()?;
                let b = self.key()?;
                Key::Or(Box::new(a), Box::new(b))
            }
            _ => match SeqSet::parse(&atom) {
                Some(s) => Key::Seq(s),
                None => return Err(format!("Unknown search key {atom}")),
            },
        })
    }
}

/// Message facts available without loading content.
pub struct Ctx<'a> {
    pub msn: i64,
    pub max_msn: i64,
    pub uid: i64,
    pub max_uid: i64,
    pub flags: &'a str,
    pub recent: bool,
    pub size: i64,
    pub internal_date: i64,
    pub modseq: i64,
    /// In the saved search result (SEARCHRES).
    pub saved: bool,
    pub email_id: i64,
    pub thread_id: i64,
    /// When the message was put in this mailbox.
    pub saved_at: i64,
    /// Loaded lazily by the caller when `needs_content`.
    pub content: Option<&'a Content>,
}

pub struct Content {
    pub raw: std::sync::Arc<Vec<u8>>,
    /// The Date header's calendar day in its own time zone.
    pub sent: Option<NaiveDate>,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Content {
    pub fn load(raw: std::sync::Arc<Vec<u8>>) -> Content {
        let root = crate::mime::parse(&raw);
        let headers: Vec<(String, String)> = root
            .fields
            .iter()
            .filter(|f| !f.name.is_empty())
            .map(|f| {
                let v = crate::mime::unfold(&raw[f.value_start..f.end]);
                let name = f.name.to_ascii_lowercase();
                let mut text = format!("{} {}", crate::mime::decode_rfc2047(&v), String::from_utf8_lossy(&v));
                if matches!(name.as_str(), "from" | "to" | "cc" | "bcc" | "sender" | "reply-to") {
                    // Normalized addresses, so comments and spacing don't hide them.
                    for a in crate::mime::parse_addresses(&v) {
                        if let Some(n) = &a.name {
                            text.push(' ');
                            text.push_str(&crate::mime::decode_rfc2047(n));
                        }
                        if let (Some(m), Some(h)) = (&a.mailbox, &a.host) {
                            text.push_str(&format!(" {}@{}", String::from_utf8_lossy(m), String::from_utf8_lossy(h)));
                        }
                    }
                }
                (name, text)
            })
            .collect();
        let sent = root
            .header(&raw, "date")
            .and_then(|d| crate::mime::parse_rfc2822_local_date(&String::from_utf8_lossy(&d)));
        let mut body = String::new();
        if let Some(m) = mail_parser::MessageParser::default().parse(raw.as_slice()) {
            for t in m.text_bodies() {
                body.push_str(&t);
                body.push('\n');
                if body.len() > 4 << 20 {
                    break;
                }
            }
        }
        if body.len() > 4 << 20 {
            body.truncate(body.floor_char_boundary(4 << 20));
        }
        Content { raw, sent, headers, body: body.to_lowercase() }
    }
}

fn contains_ci(hay: &str, needle: &[u8]) -> bool {
    let n = String::from_utf8_lossy(needle).to_lowercase();
    n.is_empty() || hay.to_lowercase().contains(&n)
}

fn day_of(ts: i64) -> NaiveDate {
    chrono::Utc.timestamp_opt(ts, 0).single().map(|d| d.date_naive()).unwrap_or_default()
}

/// Lowercase, without accents (é -> e), words split on non-alphanumerics.
fn fold(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for ch in s.chars().flat_map(|c| c.to_lowercase()) {
        let base = match ch {
            'à'..='å' | 'ā' | 'ă' | 'ą' => 'a',
            'ç' | 'ć' | 'č' => 'c',
            'è'..='ë' | 'ē' | 'ę' | 'ě' => 'e',
            'ì'..='ï' | 'ī' => 'i',
            'ñ' | 'ń' | 'ň' => 'n',
            'ò'..='ö' | 'ø' | 'ō' | 'ő' => 'o',
            'ù'..='ü' | 'ū' | 'ů' | 'ű' => 'u',
            'ý' | 'ÿ' => 'y',
            'ß' => {
                out.push_str("ss");
                continue;
            }
            c if c.is_alphanumeric() => c,
            _ => ' ',
        };
        let _ = write!(out, "{base}");
    }
    out
}

/// Fuzzy text match: every word of the needle appears (accents and case
/// aside), each as a prefix of some word of the text.
fn fuzzy_in(hay: &str, needle: &[u8]) -> bool {
    let hay = fold(hay);
    let words: Vec<&str> = hay.split_whitespace().collect();
    let n = fold(&String::from_utf8_lossy(needle));
    n.split_whitespace().all(|w| words.iter().any(|h| h.starts_with(w)))
}

fn eval_fuzzy(k: &Key, c: &Ctx) -> bool {
    let Some(content) = c.content else { return eval(k, c) };
    match k {
        Key::Body(v) => fuzzy_in(&content.body, v),
        Key::Text(v) => fuzzy_in(&content.body, v) || content.headers.iter().any(|(_, h)| fuzzy_in(h, v)),
        Key::Header(name, v) => content.headers.iter().any(|(n, h)| n == name && fuzzy_in(h, v)),
        Key::Not(x) => !eval_fuzzy(x, c),
        Key::Or(a, b) => eval_fuzzy(a, c) || eval_fuzzy(b, c),
        Key::And(v) => v.iter().all(|x| eval_fuzzy(x, c)),
        other => eval(other, c),
    }
}

pub fn eval(k: &Key, c: &Ctx) -> bool {
    match k {
        Key::Fuzzy(inner) => eval_fuzzy(inner, c),
        Key::All => true,
        Key::Flag(f, want) => has_flag(c.flags, f) == *want,
        Key::Keyword(kw, want) => has_flag(c.flags, kw) == *want,
        Key::New => c.recent && !has_flag(c.flags, "\\Seen"),
        Key::Old => !c.recent,
        Key::Recent(want) => c.recent == *want,
        Key::Larger(n) => c.size > *n,
        Key::Smaller(n) => c.size < *n,
        Key::Before(d) => day_of(c.internal_date) < *d,
        Key::On(d) => day_of(c.internal_date) == *d,
        Key::Since(d) => day_of(c.internal_date) >= *d,
        Key::Uid(s) => s.contains(c.uid, c.max_uid),
        Key::Seq(s) => s.contains(c.msn, c.max_msn),
        Key::Not(k) => !eval(k, c),
        Key::ModSeq(n) => c.modseq >= *n,
        Key::Older(n) => crate::util::now() - c.internal_date > *n,
        Key::Younger(n) => crate::util::now() - c.internal_date <= *n,
        Key::Saved => c.saved,
        Key::EmailId(n) => c.email_id == *n,
        Key::ThreadId(n) => c.thread_id == *n,
        Key::SavedBefore(d) => day_of(c.saved_at) < *d,
        Key::SavedOn(d) => day_of(c.saved_at) == *d,
        Key::SavedSince(d) => day_of(c.saved_at) >= *d,
        Key::Or(a, b) => eval(a, c) || eval(b, c),
        Key::And(v) => v.iter().all(|k| eval(k, c)),
        Key::SentBefore(d) | Key::SentOn(d) | Key::SentSince(d) => {
            let Some(content) = c.content else { return false };
            let sent = content.sent.unwrap_or_else(|| day_of(c.internal_date));
            match k {
                Key::SentBefore(_) => sent < *d,
                Key::SentOn(_) => sent == *d,
                _ => sent >= *d,
            }
        }
        Key::Header(name, value) => {
            let Some(content) = c.content else { return false };
            content.headers.iter().any(|(n, v)| n == name && contains_ci(v, value))
        }
        Key::Body(v) => {
            let Some(content) = c.content else { return false };
            contains_ci(&content.body, v)
        }
        Key::Text(v) => {
            let Some(content) = c.content else { return false };
            contains_ci(&content.body, v)
                || content.headers.iter().any(|(_, h)| contains_ci(h, v))
                || contains_ci(&String::from_utf8_lossy(&content.raw), v)
        }
    }
}
