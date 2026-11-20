//! Sieve (RFC 5228) lexer and parser.
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    Tag(String),
    Num(u64),
    Str(String),
    List(Vec<String>),
}

impl Arg {
    pub fn strings(&self) -> Option<Vec<String>> {
        match self {
            Arg::Str(s) => Some(vec![s.clone()]),
            Arg::List(l) => Some(l.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Test {
    pub name: String,
    pub args: Vec<Arg>,
    pub tests: Vec<Test>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Command {
    pub name: String,
    pub args: Vec<Arg>,
    pub tests: Vec<Test>,
    pub block: Option<Vec<Command>>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Script {
    pub requires: Vec<String>,
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Tag(String),
    Num(u64),
    Str(String),
    LBracket,
    RBracket,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    Semi,
}

fn lex(src: &str) -> Result<Vec<(Tok, usize)>, Error> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut line = 1;
    let mut out = vec![];
    let err = |line: usize, msg: &str| Error { line, msg: msg.into() };
    while i < b.len() {
        let c = b[i];
        match c {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => i += 1,
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                loop {
                    if i + 1 >= b.len() {
                        return Err(err(line, "unterminated comment"));
                    }
                    if b[i] == b'\n' {
                        line += 1;
                    }
                    if b[i] == b'*' && b[i + 1] == b'/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            b'[' => {
                out.push((Tok::LBracket, line));
                i += 1;
            }
            b']' => {
                out.push((Tok::RBracket, line));
                i += 1;
            }
            b'(' => {
                out.push((Tok::LParen, line));
                i += 1;
            }
            b')' => {
                out.push((Tok::RParen, line));
                i += 1;
            }
            b'{' => {
                out.push((Tok::LBrace, line));
                i += 1;
            }
            b'}' => {
                out.push((Tok::RBrace, line));
                i += 1;
            }
            b',' => {
                out.push((Tok::Comma, line));
                i += 1;
            }
            b';' => {
                out.push((Tok::Semi, line));
                i += 1;
            }
            b'"' => {
                let start_line = line;
                i += 1;
                let mut s = Vec::new();
                loop {
                    if i >= b.len() {
                        return Err(err(start_line, "unterminated string"));
                    }
                    match b[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' if i + 1 < b.len() => {
                            s.push(b[i + 1]);
                            i += 2;
                        }
                        b'\n' => {
                            line += 1;
                            s.push(b'\n');
                            i += 1;
                        }
                        x => {
                            s.push(x);
                            i += 1;
                        }
                    }
                }
                let s = String::from_utf8(s).map_err(|_| err(start_line, "string is not UTF-8"))?;
                out.push((Tok::Str(s.replace("\r\n", "\n").replace('\n', "\r\n")), start_line));
            }
            b':' => {
                let start = i + 1;
                i += 1;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                if i == start {
                    return Err(err(line, "empty tag"));
                }
                out.push((Tok::Tag(src[start..i].to_ascii_lowercase()), line));
            }
            b'0'..=b'9' => {
                let start = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let mut n: u64 = src[start..i].parse().map_err(|_| err(line, "number too large"))?;
                if let Some(q) = b.get(i) {
                    let mul = match q.to_ascii_uppercase() {
                        b'K' => Some(1u64 << 10),
                        b'M' => Some(1 << 20),
                        b'G' => Some(1 << 30),
                        _ => None,
                    };
                    if let Some(m) = mul {
                        n = n.saturating_mul(m);
                        i += 1;
                    }
                }
                out.push((Tok::Num(n), line));
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let word = src[start..i].to_ascii_lowercase();
                if word == "text" && b.get(i) == Some(&b':') {
                    // Multi-line string: rest of line, then lines until "." alone.
                    i += 1;
                    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
                        i += 1;
                    }
                    if b.get(i) == Some(&b'#') {
                        while i < b.len() && b[i] != b'\n' {
                            i += 1;
                        }
                    }
                    if b.get(i) == Some(&b'\r') {
                        i += 1;
                    }
                    if b.get(i) != Some(&b'\n') {
                        return Err(err(line, "text: must be followed by a line break"));
                    }
                    i += 1;
                    line += 1;
                    let start_line = line;
                    let mut text = String::new();
                    loop {
                        if i >= b.len() {
                            return Err(err(start_line, "unterminated text: block"));
                        }
                        let end = src[i..].find('\n').map(|p| i + p).unwrap_or(b.len());
                        let l = src[i..end].trim_end_matches('\r');
                        i = (end + 1).min(b.len());
                        line += 1;
                        if l == "." {
                            break;
                        }
                        let l = l.strip_prefix('.').filter(|_| l.starts_with("..")).unwrap_or(l);
                        text.push_str(l);
                        text.push_str("\r\n");
                    }
                    out.push((Tok::Str(text), start_line));
                } else {
                    out.push((Tok::Ident(word), line));
                }
            }
            _ => return Err(err(line, &format!("unexpected character '{}'", c as char))),
        }
    }
    Ok(out)
}

struct P {
    toks: Vec<(Tok, usize)>,
    pos: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.0)
    }
    fn line(&self) -> usize {
        self.toks.get(self.pos).or(self.toks.last()).map(|t| t.1).unwrap_or(1)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).map(|t| t.0.clone());
        self.pos += 1;
        t
    }
    fn err(&self, msg: impl Into<String>) -> Error {
        Error { line: self.line(), msg: msg.into() }
    }
    fn expect(&mut self, t: Tok, what: &str) -> Result<(), Error> {
        if self.peek() == Some(&t) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(format!("expected {what}")))
        }
    }

    fn args(&mut self) -> Result<Vec<Arg>, Error> {
        let mut out = vec![];
        loop {
            match self.peek() {
                Some(Tok::Tag(t)) => {
                    out.push(Arg::Tag(t.clone()));
                    self.pos += 1;
                }
                Some(Tok::Num(n)) => {
                    out.push(Arg::Num(*n));
                    self.pos += 1;
                }
                Some(Tok::Str(s)) => {
                    out.push(Arg::Str(s.clone()));
                    self.pos += 1;
                }
                Some(Tok::LBracket) => {
                    self.pos += 1;
                    let mut list = vec![];
                    loop {
                        match self.next() {
                            Some(Tok::Str(s)) => list.push(s),
                            _ => return Err(self.err("expected a string in the list")),
                        }
                        match self.next() {
                            Some(Tok::Comma) => continue,
                            Some(Tok::RBracket) => break,
                            _ => return Err(self.err("expected ',' or ']'")),
                        }
                    }
                    out.push(Arg::List(list));
                }
                _ => return Ok(out),
            }
        }
    }

    fn test(&mut self, depth: usize) -> Result<Test, Error> {
        if depth > 32 {
            return Err(self.err("tests nested too deeply"));
        }
        let line = self.line();
        let name = match self.next() {
            Some(Tok::Ident(n)) => n,
            _ => return Err(self.err("expected a test")),
        };
        let args = self.args()?;
        let mut tests = vec![];
        if self.peek() == Some(&Tok::LParen) {
            self.pos += 1;
            loop {
                tests.push(self.test(depth + 1)?);
                match self.next() {
                    Some(Tok::Comma) => continue,
                    Some(Tok::RParen) => break,
                    _ => return Err(self.err("expected ',' or ')'")),
                }
            }
        } else if matches!(self.peek(), Some(Tok::Ident(_))) {
            // `not <test>`
            tests.push(self.test(depth + 1)?);
        }
        Ok(Test { name, args, tests, line })
    }

    fn commands(&mut self, depth: usize) -> Result<Vec<Command>, Error> {
        if depth > 32 {
            return Err(self.err("blocks nested too deeply"));
        }
        let mut out = vec![];
        loop {
            match self.peek() {
                None | Some(Tok::RBrace) => return Ok(out),
                Some(Tok::Ident(_)) => {}
                _ => return Err(self.err("expected a command")),
            }
            let line = self.line();
            let Some(Tok::Ident(name)) = self.next() else { unreachable!() };
            let args = self.args()?;
            let mut tests = vec![];
            if matches!(name.as_str(), "if" | "elsif") {
                tests.push(self.test(0)?);
            }
            let block = if self.peek() == Some(&Tok::LBrace) {
                self.pos += 1;
                let b = self.commands(depth + 1)?;
                self.expect(Tok::RBrace, "'}'")?;
                Some(b)
            } else {
                self.expect(Tok::Semi, "';'")?;
                None
            };
            if matches!(name.as_str(), "if" | "elsif" | "else") && block.is_none() {
                return Err(Error { line, msg: format!("{name} needs a block") });
            }
            if matches!(name.as_str(), "elsif" | "else") && !matches!(out.last(), Some(Command { name: n, .. }) if n == "if" || n == "elsif") {
                return Err(Error { line, msg: format!("{name} without if") });
            }
            out.push(Command { name, args, tests, block, line });
        }
    }
}

/// Extensions this implementation understands.
pub const EXTENSIONS: &[&str] = &[
    "fileinto",
    "reject",
    "ereject",
    "envelope",
    "encoded-character",
    "comparator-i;ascii-numeric",
    "comparator-i;octet",
    "comparator-i;ascii-casemap",
    "imap4flags",
    "body",
    "variables",
    "vacation",
    "vacation-seconds",
    "relational",
    "subaddress",
    "copy",
    "regex",
    "date",
    "index",
    "mailbox",
    "spamtest",
    "virustest",
    "include",
];

pub fn parse(src: &str) -> Result<Script, Error> {
    if src.len() > 1024 * 1024 {
        return Err(Error { line: 1, msg: "script too large".into() });
    }
    let mut p = P { toks: lex(src)?, pos: 0 };
    let commands = p.commands(0)?;
    if p.pos < p.toks.len() {
        return Err(p.err("unexpected '}'"));
    }
    let mut requires = vec![];
    let mut seen_other = false;
    for c in &commands {
        if c.name == "require" {
            if seen_other {
                return Err(Error { line: c.line, msg: "require must come before other commands".into() });
            }
            let Some(list) = c.args.first().and_then(|a| a.strings()) else {
                return Err(Error { line: c.line, msg: "require needs a string list".into() });
            };
            for r in list {
                let r = r.to_ascii_lowercase();
                if !EXTENSIONS.contains(&r.as_str()) {
                    return Err(Error { line: c.line, msg: format!("unsupported extension \"{r}\"") });
                }
                requires.push(r);
            }
        } else {
            seen_other = true;
        }
    }
    let script = Script { requires, commands };
    validate(&script, &script.commands)?;
    Ok(script)
}

fn validate(s: &Script, cmds: &[Command]) -> Result<(), Error> {
    let need = |c: &Command, ext: &str| -> Result<(), Error> {
        if s.requires.iter().any(|r| r == ext) {
            Ok(())
        } else {
            Err(Error { line: c.line, msg: format!("{} requires \"{ext}\"", c.name) })
        }
    };
    for c in cmds {
        match c.name.as_str() {
            "require" | "if" | "elsif" | "else" | "keep" | "discard" | "stop" | "redirect" => {}
            "fileinto" => need(c, "fileinto")?,
            "reject" => need(c, "reject")?,
            "ereject" => need(c, "ereject")?,
            "setflag" | "addflag" | "removeflag" => need(c, "imap4flags")?,
            "set" => need(c, "variables")?,
            "vacation" => need(c, "vacation")?,
            "include" | "return" | "global" => need(c, "include")?,
            other => return Err(Error { line: c.line, msg: format!("unknown command \"{other}\"") }),
        }
        let has_tag = |t: &str| c.args.iter().any(|a| a == &Arg::Tag(t.into()));
        if has_tag("copy") {
            need(c, "copy")?;
        }
        if has_tag("flags") && c.name == "fileinto" {
            need(c, "imap4flags")?;
        }
        if has_tag("create") {
            need(c, "mailbox")?;
        }
        for t in &c.tests {
            validate_test(s, t)?;
        }
        if let Some(b) = &c.block {
            validate(s, b)?;
        }
    }
    Ok(())
}

fn validate_test(s: &Script, t: &Test) -> Result<(), Error> {
    let need = |ext: &str| -> Result<(), Error> {
        if s.requires.iter().any(|r| r == ext) {
            Ok(())
        } else {
            Err(Error { line: t.line, msg: format!("{} requires \"{ext}\"", t.name) })
        }
    };
    match t.name.as_str() {
        "address" | "header" | "exists" | "size" | "true" | "false" | "not" | "allof" | "anyof" => {}
        "envelope" => need("envelope")?,
        "body" => need("body")?,
        "string" => need("variables")?,
        "hasflag" => need("imap4flags")?,
        "date" | "currentdate" => need("date")?,
        "mailboxexists" => need("mailbox")?,
        "spamtest" => need("spamtest")?,
        "virustest" => need("virustest")?,
        other => return Err(Error { line: t.line, msg: format!("unknown test \"{other}\"") }),
    }
    for a in &t.args {
        if let Arg::Tag(tag) = a {
            match tag.as_str() {
                "regex" => need("regex")?,
                "value" | "count" => need("relational")?,
                "user" | "detail" => need("subaddress")?,
                "index" | "last" => need("index")?,
                _ => {}
            }
        }
        if let Arg::Str(c) = a {
            if c == "i;ascii-numeric" && t.args.iter().any(|x| x == &Arg::Tag("comparator".into())) {
                need("comparator-i;ascii-numeric")?;
            }
        }
    }
    for x in &t.tests {
        validate_test(s, x)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses() {
        let s = parse(
            r#"require ["fileinto", "imap4flags", "variables"];
# comment
if header :contains "subject" "[list]" {
    fileinto :flags "\\Seen" "Lists";
    stop;
} elsif address :is :domain "from" ["example.com", "example.org"] {
    set "x" "y";
    keep;
} else { discard; }
/* block
comment */
"#,
        )
        .unwrap();
        assert_eq!(s.requires.len(), 3);
        assert_eq!(s.commands.len(), 4);
        assert_eq!(s.commands[1].name, "if");
        assert!(parse("fileinto \"x\";").is_err());
        assert!(parse("require \"nonsense\";").is_err());
        assert!(parse("if true keep;").is_err());
        assert!(parse("else { keep; }").is_err());
    }
    #[test]
    fn multiline() {
        let s = parse("require \"vacation\";\nvacation text:\nI'm away.\n..dot\n.\n;").unwrap();
        assert_eq!(s.commands[1].args[0], Arg::Str("I'm away.\r\n.dot\r\n".into()));
        let s = parse("redirect \"a@b.c\"; if size :over 1M { discard; }").unwrap();
        assert_eq!(s.commands[1].tests[0].args[1], Arg::Num(1 << 20));
    }
}
