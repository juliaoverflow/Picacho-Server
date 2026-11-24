//! NOTIFY (RFC 5465): which mailboxes a session hears about.
//!
//! `NOTIFY SET [STATUS] (<filter> (<events>)) …` and `NOTIFY NONE`. The
//! selected mailbox keeps its usual untagged EXISTS/EXPUNGE/FETCH replies
//! (event group SELECTED or SELECTED-DELAYED); other mailboxes matched by
//! PERSONAL, INBOXES, SUBSCRIBED, SUBTREE or MAILBOXES get an untagged
//! STATUS line when they change. MailboxName and SubscriptionChange
//! events are accepted, but reported as STATUS only.
use super::proto::Arg;

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Selected,
    Personal,
    Inboxes,
    Subscribed,
    /// Mailboxes (stored names) and everything below them.
    Subtree(Vec<String>),
    Mailboxes(Vec<String>),
}

#[derive(Debug, Clone, Default)]
pub struct Watch {
    /// Mailbox filters other than SELECTED whose events aren't NONE.
    pub filters: Vec<Filter>,
    /// The selected mailbox's events are wanted (default when SELECTED isn't named).
    pub selected: bool,
    /// Send STATUS for each matched mailbox right away (`NOTIFY SET STATUS`).
    pub status_now: bool,
}

const EVENTS: [&str; 8] =
    ["MESSAGENEW", "MESSAGEEXPUNGE", "FLAGCHANGE", "ANNOTATIONCHANGE", "MAILBOXNAME", "SUBSCRIPTIONCHANGE", "MAILBOXMETADATACHANGE", "SERVERMETADATACHANGE"];

/// Parse NOTIFY's arguments. `name` turns a wire mailbox name into a
/// stored one. `Ok(None)` is NOTIFY NONE.
pub fn parse(args: &[Arg], name: &dyn Fn(&str) -> String) -> Result<Option<Watch>, String> {
    let first = args.first().and_then(|a| a.as_atom()).map(|a| a.to_ascii_uppercase());
    match first.as_deref() {
        Some("NONE") if args.len() == 1 => return Ok(None),
        Some("SET") => {}
        _ => return Err("NOTIFY expects SET or NONE.".into()),
    }
    let mut w = Watch { selected: true, ..Default::default() };
    let mut i = 1;
    if args.get(i).and_then(|a| a.as_atom()).is_some_and(|a| a.eq_ignore_ascii_case("STATUS")) {
        w.status_now = true;
        i += 1;
    }
    if i >= args.len() {
        return Err("NOTIFY SET needs at least one event group.".into());
    }
    let mut saw_selected = false;
    for g in &args[i..] {
        let Arg::List(parts) = g else { return Err("Each event group is a parenthesized list.".into()) };
        let kind = parts.first().and_then(|a| a.as_atom()).map(|a| a.to_ascii_uppercase()).ok_or("Missing filter.")?;
        let (filter, rest) = match kind.as_str() {
            "SELECTED" | "SELECTED-DELAYED" => (Filter::Selected, &parts[1..]),
            "PERSONAL" => (Filter::Personal, &parts[1..]),
            "INBOXES" => (Filter::Inboxes, &parts[1..]),
            "SUBSCRIBED" => (Filter::Subscribed, &parts[1..]),
            "SUBTREE" | "MAILBOXES" => {
                let names: Vec<String> = match parts.get(1) {
                    Some(Arg::List(l)) => l.iter().filter_map(|a| a.string()).map(|n| name(&n)).collect(),
                    Some(a) => a.string().into_iter().map(|n| name(&n)).collect(),
                    None => return Err(format!("{kind} needs mailbox names.")),
                };
                if names.is_empty() {
                    return Err(format!("{kind} needs mailbox names."));
                }
                (if kind == "SUBTREE" { Filter::Subtree(names) } else { Filter::Mailboxes(names) }, &parts[2..])
            }
            other => return Err(format!("Unknown NOTIFY filter {other}.")),
        };
        let none = match rest.first() {
            Some(Arg::Atom(a)) if a.eq_ignore_ascii_case("NONE") => true,
            Some(Arg::List(evs)) => {
                for e in evs {
                    let e = e.as_atom().unwrap_or("").to_ascii_uppercase();
                    if !EVENTS.contains(&e.as_str()) {
                        // RFC 5465 3.1: [BADEVENT] lists what we support.
                        return Err(format!("[BADEVENT ({})] Unknown event {e}.", EVENTS.join(" ")));
                    }
                }
                evs.is_empty()
            }
            None => return Err("Each event group needs events (or NONE).".into()),
            _ => return Err("Invalid events.".into()),
        };
        if filter == Filter::Selected {
            saw_selected = true;
            w.selected = !none;
        } else if !none {
            w.filters.push(filter);
        }
    }
    if !saw_selected {
        // RFC 5465 3: without SELECTED the selected mailbox is reported as usual.
        w.selected = true;
    }
    Ok(Some(w))
}

impl Watch {
    /// Whether a mailbox (stored name) of the session's own account matches.
    pub fn matches(&self, name: &str, subscribed: bool) -> bool {
        self.filters.iter().any(|f| match f {
            Filter::Selected => false,
            Filter::Personal => true,
            Filter::Inboxes => name == "INBOX",
            Filter::Subscribed => subscribed,
            Filter::Mailboxes(v) => v.iter().any(|n| n == name),
            Filter::Subtree(v) => v.iter().any(|n| name == n || name.starts_with(&format!("{n}/"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap::proto::Parser;

    fn args(s: &str) -> Vec<Arg> {
        Parser::new(format!(" {s}").as_bytes()).args().unwrap()
    }

    #[test]
    fn picacho_request() {
        let w = parse(
            &args("SET STATUS (SELECTED (MessageNew MessageExpunge FlagChange)) (PERSONAL (MessageNew MessageExpunge FlagChange))"),
            &|n| n.to_string(),
        )
        .unwrap()
        .unwrap();
        assert!(w.status_now && w.selected);
        assert!(w.matches("Archive", false));
        let w = parse(&args("SET (SELECTED NONE) (SUBTREE \"Lists\" (MessageNew))"), &|n| n.to_string()).unwrap().unwrap();
        assert!(!w.selected && w.matches("Lists/rust", false) && !w.matches("Listsx", false));
        assert!(parse(&args("NONE"), &|n| n.to_string()).unwrap().is_none());
        assert!(parse(&args("SET (PERSONAL (Bogus))"), &|n| n.to_string()).unwrap_err().contains("BADEVENT"));
    }
}
