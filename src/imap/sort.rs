//! SORT (RFC 5256, RFC 5957 DISPLAY) and THREAD (ORDEREDSUBJECT, REFERENCES).
use crate::mime::{EmailAddr, Meta};
use std::cmp::Ordering;
use std::collections::HashMap;

pub struct Item {
    pub msn: i64,
    pub uid: i64,
    pub size: i64,
    pub internal: i64,
    pub meta: Meta,
}

impl Item {
    /// Sent date, falling back to the internal date.
    fn date(&self) -> i64 {
        self.meta.sent.unwrap_or(self.internal)
    }
    pub fn id(&self, uid: bool) -> i64 {
        if uid {
            self.uid
        } else {
            self.msn
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Crit {
    Arrival,
    Cc,
    Date,
    From,
    Size,
    Subject,
    To,
    DisplayFrom,
    DisplayTo,
}

pub fn parse_criteria(atoms: &[String]) -> Result<Vec<(Crit, bool)>, String> {
    let mut out = vec![];
    let mut reverse = false;
    for a in atoms {
        let c = match a.to_ascii_uppercase().as_str() {
            "REVERSE" => {
                if reverse {
                    return Err("REVERSE REVERSE".into());
                }
                reverse = true;
                continue;
            }
            "ARRIVAL" => Crit::Arrival,
            "CC" => Crit::Cc,
            "DATE" => Crit::Date,
            "FROM" => Crit::From,
            "SIZE" => Crit::Size,
            "SUBJECT" => Crit::Subject,
            "TO" => Crit::To,
            "DISPLAYFROM" => Crit::DisplayFrom,
            "DISPLAYTO" => Crit::DisplayTo,
            other => return Err(format!("Unknown sort criterion {other}")),
        };
        out.push((c, reverse));
        reverse = false;
    }
    if reverse || out.is_empty() {
        return Err("Invalid sort criteria".into());
    }
    Ok(out)
}

fn mailbox_part(key: &str, a: &[EmailAddr]) -> String {
    if !key.is_empty() {
        return key.to_ascii_uppercase();
    }
    a.first().map(|x| x.email.rsplit_once('@').map(|(l, _)| l).unwrap_or(&x.email).to_ascii_uppercase()).unwrap_or_default()
}

fn display(key: &str, a: &[EmailAddr]) -> String {
    if !key.is_empty() {
        return key.to_lowercase();
    }
    a.first()
        .map(|x| x.name.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| x.email.clone()))
        .unwrap_or_default()
        .to_lowercase()
}

fn key_cmp(a: &Item, b: &Item, c: Crit) -> Ordering {
    match c {
        Crit::Arrival => a.internal.cmp(&b.internal),
        Crit::Date => a.date().cmp(&b.date()),
        Crit::Size => a.size.cmp(&b.size),
        Crit::Subject => a.meta.base_subject.to_ascii_uppercase().cmp(&b.meta.base_subject.to_ascii_uppercase()),
        Crit::From => mailbox_part(&a.meta.sort_from, &a.meta.from).cmp(&mailbox_part(&b.meta.sort_from, &b.meta.from)),
        Crit::To => mailbox_part(&a.meta.sort_to, &a.meta.to).cmp(&mailbox_part(&b.meta.sort_to, &b.meta.to)),
        Crit::Cc => mailbox_part(&a.meta.sort_cc, &a.meta.cc).cmp(&mailbox_part(&b.meta.sort_cc, &b.meta.cc)),
        Crit::DisplayFrom => display(&a.meta.display_from, &a.meta.from).cmp(&display(&b.meta.display_from, &b.meta.from)),
        Crit::DisplayTo => display(&a.meta.display_to, &a.meta.to).cmp(&display(&b.meta.display_to, &b.meta.to)),
    }
}

pub fn sort(items: &mut [Item], crits: &[(Crit, bool)]) {
    items.sort_by(|a, b| {
        for &(c, rev) in crits {
            let o = key_cmp(a, b, c);
            let o = if rev { o.reverse() } else { o };
            if o != Ordering::Equal {
                return o;
            }
        }
        a.msn.cmp(&b.msn)
    });
}

// ------------------------------------------------------------------ THREAD

#[derive(Default)]
struct Node {
    msg: Option<usize>,
    parent: Option<usize>,
    children: Vec<usize>,
}

struct Tree {
    nodes: Vec<Node>,
}

impl Tree {
    fn is_ancestor(&self, anc: usize, mut n: usize) -> bool {
        let mut guard = 0;
        loop {
            if n == anc {
                return true;
            }
            match self.nodes[n].parent {
                Some(p) => n = p,
                None => return false,
            }
            guard += 1;
            if guard > 100_000 {
                return true;
            }
        }
    }
    fn unlink(&mut self, n: usize) {
        if let Some(p) = self.nodes[n].parent.take() {
            self.nodes[p].children.retain(|c| *c != n);
        }
    }
    fn link(&mut self, parent: usize, child: usize) {
        self.unlink(child);
        self.nodes[child].parent = Some(parent);
        self.nodes[parent].children.push(child);
    }
}

fn render(tree: &Tree, n: usize, items: &[Item], uid: bool, out: &mut String) {
    let node = &tree.nodes[n];
    match node.msg {
        Some(m) => {
            out.push_str(&items[m].id(uid).to_string());
            match node.children.len() {
                0 => {}
                1 => {
                    out.push(' ');
                    render(tree, node.children[0], items, uid, out);
                }
                _ => {
                    out.push(' ');
                    for &c in &node.children {
                        out.push('(');
                        render(tree, c, items, uid, out);
                        out.push(')');
                    }
                }
            }
        }
        None => {
            for &c in &node.children {
                out.push('(');
                render(tree, c, items, uid, out);
                out.push(')');
            }
        }
    }
}

fn subject_modified(m: &Meta) -> bool {
    let norm: String = m.subject.split_whitespace().collect::<Vec<_>>().join(" ");
    !norm.eq_ignore_ascii_case(&m.base_subject)
}

pub fn thread_orderedsubject(items: &[Item], uid: bool) -> String {
    let mut idx: Vec<usize> = (0..items.len()).collect();
    idx.sort_by(|&a, &b| {
        items[a]
            .meta
            .base_subject
            .to_ascii_uppercase()
            .cmp(&items[b].meta.base_subject.to_ascii_uppercase())
            .then(items[a].date().cmp(&items[b].date()))
            .then(items[a].msn.cmp(&items[b].msn))
    });
    let mut groups: Vec<Vec<usize>> = vec![];
    for i in idx {
        match groups.last_mut() {
            Some(g) if items[g[0]].meta.base_subject.eq_ignore_ascii_case(&items[i].meta.base_subject) => g.push(i),
            _ => groups.push(vec![i]),
        }
    }
    groups.sort_by(|a, b| items[a[0]].date().cmp(&items[b[0]].date()).then(items[a[0]].msn.cmp(&items[b[0]].msn)));
    let mut out = String::new();
    for g in groups {
        out.push('(');
        out.push_str(&items[g[0]].id(uid).to_string());
        match g.len() {
            1 => {}
            2 => out.push_str(&format!(" {}", items[g[1]].id(uid))),
            _ => {
                out.push(' ');
                for &c in &g[1..] {
                    out.push_str(&format!("({})", items[c].id(uid)));
                }
            }
        }
        out.push(')');
    }
    out
}

pub fn thread_references(items: &[Item], uid: bool) -> String {
    let mut tree = Tree { nodes: vec![] };
    let mut by_id: HashMap<String, usize> = HashMap::new();
    let mut order: Vec<usize> = (0..items.len()).collect();
    order.sort_by_key(|&i| items[i].msn);

    let mut container = |tree: &mut Tree, id: &str| -> usize {
        *by_id.entry(id.to_string()).or_insert_with(|| {
            tree.nodes.push(Node::default());
            tree.nodes.len() - 1
        })
    };

    // (1) Link messages and their references.
    for &i in &order {
        let m = &items[i].meta;
        let own = match &m.msgid {
            Some(id) => {
                let c = container(&mut tree, id);
                if tree.nodes[c].msg.is_some() {
                    // Duplicate Message-ID: treat as unique.
                    tree.nodes.push(Node::default());
                    tree.nodes.len() - 1
                } else {
                    c
                }
            }
            None => {
                tree.nodes.push(Node::default());
                tree.nodes.len() - 1
            }
        };
        tree.nodes[own].msg = Some(i);
        let refs: Vec<String> = if !m.references.is_empty() {
            m.references.clone()
        } else {
            m.in_reply_to.iter().take(1).cloned().collect()
        };
        let mut prev: Option<usize> = None;
        for r in &refs {
            let c = container(&mut tree, r);
            if let Some(p) = prev {
                if p != c && tree.nodes[c].parent.is_none() && !tree.is_ancestor(c, p) {
                    tree.link(p, c);
                }
            }
            prev = Some(c);
        }
        // The message's own References win over any parent presumed from
        // other messages: drop that first, then link unless it loops.
        tree.unlink(own);
        if let Some(p) = prev {
            if p != own && !tree.is_ancestor(own, p) {
                tree.link(p, own);
            }
        }
    }

    // (2) Root set.
    let mut roots: Vec<usize> = (0..tree.nodes.len()).filter(|&n| tree.nodes[n].parent.is_none()).collect();

    // (3) Prune dummies.
    fn prune(tree: &mut Tree, n: usize, is_root: bool) -> Vec<usize> {
        let kids = std::mem::take(&mut tree.nodes[n].children);
        let mut new_kids = vec![];
        for k in kids {
            tree.nodes[k].parent = None;
            for r in prune(tree, k, false) {
                tree.nodes[r].parent = Some(n);
                new_kids.push(r);
            }
        }
        tree.nodes[n].children = new_kids;
        if tree.nodes[n].msg.is_some() {
            return vec![n];
        }
        let kids = tree.nodes[n].children.clone();
        if kids.is_empty() {
            return vec![];
        }
        if is_root && kids.len() > 1 {
            return vec![n];
        }
        // Promote children.
        tree.nodes[n].children.clear();
        for &k in &kids {
            tree.nodes[k].parent = None;
        }
        kids
    }
    let mut pruned = vec![];
    for r in roots.drain(..) {
        for x in prune(&mut tree, r, true) {
            tree.nodes[x].parent = None;
            pruned.push(x);
        }
    }
    let mut roots = pruned;

    let date_of = |tree: &Tree, n: usize| -> (i64, i64) {
        let m = tree.nodes[n].msg.or_else(|| tree.nodes[n].children.first().and_then(|c| tree.nodes[*c].msg));
        m.map(|m| (items[m].date(), items[m].msn)).unwrap_or((0, 0))
    };
    fn sort_children(tree: &mut Tree, n: usize, key: &dyn Fn(&Tree, usize) -> (i64, i64)) {
        let mut kids = std::mem::take(&mut tree.nodes[n].children);
        for &k in &kids {
            sort_children(tree, k, key);
        }
        kids.sort_by_key(|&k| key(tree, k));
        tree.nodes[n].children = kids;
    }

    // (4) Sort the root set (dummies by their first child after sorting).
    for &r in &roots {
        sort_children(&mut tree, r, &date_of);
    }
    roots.sort_by_key(|&r| date_of(&tree, r));

    // (5) Merge roots with the same base subject.
    let subj_of = |tree: &Tree, n: usize| -> Option<(String, bool)> {
        let m = tree.nodes[n].msg.or_else(|| tree.nodes[n].children.first().and_then(|c| tree.nodes[*c].msg))?;
        let s = items[m].meta.base_subject.to_ascii_uppercase();
        if s.is_empty() {
            return None;
        }
        Some((s, subject_modified(&items[m].meta)))
    };
    let mut table: HashMap<String, usize> = HashMap::new();
    for &r in &roots {
        let Some((s, modified)) = subj_of(&tree, r) else { continue };
        match table.get(&s) {
            None => {
                table.insert(s, r);
            }
            Some(&t) => {
                let t_dummy = tree.nodes[t].msg.is_none();
                let r_dummy = tree.nodes[r].msg.is_none();
                let t_modified = tree.nodes[t].msg.map(|m| subject_modified(&items[m].meta)).unwrap_or(false);
                if (r_dummy && !t_dummy) || (!r_dummy && !t_dummy && t_modified && !modified) {
                    table.insert(s, r);
                }
            }
        }
    }
    let mut slots: Vec<Option<usize>> = roots.iter().map(|&r| Some(r)).collect();
    let position: HashMap<usize, usize> = roots.iter().enumerate().map(|(i, &r)| (r, i)).collect();
    for &r in &roots {
        let Some(t) = subj_of(&tree, r).and_then(|(s, _)| table.get(&s).copied()).filter(|&t| t != r) else { continue };
        let tpos = position[&t];
        let Some(tcur) = slots[tpos] else { continue };
        if tcur == r {
            continue;
        }
        let t_dummy = tree.nodes[tcur].msg.is_none();
        let r_dummy = tree.nodes[r].msg.is_none();
        let r_modified = tree.nodes[r].msg.map(|m| subject_modified(&items[m].meta)).unwrap_or(false);
        let t_modified = tree.nodes[tcur].msg.map(|m| subject_modified(&items[m].meta)).unwrap_or(false);
        if t_dummy && r_dummy {
            let kids = std::mem::take(&mut tree.nodes[r].children);
            for k in kids {
                tree.nodes[k].parent = None;
                tree.link(tcur, k);
            }
        } else if t_dummy {
            tree.link(tcur, r);
        } else if r_dummy {
            tree.link(r, tcur);
            slots[tpos] = Some(r);
        } else if !t_modified && r_modified {
            tree.link(tcur, r);
        } else {
            tree.nodes.push(Node::default());
            let d = tree.nodes.len() - 1;
            tree.link(d, tcur);
            tree.link(d, r);
            slots[tpos] = Some(d);
        }
        slots[position[&r]] = None;
    }
    let result: Vec<usize> = slots.into_iter().flatten().collect();

    // (6) Sort siblings everywhere.
    for &r in &result {
        sort_children(&mut tree, r, &date_of);
    }
    let mut out = String::new();
    for r in result {
        out.push('(');
        render(&tree, r, items, uid, &mut out);
        out.push(')');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item(msn: i64, id: &str, refs: &[&str], subject: &str, date: i64) -> Item {
        let meta = Meta {
            msgid: Some(id.into()),
            references: refs.iter().map(|s| s.to_string()).collect(),
            subject: subject.into(),
            base_subject: crate::mime::base_subject(subject),
            sent: Some(date),
            ..Default::default()
        };
        Item { msn, uid: msn, size: 0, internal: date, meta }
    }
    #[test]
    fn references_chain() {
        let items = vec![item(1, "a", &[], "x", 1), item(2, "b", &["a"], "Re: x", 2), item(3, "c", &[], "y", 3)];
        assert_eq!(thread_references(&items, false), "(1 2)(3)");
    }
    #[test]
    fn subject_merge() {
        let items = vec![item(1, "a", &[], "hello", 1), item(2, "b", &[], "Re: hello", 2)];
        assert_eq!(thread_references(&items, false), "(1 2)");
        assert_eq!(thread_orderedsubject(&items, false), "(1 2)");
    }
}
