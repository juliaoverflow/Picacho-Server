//! A small namespace-aware XML DOM (on quick-xml) for WebDAV requests,
//! DMARC reports and Autodiscover, plus a writer that escapes correctly.
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Element {
    /// Namespace URI ("" when none).
    pub ns: String,
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Element(Element),
    Text(String),
}

impl Element {
    pub fn is(&self, ns: &str, name: &str) -> bool {
        self.ns == ns && self.name == name
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|c| match c {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    pub fn child(&self, ns: &str, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.is(ns, name))
    }

    pub fn children_named<'a>(&'a self, ns: &'a str, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.elements().filter(move |e| e.is(ns, name))
    }

    /// Concatenated text content of this element and its descendants.
    pub fn text(&self) -> String {
        let mut out = String::new();
        fn walk(e: &Element, out: &mut String) {
            for c in &e.children {
                match c {
                    Node::Text(t) => out.push_str(t),
                    Node::Element(x) => walk(x, out),
                }
            }
        }
        walk(self, &mut out);
        out
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Path lookup by local names, ignoring namespaces ("record/row/source_ip").
    pub fn find(&self, path: &str) -> Option<&Element> {
        let mut cur = self;
        for part in path.split('/') {
            cur = cur.elements().find(|e| e.name == part)?;
        }
        Some(cur)
    }

    pub fn find_text(&self, path: &str) -> String {
        self.find(path).map(|e| e.text().trim().to_string()).unwrap_or_default()
    }

    /// Serialize back to XML (used to store dead properties verbatim).
    pub fn to_xml(&self) -> String {
        let mut w = Writer::new();
        w.element(self);
        w.finish()
    }

    /// Like `to_xml` without the XML declaration.
    pub fn to_fragment(&self) -> String {
        let x = self.to_xml();
        match x.split_once("?>\n") {
            Some((_, rest)) => rest.to_string(),
            None => x,
        }
    }
}

/// Parse a document; returns the root element.
pub fn parse(input: &[u8]) -> Result<Element, String> {
    if input.len() > 16 * 1024 * 1024 {
        return Err("XML document too large".into());
    }
    let mut r = NsReader::from_reader(input);
    r.config_mut().trim_text(false);
    r.config_mut().expand_empty_elements = true;
    let mut stack: Vec<Element> = vec![];
    let mut root = None;
    let mut buf = Vec::new();
    let mut depth = 0usize;
    loop {
        match r.read_resolved_event_into(&mut buf) {
            Err(e) => return Err(format!("invalid XML: {e}")),
            Ok((ns, Event::Start(s))) => {
                depth += 1;
                if depth > 64 {
                    return Err("XML nested too deeply".into());
                }
                let ns = match ns {
                    ResolveResult::Bound(n) => String::from_utf8_lossy(n.as_ref()).to_string(),
                    _ => String::new(),
                };
                let name = String::from_utf8_lossy(s.local_name().as_ref()).to_string();
                let mut attrs = vec![];
                for a in s.attributes().flatten() {
                    let k = String::from_utf8_lossy(a.key.local_name().as_ref()).to_string();
                    if a.key.as_ref().starts_with(b"xmlns:") && a.value.is_empty() {
                        // Namespaces in XML 1.0: a prefix can't be bound to "".
                        return Err("empty namespace for a prefix".into());
                    }
                    if a.key.as_ref().starts_with(b"xmlns") {
                        continue;
                    }
                    let v = a.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                    attrs.push((k, v));
                }
                stack.push(Element { ns, name, attrs, children: vec![] });
            }
            Ok((_, Event::End(_))) => {
                depth = depth.saturating_sub(1);
                let Some(e) = stack.pop() else { return Err("unbalanced XML".into()) };
                match stack.last_mut() {
                    Some(p) => p.children.push(Node::Element(e)),
                    None => root = Some(e),
                }
            }
            Ok((_, Event::Text(t))) => {
                if let Some(p) = stack.last_mut() {
                    let s = t.unescape().map(|s| s.to_string()).unwrap_or_else(|_| String::from_utf8_lossy(&t).to_string());
                    p.children.push(Node::Text(s));
                }
            }
            Ok((_, Event::CData(t))) => {
                if let Some(p) = stack.last_mut() {
                    p.children.push(Node::Text(String::from_utf8_lossy(&t).to_string()));
                }
            }
            Ok((_, Event::Eof)) => break,
            Ok(_) => {}
        }
        buf.clear();
    }
    root.ok_or_else(|| "empty XML document".into())
}

pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\r' && c != '\t' => {}
            c => o.push(c),
        }
    }
    o
}

/// Builds XML text with namespace prefixes assigned on first use.
pub struct Writer {
    out: String,
    prefixes: Vec<(String, String)>,
    root_decls_at: Option<usize>,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Self { out: String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"), prefixes: vec![], root_decls_at: None }
    }

    /// Pre-register a prefix (e.g. "D" for DAV:).
    pub fn prefix(mut self, prefix: &str, ns: &str) -> Self {
        self.prefixes.push((ns.to_string(), prefix.to_string()));
        self
    }

    fn pfx(&mut self, ns: &str) -> String {
        if ns.is_empty() {
            return String::new();
        }
        if let Some((_, p)) = self.prefixes.iter().find(|(n, _)| n == ns) {
            return format!("{p}:");
        }
        let p = format!("x{}", self.prefixes.len());
        self.prefixes.push((ns.to_string(), p.clone()));
        format!("{p}:")
    }

    pub fn open(&mut self, ns: &str, name: &str) {
        self.open_attrs(ns, name, &[]);
    }

    pub fn open_attrs(&mut self, ns: &str, name: &str, attrs: &[(&str, &str)]) {
        let p = self.pfx(ns);
        self.out.push('<');
        self.out.push_str(&p);
        self.out.push_str(name);
        if self.root_decls_at.is_none() {
            self.root_decls_at = Some(self.out.len());
        }
        for (k, v) in attrs {
            self.out.push_str(&format!(" {k}=\"{}\"", escape(v)));
        }
        self.out.push('>');
    }

    pub fn close(&mut self, ns: &str, name: &str) {
        let p = self.pfx(ns);
        self.out.push_str(&format!("</{p}{name}>"));
    }

    pub fn empty(&mut self, ns: &str, name: &str) {
        let p = self.pfx(ns);
        if self.root_decls_at.is_none() {
            self.out.push_str(&format!("<{p}{name}"));
            self.root_decls_at = Some(self.out.len());
            self.out.push_str("/>");
        } else {
            self.out.push_str(&format!("<{p}{name}/>"));
        }
    }

    pub fn text_el(&mut self, ns: &str, name: &str, text: &str) {
        self.open(ns, name);
        self.text(text);
        self.close(ns, name);
    }

    pub fn text(&mut self, t: &str) {
        self.out.push_str(&escape(t));
    }

    /// Insert pre-serialized XML (must be well-formed and self-contained).
    pub fn raw(&mut self, xml: &str) {
        self.out.push_str(xml);
    }

    pub fn element(&mut self, e: &Element) {
        let attrs: Vec<(&str, &str)> = e.attrs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        if e.children.is_empty() {
            let p = self.pfx(&e.ns);
            if self.root_decls_at.is_none() {
                self.out.push_str(&format!("<{p}{}", e.name));
                self.root_decls_at = Some(self.out.len());
            } else {
                self.out.push_str(&format!("<{p}{}", e.name));
            }
            for (k, v) in attrs {
                self.out.push_str(&format!(" {k}=\"{}\"", escape(v)));
            }
            self.out.push_str("/>");
            return;
        }
        self.open_attrs(&e.ns, &e.name, &attrs);
        for c in &e.children {
            match c {
                Node::Text(t) => self.text(t),
                Node::Element(x) => self.element(x),
            }
        }
        self.close(&e.ns, &e.name);
    }

    /// Finish: namespace declarations go on the root element.
    pub fn finish(mut self) -> String {
        if let Some(at) = self.root_decls_at {
            let decls: String = self.prefixes.iter().map(|(ns, p)| format!(" xmlns:{p}=\"{}\"", escape(ns))).collect();
            self.out.insert_str(at, &decls);
        }
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let doc = br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:displayname/><C:calendar-data>x &amp; y</C:calendar-data></D:prop></D:propfind>"#;
        let e = parse(doc).unwrap();
        assert!(e.is("DAV:", "propfind"));
        let prop = e.child("DAV:", "prop").unwrap();
        assert!(prop.child("DAV:", "displayname").is_some());
        assert_eq!(prop.child("urn:ietf:params:xml:ns:caldav", "calendar-data").unwrap().text(), "x & y");
        let mut w = Writer::new().prefix("D", "DAV:");
        w.open("DAV:", "multistatus");
        w.text_el("DAV:", "href", "/a&b");
        w.element(prop);
        w.close("DAV:", "multistatus");
        let out = w.finish();
        let back = parse(out.as_bytes()).unwrap();
        assert_eq!(back.child("DAV:", "href").unwrap().text(), "/a&b");
        assert!(back.child("DAV:", "prop").unwrap().child("urn:ietf:params:xml:ns:caldav", "calendar-data").is_some());
    }
}
