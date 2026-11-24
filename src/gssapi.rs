//! Kerberos sign-in (SASL GSSAPI, RFC 4752) for IMAP, SMTP, POP3 and
//! ManageSieve, through the system's GSS-API library (MIT or Heimdal),
//! loaded when first used: builds need no Kerberos headers, and servers
//! without Kerberos run as before (GSSAPI simply isn't offered).
//!
//! Turned on by `[kerberos]` in config.toml with a keytab holding the
//! services' keys (`imap/<host>`, `smtp/<host>`, `pop/<host>`,
//! `sieve/<host>`). A client's principal `user@REALM` is mapped to the
//! mailbox `user@<domain>` (or taken as an address when it already is one),
//! within the configured realm; the security layer is "none" (TLS protects
//! the connection), as RFC 4752 3.1 allows.
//!
//! Loading and the GSS-API bindings follow the Picacho app's
//! `sync/gss.rs` (same authors, same MIT license).
use anyhow::{bail, ensure, Context as _, Result};
use std::ffi::c_void;
use std::sync::OnceLock;

type OmUint32 = u32;

#[repr(C)]
struct Buffer {
    length: usize,
    value: *mut c_void,
}

impl Buffer {
    fn empty() -> Self {
        Self { length: 0, value: std::ptr::null_mut() }
    }
    fn of(bytes: &[u8]) -> Self {
        Self { length: bytes.len(), value: bytes.as_ptr() as *mut c_void }
    }
}

const COMPLETE: OmUint32 = 0;
const ERROR_MASK: OmUint32 = 0xffff_0000;
const GSS_CODE: i32 = 1;
const MECH_CODE: i32 = 2;

type AcceptSecContext = unsafe extern "C" fn(
    *mut OmUint32,
    *mut *mut c_void,
    *mut c_void,
    *mut Buffer,
    *mut c_void,
    *mut *mut c_void,
    *mut *mut c_void,
    *mut Buffer,
    *mut OmUint32,
    *mut OmUint32,
    *mut *mut c_void,
) -> OmUint32;
type DisplayName = unsafe extern "C" fn(*mut OmUint32, *mut c_void, *mut Buffer, *mut *mut c_void) -> OmUint32;
type ReleaseName = unsafe extern "C" fn(*mut OmUint32, *mut *mut c_void) -> OmUint32;
type ReleaseBuffer = unsafe extern "C" fn(*mut OmUint32, *mut Buffer) -> OmUint32;
type DeleteSecContext = unsafe extern "C" fn(*mut OmUint32, *mut *mut c_void, *mut Buffer) -> OmUint32;
type Wrap = unsafe extern "C" fn(*mut OmUint32, *mut c_void, i32, OmUint32, *mut Buffer, *mut i32, *mut Buffer) -> OmUint32;
type Unwrap = unsafe extern "C" fn(*mut OmUint32, *mut c_void, *mut Buffer, *mut Buffer, *mut i32, *mut OmUint32) -> OmUint32;
type DisplayStatus = unsafe extern "C" fn(*mut OmUint32, OmUint32, i32, *mut c_void, *mut OmUint32, *mut Buffer) -> OmUint32;
type RegisterKeytab = unsafe extern "C" fn(*const std::ffi::c_char) -> OmUint32;

struct Library {
    _library: libloading::Library,
    accept: AcceptSecContext,
    display_name: DisplayName,
    release_name: ReleaseName,
    release_buffer: ReleaseBuffer,
    delete_sec_context: DeleteSecContext,
    wrap: Wrap,
    unwrap: Unwrap,
    display_status: DisplayStatus,
    register_keytab: Option<RegisterKeytab>,
}
// The functions are the library's, valid while loaded (the whole process);
// GSS-API is thread-safe for distinct contexts.
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

const CANDIDATES: &[&str] = &["libgssapi_krb5.so.2", "libgssapi.so.3", "libgssapi.so.10", "libgssapi_krb5.so", "libgssapi.so"];

fn library() -> Result<&'static Library> {
    static LIBRARY: OnceLock<std::result::Result<Library, String>> = OnceLock::new();
    LIBRARY.get_or_init(|| load().map_err(|e| format!("{e:#}"))).as_ref().map_err(|e| anyhow::anyhow!("{e}"))
}

fn load() -> Result<Library> {
    let mut last = None;
    for name in CANDIDATES {
        // SAFETY: loading the system's GSS-API library runs only its own initializers.
        match unsafe { libloading::Library::new(name) } {
            Ok(library) => return bind(library),
            Err(e) => last = Some(e),
        }
    }
    bail!("No Kerberos (GSS-API) library found{}", last.map(|e| format!(" ({e})")).unwrap_or_default())
}

fn bind(library: libloading::Library) -> Result<Library> {
    // SAFETY: each symbol is looked up by its RFC 2744 name and C signature.
    unsafe {
        macro_rules! function {
            ($name:literal) => {
                *library.get($name).with_context(|| format!("The Kerberos library lacks {}", String::from_utf8_lossy(&$name[..$name.len() - 1])))?
            };
        }
        Ok(Library {
            accept: function!(b"gss_accept_sec_context\0"),
            display_name: function!(b"gss_display_name\0"),
            release_name: function!(b"gss_release_name\0"),
            release_buffer: function!(b"gss_release_buffer\0"),
            delete_sec_context: function!(b"gss_delete_sec_context\0"),
            wrap: function!(b"gss_wrap\0"),
            unwrap: function!(b"gss_unwrap\0"),
            display_status: function!(b"gss_display_status\0"),
            register_keytab: library.get::<RegisterKeytab>(b"krb5_gss_register_acceptor_identity\0").ok().map(|f| *f),
            _library: library,
        })
    }
}

impl Library {
    fn describe(&self, major: OmUint32, minor: OmUint32) -> String {
        let mut parts = Vec::new();
        for (code, kind) in [(major, GSS_CODE), (minor, MECH_CODE)] {
            if code == 0 {
                continue;
            }
            let mut context = 0;
            for _ in 0..8 {
                let mut ignored = 0;
                let mut text = Buffer::empty();
                // SAFETY: an output buffer the library fills and we release.
                let status = unsafe { (self.display_status)(&mut ignored, code, kind, std::ptr::null_mut(), &mut context, &mut text) };
                if status & ERROR_MASK != 0 {
                    break;
                }
                let message = unsafe { take(self, &mut text) };
                let message = String::from_utf8_lossy(&message).trim().to_owned();
                if !message.is_empty() && !parts.contains(&message) {
                    parts.push(message);
                }
                if context == 0 {
                    break;
                }
            }
        }
        if parts.is_empty() {
            format!("GSS-API status {major:#x}/{minor}")
        } else {
            parts.join("; ")
        }
    }
}

/// SAFETY: `buffer` must have been filled by the library.
unsafe fn take(library: &Library, buffer: &mut Buffer) -> Vec<u8> {
    let bytes = if buffer.value.is_null() || buffer.length == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(buffer.value as *const u8, buffer.length) }.to_vec()
    };
    let mut minor = 0;
    unsafe { (library.release_buffer)(&mut minor, buffer) };
    bytes
}

/// Point the library at the keytab (once, before the first context).
pub fn init(keytab: &std::path::Path) -> Result<()> {
    let lib = library()?;
    let path = std::ffi::CString::new(keytab.as_os_str().as_encoded_bytes()).context("keytab path")?;
    match lib.register_keytab {
        // SAFETY: a NUL-terminated path the library copies.
        Some(f) => ensure!(unsafe { f(path.as_ptr()) } == 0, "The Kerberos library refused the keytab {}", keytab.display()),
        // Heimdal and others read KRB5_KTNAME.
        None => unsafe { std::env::set_var("KRB5_KTNAME", format!("FILE:{}", keytab.display())) },
    }
    Ok(())
}

/// Whether GSSAPI can be offered: configured, and the library loads.
pub fn available(state: &crate::state::State) -> bool {
    state.config.kerberos.as_ref().is_some_and(|k| k.enabled) && library().is_ok()
}

/// One server-side GSSAPI exchange (RFC 4752 3.1).
pub struct Exchange {
    lib: &'static Library,
    context: *mut c_void,
    /// The client's principal, once the context is established.
    pub client: Option<String>,
    /// Sent the security-layer offer; waiting for the client's choice.
    offered: bool,
}
// The context is used from one task at a time.
unsafe impl Send for Exchange {}

/// What to do after a client message.
pub enum Step {
    /// Send this challenge and wait for the next response.
    Continue(Vec<u8>),
    /// Done: the client is this principal, acting as this authorization id ("" for itself).
    Done { principal: String, authzid: String },
}

impl Exchange {
    pub fn new() -> Result<Self> {
        Ok(Self { lib: library()?, context: std::ptr::null_mut(), client: None, offered: false })
    }

    pub fn step(&mut self, input: &[u8]) -> Result<Step> {
        if self.offered {
            // The client's security-layer choice: 4 octets (layer + max size), then authzid.
            let msg = self.unwrap(input)?;
            ensure!(msg.len() >= 4, "Invalid GSSAPI security layer reply");
            ensure!(msg[0] & 1 == 1, "Only the \"no security layer\" option is offered");
            let authzid = String::from_utf8(msg[4..].to_vec()).context("authorization id isn't UTF-8")?;
            return Ok(Step::Done { principal: self.client.clone().unwrap_or_default(), authzid });
        }
        if self.client.is_some() {
            // Context done; the client's empty response before our offer.
            return self.offer();
        }
        let mut minor = 0;
        let mut token = Buffer::of(input);
        let mut output = Buffer::empty();
        let mut name: *mut c_void = std::ptr::null_mut();
        let mut flags = 0;
        // SAFETY: RFC 2744 gss_accept_sec_context with default credentials (the keytab).
        let major = unsafe {
            (self.lib.accept)(
                &mut minor,
                &mut self.context,
                std::ptr::null_mut(),
                &mut token,
                std::ptr::null_mut(),
                &mut name,
                std::ptr::null_mut(),
                &mut output,
                &mut flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let out = unsafe { take(self.lib, &mut output) };
        ensure!(major & ERROR_MASK == 0, "Kerberos: {}", self.lib.describe(major, minor));
        if major != COMPLETE {
            return Ok(Step::Continue(out));
        }
        let mut text = Buffer::empty();
        let mut minor2 = 0;
        // SAFETY: the name the context returned, displayed then released.
        unsafe {
            (self.lib.display_name)(&mut minor2, name, &mut text, std::ptr::null_mut());
        }
        let principal = String::from_utf8_lossy(&unsafe { take(self.lib, &mut text) }).into_owned();
        unsafe { (self.lib.release_name)(&mut minor2, &mut name) };
        self.client = Some(principal);
        if out.is_empty() {
            // Nothing left of the context exchange: offer the layers now.
            return self.offer();
        }
        Ok(Step::Continue(out))
    }

    /// Our security-layer offer: "none" only, no maximum size.
    fn offer(&mut self) -> Result<Step> {
        self.offered = true;
        Ok(Step::Continue(self.wrap(&[1, 0, 0, 0])?))
    }

    fn wrap(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let (mut minor, mut conf) = (0, 0);
        let mut input = Buffer::of(message);
        let mut output = Buffer::empty();
        // SAFETY: an established context; integrity only (conf_req 0).
        let major = unsafe { (self.lib.wrap)(&mut minor, self.context, 0, 0, &mut input, &mut conf, &mut output) };
        let out = unsafe { take(self.lib, &mut output) };
        ensure!(major & ERROR_MASK == 0, "wrap: {}", self.lib.describe(major, minor));
        Ok(out)
    }

    fn unwrap(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let (mut minor, mut conf, mut qop) = (0, 0, 0);
        let mut input = Buffer::of(message);
        let mut output = Buffer::empty();
        // SAFETY: as wrap.
        let major = unsafe { (self.lib.unwrap)(&mut minor, self.context, &mut input, &mut output, &mut conf, &mut qop) };
        let out = unsafe { take(self.lib, &mut output) };
        ensure!(major & ERROR_MASK == 0, "unwrap: {}", self.lib.describe(major, minor));
        Ok(out)
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if !self.context.is_null() {
            let mut minor = 0;
            // SAFETY: our own context, deleted once.
            unsafe { (self.lib.delete_sec_context)(&mut minor, &mut self.context, std::ptr::null_mut()) };
        }
    }
}

/// The mailbox a Kerberos principal signs in to, if allowed: `user@REALM`
/// must be in the configured realm; `user` becomes `user@<domain>` (or is
/// taken as is when it's an address). A requested authzid must be the
/// same mailbox.
pub async fn account_for(state: &crate::state::State, principal: &str, authzid: &str) -> Option<crate::db::Account> {
    let k = state.config.kerberos.as_ref()?;
    let (user, realm) = principal.rsplit_once('@').unwrap_or((principal, ""));
    if !k.realm.is_empty() && !realm.eq_ignore_ascii_case(&k.realm) {
        return None;
    }
    if user.contains('/') {
        // Service or admin principals (host/x, user/admin) never sign in as mailboxes.
        return None;
    }
    let email = if user.contains('@') {
        user.to_ascii_lowercase()
    } else {
        let domain = if k.domain.is_empty() { state.settings().server.primary_domain.clone()? } else { k.domain.clone() };
        format!("{}@{}", user.to_ascii_lowercase(), domain.to_ascii_lowercase())
    };
    let a = state.db.account_by_email(&email).await.ok()??;
    if !authzid.is_empty() && !authzid.eq_ignore_ascii_case(&a.email) {
        return None;
    }
    a.active.then_some(a)
}
