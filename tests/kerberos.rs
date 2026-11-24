//! Kerberos (SASL GSSAPI) sign-in against a throwaway MIT realm. Needs
//! krb5kdc, kdb5_util, kadmin.local, kinit and libgssapi_krb5; ignored by
//! default. Run with: cargo test --test kerberos -- --ignored
use picacho_server::config::{Config, Kerberos};
use picacho_server::server::{spawn_listener, Proto};
use picacho_server::state::AppState;
use std::ffi::c_void;
use std::net::SocketAddr;
use std::process::Command;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

// ---- a minimal GSS-API initiator (the client side), for the test only

#[repr(C)]
struct Buffer {
    length: usize,
    value: *mut c_void,
}
type InitSecContext = unsafe extern "C" fn(*mut u32, *mut c_void, *mut *mut c_void, *mut c_void, *mut c_void, u32, u32, *mut c_void, *mut Buffer, *mut *mut c_void, *mut Buffer, *mut u32, *mut u32) -> u32;
type ImportName = unsafe extern "C" fn(*mut u32, *mut Buffer, *mut c_void, *mut *mut c_void) -> u32;
type Wrap = unsafe extern "C" fn(*mut u32, *mut c_void, i32, u32, *mut Buffer, *mut i32, *mut Buffer) -> u32;
type Unwrap = unsafe extern "C" fn(*mut u32, *mut c_void, *mut Buffer, *mut Buffer, *mut i32, *mut u32) -> u32;

struct Client {
    lib: libloading::Library,
    ctx: *mut c_void,
    target: *mut c_void,
}
unsafe impl Send for Client {}

impl Client {
    fn new(service: &str) -> Client {
        unsafe {
            let lib = libloading::Library::new("libgssapi_krb5.so.2").unwrap();
            let import: ImportName = *lib.get(b"gss_import_name\0").unwrap();
            let nt: *mut *mut c_void = *lib.get::<*mut *mut c_void>(b"GSS_C_NT_HOSTBASED_SERVICE\0").unwrap();
            let mut target = std::ptr::null_mut();
            let mut minor = 0;
            let mut name = Buffer { length: service.len(), value: service.as_ptr() as *mut c_void };
            assert_eq!(import(&mut minor, &mut name, *nt, &mut target), 0);
            Client { lib, ctx: std::ptr::null_mut(), target }
        }
    }
    fn step(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        unsafe {
            let init: InitSecContext = *self.lib.get(b"gss_init_sec_context\0").unwrap();
            let mut minor = 0;
            let mut inb = Buffer { length: input.len(), value: input.as_ptr() as *mut c_void };
            let mut out = Buffer { length: 0, value: std::ptr::null_mut() };
            let major = init(&mut minor, std::ptr::null_mut(), &mut self.ctx, self.target, std::ptr::null_mut(), 2 | 32, 0, std::ptr::null_mut(), &mut inb, std::ptr::null_mut(), &mut out, std::ptr::null_mut(), std::ptr::null_mut());
            assert_eq!(major & 0xffff_0000, 0, "init_sec_context failed: {major:#x}/{minor}");
            let bytes = if out.value.is_null() { vec![] } else { std::slice::from_raw_parts(out.value as *const u8, out.length).to_vec() };
            (bytes, major == 0)
        }
    }
    fn unwrap(&mut self, m: &[u8]) -> Vec<u8> {
        unsafe {
            let f: Unwrap = *self.lib.get(b"gss_unwrap\0").unwrap();
            let (mut minor, mut c, mut q) = (0, 0, 0);
            let mut inb = Buffer { length: m.len(), value: m.as_ptr() as *mut c_void };
            let mut out = Buffer { length: 0, value: std::ptr::null_mut() };
            assert_eq!(f(&mut minor, self.ctx, &mut inb, &mut out, &mut c, &mut q) & 0xffff_0000, 0);
            std::slice::from_raw_parts(out.value as *const u8, out.length).to_vec()
        }
    }
    fn wrap(&mut self, m: &[u8]) -> Vec<u8> {
        unsafe {
            let f: Wrap = *self.lib.get(b"gss_wrap\0").unwrap();
            let (mut minor, mut c) = (0, 0);
            let mut inb = Buffer { length: m.len(), value: m.as_ptr() as *mut c_void };
            let mut out = Buffer { length: 0, value: std::ptr::null_mut() };
            assert_eq!(f(&mut minor, self.ctx, 0, 0, &mut inb, &mut c, &mut out) & 0xffff_0000, 0);
            std::slice::from_raw_parts(out.value as *const u8, out.length).to_vec()
        }
    }
}

// ---- a throwaway realm

struct Realm {
    kdc: std::process::Child,
    dir: tempfile::TempDir,
}
impl Drop for Realm {
    fn drop(&mut self) {
        let _ = self.kdc.kill();
        let _ = self.kdc.wait();
    }
}

fn realm() -> Realm {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display().to_string();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::fs::write(
        dir.path().join("krb5.conf"),
        format!("[libdefaults]\n default_realm = MAIL.TEST\n dns_lookup_kdc = false\n rdns = false\n dns_canonicalize_hostname = false\n qualify_shortname = \"\"\n default_ccache_name = FILE:{d}/ccache\n[realms]\n MAIL.TEST = {{\n  kdc = 127.0.0.1:{port}\n }}\n[domain_realm]\n localhost = MAIL.TEST\n .localdomain = MAIL.TEST\n localdomain = MAIL.TEST\n"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("kdc.conf"),
        format!("[kdcdefaults]\n kdc_ports = {port}\n kdc_tcp_ports = {port}\n[realms]\n MAIL.TEST = {{\n  database_name = {d}/principal\n  key_stash_file = {d}/stash\n  acl_file = {d}/kadm5.acl\n }}\n"),
    )
    .unwrap();
    std::fs::write(dir.path().join("kadm5.acl"), "").unwrap();
    let env = |c: &mut Command| {
        c.env("KRB5_CONFIG", format!("{d}/krb5.conf")).env("KRB5_KDC_PROFILE", format!("{d}/kdc.conf")).env("KRB5CCNAME", format!("FILE:{d}/ccache"));
    };
    let run = |args: &[&str], input: Option<&str>| {
        let mut c = Command::new(args[0]);
        c.args(&args[1..]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped());
        env(&mut c);
        let mut child = c.spawn().unwrap();
        if let Some(t) = input {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(t.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    run(&["kdb5_util", "create", "-s", "-r", "MAIL.TEST", "-P", "master-key"], None);
    run(&["kadmin.local", "-q", "addprinc -pw user-pw bob"], None);
    run(&["kadmin.local", "-q", "addprinc -pw other-pw mallory"], None);
    for svc in ["imap", "smtp", "pop", "sieve"] {
        run(&["kadmin.local", "-q", &format!("addprinc -randkey {svc}/localhost")], None);
        run(&["kadmin.local", "-q", &format!("ktadd -k {d}/keytab {svc}/localhost")], None);
    }
    let mut kdc = Command::new("krb5kdc");
    kdc.args(["-n", "-r", "MAIL.TEST"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    env(&mut kdc);
    let kdc = kdc.spawn().unwrap();
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    run(&["kinit", "bob@MAIL.TEST"], Some("user-pw\n"));
    // SAFETY: before the library is loaded, in a test that runs alone.
    unsafe {
        std::env::set_var("KRB5_CONFIG", format!("{d}/krb5.conf"));
        std::env::set_var("KRB5CCNAME", format!("FILE:{d}/ccache"));
    }
    Realm { kdc, dir }
}

async fn line(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
    let mut l = String::new();
    r.read_line(&mut l).await.unwrap();
    l
}

#[tokio::test]
#[ignore = "needs MIT Kerberos (krb5kdc, kdb5_util, kadmin.local, kinit)"]
async fn kerberos_sign_in_over_imap_and_smtp() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let realm = realm();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.hostname = Some("localhost".into());
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.kerberos = Some(Kerberos { enabled: true, keytab: realm.dir.path().join("keytab"), realm: "MAIL.TEST".into(), domain: "example.test".into() });
    let state = AppState::new(cfg).await.unwrap();
    let mut s = (*state.settings()).clone();
    s.server.setup_complete = true;
    s.security.require_tls_for_auth = false;
    state.save_settings(s).await.unwrap();
    let d = state.db.create_domain("example.test", "local", "").await.unwrap();
    state.db.create_account("bob@example.test", d, "!", "Bob", "user", 0).await.unwrap();
    assert!(picacho_server::gssapi::available(&state));
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let imap = spawn_listener(state.clone(), any, Proto::Imap).await.unwrap();
    let smtp = spawn_listener(state.clone(), any, Proto::Submission).await.unwrap();

    // IMAP AUTHENTICATE GSSAPI.
    let (r, mut w) = TcpStream::connect(imap).await.unwrap().into_split();
    let mut r = BufReader::new(r);
    let greeting = line(&mut r).await;
    assert!(greeting.contains("AUTH=GSSAPI"), "{greeting}");
    let mut client = Client::new("imap@localhost");
    let (first, _) = client.step(&[]);
    w.write_all(format!("a1 AUTHENTICATE GSSAPI {}\r\n", b64.encode(&first)).as_bytes()).await.unwrap();
    let mut done = false;
    loop {
        let l = line(&mut r).await;
        if l.starts_with("a1 ") {
            assert!(l.starts_with("a1 OK"), "{l}");
            break;
        }
        let token = b64.decode(l.trim_start_matches('+').trim()).unwrap();
        let reply = if !done {
            let (out, complete) = client.step(&token);
            done = complete;
            out
        } else {
            // The server's security-layer offer: take "none", act as ourselves.
            let offer = client.unwrap(&token);
            assert_eq!(offer[0] & 1, 1);
            client.wrap(&[1, 0, 0, 0])
        };
        w.write_all(format!("{}\r\n", b64.encode(&reply)).as_bytes()).await.unwrap();
    }
    w.write_all(b"a2 SELECT INBOX\r\n").await.unwrap();
    loop {
        let l = line(&mut r).await;
        if l.starts_with("a2 ") {
            assert!(l.starts_with("a2 OK"), "signed in as bob@example.test: {l}");
            break;
        }
    }

    // SMTP AUTH GSSAPI, with an authzid for another mailbox: refused.
    let (r, mut w) = TcpStream::connect(smtp).await.unwrap().into_split();
    let mut r = BufReader::new(r);
    line(&mut r).await;
    w.write_all(b"EHLO client\r\n").await.unwrap();
    let mut ehlo = String::new();
    loop {
        let l = line(&mut r).await;
        ehlo.push_str(&l);
        if l.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }
    assert!(ehlo.contains("GSSAPI"), "{ehlo}");
    let mut client = Client::new("smtp@localhost");
    let (first, _) = client.step(&[]);
    w.write_all(format!("AUTH GSSAPI {}\r\n", b64.encode(&first)).as_bytes()).await.unwrap();
    let mut done = false;
    loop {
        let l = line(&mut r).await;
        if !l.starts_with("334") {
            assert!(l.starts_with("535"), "authzid of someone else: {l}");
            break;
        }
        let token = b64.decode(l[3..].trim()).unwrap();
        let reply = if !done {
            let (out, complete) = client.step(&token);
            done = complete;
            out
        } else {
            client.unwrap(&token);
            let mut m = vec![1u8, 0, 0, 0];
            m.extend_from_slice(b"mallory@example.test");
            client.wrap(&m)
        };
        w.write_all(format!("{}\r\n", b64.encode(&reply)).as_bytes()).await.unwrap();
    }
}
