//! The loopback half of the browser (authorization code + PKCE) sign-in: a
//! one-shot listener the browser's redirect lands on.
//!
//! [`crate::auth::TokenCache::begin_browser_code`] builds the authorize URL and
//! holds the verifier; this module owns the socket the `redirect_uri` in that
//! URL points at. They are separate on purpose — the cache is shared,
//! process-wide state, and a TCP listener is a session concern that belongs to
//! whoever is running the enrollment — but they are designed as a pair:
//! [`redirect_uri`](crate::browser::Loopback::redirect_uri) produces exactly the
//! literal-loopback shape `begin_browser_code` accepts, so the two cannot
//! drift apart.
//!
//! Adapted from the working reference client, OneDriveForLinux
//! `crates/graph-client/src/pkce.rs` (MIT OR Apache-2.0, the same terms as
//! this crate), with the conditions of OneDriveHydration's accepted
//! `docs/PKCE-ENROLLMENT-REVIEW.md` applied:
//!
//!  * **Bound once.** The socket is bound on port 0 and that same socket
//!    accepts the redirect. The pick-a-port-then-rebind pattern the review
//!    measured (§1c) left a window in which another local socket could take
//!    the port; a listener that never lets go has no window.
//!  * **`127.0.0.1` literally, never `localhost`** (§1a) — the name resolves
//!    to `::1` first on real machines, and `[::1]:P` is independently
//!    bindable while `127.0.0.1:P` is held.
//!  * **`state` is checked before the code is read** (RFC 6749 §10.12), and a
//!    redirect that fails the check ends the flow rather than being retried:
//!    a response that does not belong to this request is not this request's
//!    to keep waiting past.
//!  * **Nothing is logged.** The redirect's query string carries the
//!    authorization code; no error and no diagnostic quotes it.
//!  * **The timeout says why** (§6.2): the known way to complete a sign-in
//!    and still time out here is a sandboxed browser that cannot reach a
//!    host loopback listener, and the error names that instead of shrugging.

use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// How long each accepted connection may take to deliver its request line.
///
/// This is not the sign-in timeout — that is the caller's, passed to
/// [`Loopback::wait`] — it is a bound on one TCP peer that connected and then
/// stalled, so a stray local prober cannot wedge the accept loop.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the accept loop looks again while nothing has connected.
const ACCEPT_POLL: Duration = Duration::from_millis(200);

/// What one redirect request said, once `state` has been checked.
enum Redirect {
    /// The authorization code. The only value worth anything, and it is
    /// worth nothing without the verifier the cache holds.
    Code(String),
    /// The identity platform reported a failure (`error`, description).
    Refused(String, String),
    /// Not the redirect: no `code`, no `error`, no `state`. Browsers send
    /// these — a favicon fetch, a speculative preconnect — and one of them
    /// must not end a sign-in the user is still completing.
    Noise,
}

/// The one-shot loopback listener.
pub struct Loopback {
    listener: TcpListener,
    port: u16,
}

impl Loopback {
    /// Bind `127.0.0.1:0` — the kernel picks the port, and from this moment
    /// the socket is listening. Nothing else can take the port for as long
    /// as this value lives.
    pub fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    /// The `redirect_uri` to build the sign-in with: `http://127.0.0.1:{port}`,
    /// which is the shape [`crate::auth::TokenCache::begin_browser_code`]
    /// requires and the one Microsoft's loopback matching rules make legal
    /// against a single registered path-less `http://127.0.0.1`.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Block until the browser delivers the redirect, and return the
    /// authorization code.
    ///
    /// `expected_state` is [`crate::auth::BrowserCode::state`]; it is compared
    /// before anything else in the redirect is believed. Consumes the
    /// listener: a code has either been delivered or it never will be, and
    /// either way the port is released here.
    pub fn wait(self, expected_state: &str, timeout: Duration) -> io::Result<String> {
        self.listener.set_nonblocking(true)?;
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(REQUEST_READ_TIMEOUT))?;
                    let line = match request_line(&mut stream) {
                        Ok(line) => line,
                        // A peer that connected and said nothing readable is
                        // noise, not the browser; keep waiting.
                        Err(_) => continue,
                    };
                    let outcome = parse_redirect(&line, expected_state);
                    let (heading, detail) = match &outcome {
                        Ok(Redirect::Code(_)) => (
                            "Innlogging mottatt",
                            "Du kan lukke denne fanen og g\u{e5} tilbake.",
                        ),
                        Ok(Redirect::Refused(..)) | Err(_) => (
                            "Innlogging mislyktes",
                            "G\u{e5} tilbake til terminalen for detaljer.",
                        ),
                        Ok(Redirect::Noise) => continue,
                    };
                    // Best-effort: the browser tab deserves an answer, but a
                    // peer that hung up before reading it has not changed
                    // what happened.
                    let body = format!(
                        "<html><body style='font-family:sans-serif'>\
                         <h2>{heading}</h2><p>{detail}</p></body></html>"
                    );
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );
                    let _ = stream.flush();
                    return match outcome? {
                        Redirect::Code(code) => Ok(code),
                        Redirect::Refused(code, description) => Err(io::Error::other(format!(
                            "the sign-in was refused ({code}): {description}"
                        ))),
                        Redirect::Noise => unreachable!("noise continues the loop above"),
                    };
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "no redirect arrived within {}s. If the sign-in was \
                                 completed in the browser, the likely cause is a \
                                 sandboxed browser (Flatpak, Snap) that is not allowed \
                                 to reach http://127.0.0.1:{} on the host loopback; \
                                 retry with an unsandboxed browser, or complete the \
                                 printed URL in one that can reach the host",
                                timeout.as_secs(),
                                self.port
                            ),
                        ));
                    }
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// The first line of one HTTP request, bounded.
///
/// Read byte-wise up to `\n` rather than through a buffered reader, so
/// nothing beyond the request line is consumed or held; bounded, so a peer
/// feeding an endless first line is an error rather than an allocation.
fn request_line(stream: &mut impl Read) -> io::Result<String> {
    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while line.len() < 8192 {
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            let text = String::from_utf8_lossy(&line);
            return Ok(text.trim_end_matches('\r').to_string());
        }
        line.push(byte[0]);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "the request line did not end",
    ))
}

/// Read `GET /?code=…&state=… HTTP/1.1`, checking `state` before anything
/// else is believed.
///
/// The error never quotes the line: on the success path the line *is* the
/// authorization code.
fn parse_redirect(request_line: &str, expected_state: &str) -> io::Result<Redirect> {
    let Some(path) = request_line.split_whitespace().nth(1) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the redirect request line was malformed",
        ));
    };
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut description = None;
    for pair in query.split('&') {
        let Some((key, raw)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "code" => code = Some(percent_decode(raw)),
            "state" => state = Some(percent_decode(raw)),
            "error" => error = Some(percent_decode(raw)),
            "error_description" => description = Some(percent_decode(raw)),
            _ => {}
        }
    }
    if code.is_none() && error.is_none() && state.is_none() {
        return Ok(Redirect::Noise);
    }
    // Before the code, before even the error: a response whose `state` is not
    // this request's is not this request's response, and nothing in it — not
    // its code, not its claimed failure — is to be acted on.
    if state.as_deref() != Some(expected_state) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the redirect's state did not match this sign-in (RFC 6749 \u{a7}10.12); \
             the response belongs to some other request and its code was not used",
        ));
    }
    if let Some(error) = error {
        return Ok(Redirect::Refused(
            printable_filter(&error, 40),
            description
                .map(|d| printable_filter(&d, 200))
                .unwrap_or_else(|| "no description".into()),
        ));
    }
    match code {
        Some(code) => Ok(Redirect::Code(code)),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the redirect carried neither a code nor an error",
        )),
    }
}

/// `%XX` and `+` decoding for one query value.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A server-supplied string, reduced to something safe to print: control
/// characters dropped, length capped. The identity platform's error strings
/// are meant for a terminal, which makes them a place to put escape
/// sequences — the same reasoning as `auth`'s refusal to carry the device
/// code flow's `message` field.
fn printable_filter(raw: &str, max: usize) -> String {
    raw.chars().filter(|c| !c.is_control()).take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::thread;

    fn get(uri: &str, path: &str) -> String {
        let address = uri.strip_prefix("http://").unwrap();
        let mut stream = TcpStream::connect(address).unwrap();
        write!(stream, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut reply = String::new();
        let _ = stream.read_to_string(&mut reply);
        reply
    }

    #[test]
    fn the_redirect_uri_is_literal_loopback_with_the_bound_port() {
        let loopback = Loopback::bind().unwrap();
        let uri = loopback.redirect_uri();
        let port: u16 = uri
            .strip_prefix("http://127.0.0.1:")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(port, loopback.port);
        assert_ne!(port, 0, "the kernel assigned a real port at bind");
    }

    #[test]
    fn the_listener_is_up_before_wait_is_called() {
        // The whole point of binding once: between `bind` and `wait` — where
        // the browser is launched — the port is already owned, so a redirect
        // (or a squatter) arriving early meets our socket, not a free port.
        let loopback = Loopback::bind().unwrap();
        let uri = loopback.redirect_uri();
        let early = thread::spawn(move || get(&uri, "/?code=early-code&state=s"));
        let code = loopback.wait("s", Duration::from_secs(10)).unwrap();
        assert_eq!(code, "early-code");
        assert!(early.join().unwrap().contains("200 OK"));
    }

    #[test]
    fn a_mismatched_state_ends_the_flow_without_yielding_the_code() {
        let loopback = Loopback::bind().unwrap();
        let uri = loopback.redirect_uri();
        let client = thread::spawn(move || get(&uri, "/?code=stolen&state=wrong"));
        let err = loopback
            .wait("expected", Duration::from_secs(10))
            .unwrap_err();
        client.join().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let message = err.to_string();
        assert!(message.contains("state"), "{message}");
        assert!(
            !message.contains("stolen"),
            "the refused code must not be quoted: {message}"
        );
    }

    #[test]
    fn a_refusal_is_reported_without_ending_up_as_a_code() {
        let loopback = Loopback::bind().unwrap();
        let uri = loopback.redirect_uri();
        let client = thread::spawn(move || {
            get(
                &uri,
                "/?error=access_denied&error_description=User+cancelled&state=s",
            )
        });
        let err = loopback.wait("s", Duration::from_secs(10)).unwrap_err();
        client.join().unwrap();
        let message = err.to_string();
        assert!(message.contains("access_denied"), "{message}");
        assert!(message.contains("User cancelled"), "{message}");
    }

    #[test]
    fn browser_noise_does_not_end_the_wait() {
        // A favicon fetch or a speculative preconnect arrives before the real
        // redirect on real desktops. Neither may consume the one-shot wait.
        let loopback = Loopback::bind().unwrap();
        let uri = loopback.redirect_uri();
        let noisy = uri.clone();
        let client = thread::spawn(move || {
            let address = noisy.strip_prefix("http://").unwrap().to_string();
            // A connection that says nothing, then a request with no query.
            drop(TcpStream::connect(&address).unwrap());
            get(&noisy, "/favicon.ico");
            get(&noisy, "/?code=real-code&state=s")
        });
        let code = loopback.wait("s", Duration::from_secs(10)).unwrap();
        assert_eq!(code, "real-code");
        client.join().unwrap();
    }

    #[test]
    fn the_timeout_names_the_sandboxed_browser_cause() {
        let loopback = Loopback::bind().unwrap();
        let err = loopback.wait("s", Duration::ZERO).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let message = err.to_string();
        assert!(message.contains("sandboxed browser"), "{message}");
        assert!(message.contains("Flatpak"), "{message}");
    }

    #[test]
    fn percent_decoding_handles_the_shapes_a_query_carries() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("AADSTS%3A50011"), "AADSTS:50011");
        assert_eq!(percent_decode("trailing%2"), "trailing%2");
        assert_eq!(percent_decode("bad%zzhex"), "bad%zzhex");
    }

    #[test]
    fn control_characters_do_not_reach_a_terminal() {
        assert_eq!(printable_filter("a\u{1b}[31mb\r\n", 40), "a[31mb");
    }
}
