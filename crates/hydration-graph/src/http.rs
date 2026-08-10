//! The socket.
//!
//! Everything else in this crate is a pure function of bytes it was handed.
//! This module is the only place that opens a connection, the only place that
//! knows a bearer token exists, and the only place that turns an HTTP reply
//! into the three shapes the seams above are written against — [`RawPage`],
//! [`Reply`] and [`TokenReply`]. It implements [`PageSource`] for the read
//! half, [`Transport`] for the write half and [`TokenTransport`] for the
//! credential, and it decides nothing else: no retry policy, no backoff, no
//! interpretation of a body. Those live above the line, where a test can drive
//! them in microseconds.
//!
//! ## Three sockets, one configuration
//!
//! The refresh POST is the most sensitive request this program makes — it
//! carries a single-use credential that, spent wrongly, signs the user out of
//! every machine they own — so it is emphatically not the one to leave for a
//! caller to wire up with an HTTP client of its own. [`GraphTokens`] sends it
//! through the same [`agent`] configuration as everything else: rustls with
//! real certificate verification, the compiled-in root program rather than the
//! platform store, `https_only`, no redirects, and the same timeouts — plus a
//! whole-call one, because [`crate::auth::TOKEN_POST_DEADLINE`] is a hard requirement
//! rather than a preference and the shipped transport is where it is kept.
//!
//! [`crate::auth::TokenCache`] is itself a [`TokenSource`], so the wiring is
//! `GraphHttp::new(Arc::clone(&cache))` and nothing in between reshapes a
//! credential. That matters more than it looks: the alternative — a seam that
//! wants the bare token while the cache hands out an `Authorization` value —
//! can only be bridged by slicing a credential string in glue code, which is
//! how a `[7..]` ends up in the one place nobody wants an off-by-one.
//!
//! Behind the `http` feature, off by default, so that the crate builds and its
//! whole suite runs on a machine with no TLS stack, no certificate store and no
//! network.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ureq::http::header::{HeaderName, HeaderValue};

use crate::auth::{
    AuthError, Clock, CredentialStore, TokenCache, TokenReply, TokenRequest, TokenTransport,
};
use crate::{
    delta_url, latest_url, on_the_graph_endpoint, DeltaLink, DriveScope, Method, NextLink,
    PageSource, RawPage, Reply, Request, Transport,
};

// ---------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------

/// The ceiling on a reply this module will read into memory.
///
/// A response body is attacker-controlled in the only sense that matters here:
/// its length is chosen by the far end. `read_to_end` on a socket is an OOM the
/// remote side can trigger at will, and the process that dies owns the upload
/// queue. A delta page is 200 items — a few hundred kilobytes — and every other
/// reply this crate reads is a single `driveItem` or an upload session, so the
/// limit is two orders of magnitude above anything legitimate and still finite.
const MAX_REPLY_BYTES: u64 = 16 * 1024 * 1024;

/// The longest `Retry-After` that is passed through as given.
///
/// The seams above sleep whatever this module reports, a bounded number of
/// times. A service that answers `Retry-After: 86400` therefore parks the delta
/// thread for four days, with nothing in any log, and the download direction
/// simply stops. Clamping trades a wasted retry against a dead thread: the
/// retry budget is exhausted, the round fails *visibly*, and the caller runs
/// another one later. Five minutes is above every throttle Graph issues in
/// practice and below the point where a stalled thread stops looking like a
/// stall.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// How long to wait for a connection, a name, and the first byte of a reply.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);
const RECV_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const RECV_BODY_TIMEOUT: Duration = Duration::from_secs(120);

/// The ceiling on sending one request body.
///
/// Deliberately generous rather than absent. The largest body this crate sends
/// is one upload fragment — 10 MiB by default — so ten minutes is a floor of
/// about 17 KiB/s, below any link a sync client is usable on. Left unset, a
/// socket that is open but dead hangs the upload thread forever, and every edit
/// queued behind it exists nowhere but this machine.
const SEND_BODY_TIMEOUT: Duration = Duration::from_secs(600);

/// The ceiling on a whole token-endpoint round trip.
///
/// [`crate::auth::TOKEN_POST_DEADLINE`] says why this exists rather than being left to
/// the per-phase timeouts above: the cache holds a mutex every thread in the
/// process needs across this call, so "slow" and "wedged" are the same outcome.
/// The per-phase timeouts do not add up to a bound — a connection that
/// establishes, then trickles, then stalls, resets each of them in turn — and a
/// whole-call one does.
///
/// Sixty seconds for a request that is four form fields and a reply that is two
/// tokens. This is not a performance budget; it is the point past which
/// something is wrong.
const TOKEN_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// The ceiling on a token-endpoint reply.
///
/// Same reasoning as [`MAX_REPLY_BYTES`] and two orders of magnitude smaller,
/// because the largest legitimate answer here is an access token, a refresh
/// token and an `expires_in`. A megabyte of it is a different service.
const MAX_TOKEN_REPLY_BYTES: u64 = 256 * 1024;

/// What this client calls itself. Not cosmetic: it is what the service's
/// throttling diagnostics have to identify when a tenant asks why it is being
/// slowed down.
const USER_AGENT: &str = concat!("hydration-graph/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// Where the credential comes from
// ---------------------------------------------------------------------------

/// The account's credential, fetched at the moment it is about to be used.
///
/// A seam rather than a `String` field, because an OAuth access token expires —
/// typically in an hour — and a long-lived sync process outlives it many times
/// over. Asked for per request, so a refresh is a detail of the implementation
/// rather than a restart of the process.
///
/// [`crate::auth::TokenCache`] implements this, and is what a daemon should use: it
/// does the device code flow, the single-flight refresh and the rotation. The
/// seam remains because it is also reasonable to hold a token from a broker, a
/// keyring, or another process, and because a suite that needed a real
/// credential to test the write path is a suite nobody runs.
pub trait TokenSource: Send {
    /// The complete value of the `Authorization` header, `Bearer ` prefix
    /// included.
    ///
    /// The whole header value and **not** the bare token, so that
    /// [`crate::auth::AccessToken::header_value`] fits this seam exactly. The bare
    /// token is not a shape anything in `auth` produces — it exists behind
    /// `Secret`, which has two named doors and neither of them is this — so a
    /// seam that asked for it could only be fed by slicing off a seven-character
    /// prefix in whatever glue code got written last. Nothing that handles a
    /// credential should be doing arithmetic on its string.
    fn authorization(&mut self) -> io::Result<String>;
}

/// One fixed token. For tests, for short-lived tools, and for a caller that
/// does its own refreshing somewhere else.
///
/// Takes the bare token and adds the prefix, because that is the form a token
/// arrives in from anything that is not this crate.
pub struct StaticToken(String);

impl StaticToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }
}

impl TokenSource for StaticToken {
    fn authorization(&mut self) -> io::Result<String> {
        Ok(format!("Bearer {}", self.0))
    }
}

/// A token source shared between the read half and the write half.
///
/// The two seams are owned by different objects on different threads, so each
/// gets its own [`GraphHttp`]; this is how they nonetheless share one refresh
/// rather than racing to perform two.
///
/// [`crate::auth::TokenCache`] needs no such wrapper — it takes `&self` throughout and
/// has its own lock — so `Arc<TokenCache<…>>` is the shape to reach for. This
/// impl is for a `TokenSource` written elsewhere that does not.
impl<T: TokenSource> TokenSource for Arc<std::sync::Mutex<T>> {
    fn authorization(&mut self) -> io::Result<String> {
        let mut inner = self
            .lock()
            .map_err(|_| io::Error::other("the token source is poisoned"))?;
        inner.authorization()
    }
}

/// The shared cache, used directly.
///
/// This is the wiring the daemon wants: one `Arc<TokenCache>` built at startup,
/// cloned into the delta thread's [`GraphHttp`] and the upload thread's, so the
/// single-flight refresh that `auth` exists to provide actually spans them. Two
/// caches over one stored credential reproduces the exact failure that module
/// was written to prevent, and no type can refuse it — but this impl at least
/// makes the correct wiring the short one to write.
impl<T: TokenTransport, C: Clock, S: CredentialStore> TokenSource for Arc<TokenCache<T, C, S>> {
    fn authorization(&mut self) -> io::Result<String> {
        Ok(self.token().map_err(auth_failure)?.header_value())
    }
}

/// The same, for a cache a caller owns outright rather than shares. Rare — the
/// point of the cache is that it is shared — and here so that the seam does not
/// force an `Arc` on a single-threaded tool.
impl<T: TokenTransport, C: Clock, S: CredentialStore> TokenSource for TokenCache<T, C, S> {
    fn authorization(&mut self) -> io::Result<String> {
        Ok(TokenCache::token(self)
            .map_err(auth_failure)?
            .header_value())
    }
}

/// An [`AuthError`] as an `io::Error`, built from literals.
///
/// Every message here is a string constant chosen in this file. `AuthError` is
/// already sanitised at its own boundary, but this error travels further than
/// that one — out through `PageSource` and `Transport` into the round driver,
/// which logs it — and the rule at a widening boundary is that nothing a
/// service, a store or a transport chose gets to cross it.
///
/// The kind is the part a caller can act on, so it is chosen rather than
/// flattened: `PermissionDenied` is "stop and ask the user", everything else is
/// "this round failed".
fn auth_failure(e: AuthError) -> io::Error {
    match e {
        AuthError::SignedOut => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no credential is held; a device code sign-in is needed",
        ),
        AuthError::CredentialRejected => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the stored credential has been refused; a new sign-in is needed",
        ),
        AuthError::InvalidGrant | AuthError::AccessDenied => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the refresh token was refused",
        ),
        AuthError::Transport { kind } => {
            io::Error::new(kind, "the token endpoint could not be reached")
        }
        _ => io::Error::other("the access token could not be refreshed"),
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// The Graph transport: one connection pool, one token source.
///
/// Implements both seams. Construct two of them — one for the delta thread, one
/// for the upload thread — and give them the same shared [`TokenSource`]. They
/// are separate values on purpose: `PageSource` and `Transport` are `&mut self`
/// traits, so a single shared client would need a lock held across a whole
/// request, and a 10 MiB fragment upload would block every delta page behind
/// it.
pub struct GraphHttp<T: TokenSource> {
    agent: ureq::Agent,
    token: T,
}

impl<T: TokenSource> GraphHttp<T> {
    fn send_response(
        &mut self,
        method: Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        authorize: bool,
    ) -> io::Result<ureq::http::Response<ureq::Body>> {
        let headers = caller_headers(headers)?;
        let authorized = may_authorize(url, authorize)?;

        let mut builder = ureq::http::Request::builder()
            .method(method.as_str())
            .uri(url);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if authorized {
            builder = builder.header(
                ureq::http::header::AUTHORIZATION,
                authorization_header(&mut self.token)?,
            );
        }

        let bodiless = body.is_empty() && matches!(method, Method::Get | Method::Delete);
        if bodiless {
            builder
                .body(())
                .map_err(bad_request)
                .and_then(|request| self.agent.run(request).map_err(|e| wire_error(url, e)))
        } else {
            builder
                .body(body)
                .map_err(bad_request)
                .and_then(|request| self.agent.run(request).map_err(|e| wire_error(url, e)))
        }
    }

    pub fn new(token: T) -> Self {
        Self {
            agent: agent(),
            token,
        }
    }
}

/// The one place the client is configured.
///
/// # TLS
///
/// Certificates are verified. Saying so in a comment is not ceremony: it is the
/// only way this decision is visible, because the failure mode of getting it
/// wrong is *silent*. A client with verification disabled connects, completes
/// the handshake, transfers data and returns 200 — against any host that can
/// get itself in the path. There is no error, no warning and no log line, and
/// the first symptom is somebody else holding a token that can read and delete
/// the user's entire drive.
///
/// Concretely:
///
/// * `TlsProvider::Rustls` — rustls performs full X.509 path building and
///   chain validation, and checks the certificate against the SNI hostname.
///   There is no mode in which it accepts a name mismatch quietly.
/// * `RootCerts::WebPki` — Mozilla's root program, compiled in, rather than the
///   platform store. Deliberate: the platform store is where a corporate
///   interception proxy installs the root that makes a machine-in-the-middle
///   look legitimate, and a *sync client's* credential is exactly what such a
///   proxy should not get. A deployment that genuinely needs to trust an
///   internal CA has to change this line and be seen to change it.
/// * `disable_verification` is never called. ureq's default is `false`; it is
///   set here anyway, explicitly, so that the guarantee is a statement in this
///   file rather than an inherited default, and so `verification_is_on` below
///   fails loudly if anyone flips it.
/// * `https_only(true)` — a plaintext URL is refused by the client, not just by
///   the origin check. That check only runs for requests that carry a
///   credential; this one also covers the pre-authorised upload URLs, where the
///   scheme is chosen by a *response body* and `http://` would put the user's
///   file contents on the wire in the clear.
///
/// # Redirects
///
/// Not followed at all. ureq strips `Authorization` across hosts by default,
/// but "not followed" is the property actually wanted: no call site in this
/// crate expects a redirect, so a `Location` is a 3xx handed upward as the
/// status it is, rather than a second request to a host nobody chose.
///
/// # One configuration, two agents
///
/// `whole_call` is the only difference between the Graph client and the token
/// client, and it is `None` for Graph on purpose: the largest request this crate
/// sends is a 10 MiB upload fragment, and a whole-call ceiling that a slow link
/// can reach turns a working upload into a retry loop. The token endpoint has no
/// such request, and a bound there is worth far more — see
/// [`TOKEN_CALL_TIMEOUT`].
fn config(whole_call: Option<Duration>) -> ureq::config::Config {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::WebPki)
        .disable_verification(false)
        .build();

    ureq::Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        // Status codes are data here, not errors: 429, 410 and 404 all mean
        // something specific to the layers above, and a client that turned
        // them into `Err` would hide every one of them behind one io error.
        // The token endpoint needs this just as much: `authorization_pending`
        // and `invalid_grant` both arrive as HTTP 400 with the answer in the
        // body, and a client that refused to read a 400's body could not tell
        // "the user has not clicked yet" from "you are signed out".
        .http_status_as_error(false)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .user_agent(USER_AGENT)
        .timeout_global(whole_call)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_resolve(Some(RESOLVE_TIMEOUT))
        .timeout_recv_response(Some(RECV_RESPONSE_TIMEOUT))
        .timeout_recv_body(Some(RECV_BODY_TIMEOUT))
        .timeout_send_body(Some(SEND_BODY_TIMEOUT))
        .build()
}

/// The client every Graph request goes through.
fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(config(None))
}

/// The client the refresh POST goes through.
///
/// Everything [`agent`] guarantees, plus the whole-call ceiling that
/// [`crate::auth::TOKEN_POST_DEADLINE`] requires. Separate from the Graph agent only in
/// that one setting — the certificate verification, the root store, the
/// `https_only` refusal and the redirect policy are literally the same code, so
/// they cannot drift apart for the one request where getting them wrong hands
/// over a credential that can read and delete the user's entire drive.
fn token_agent() -> ureq::Agent {
    ureq::Agent::new_with_config(config(Some(TOKEN_CALL_TIMEOUT)))
}

// ---------------------------------------------------------------------------
// The credential
// ---------------------------------------------------------------------------

/// Whether this request may carry the account's bearer token.
///
/// **This is the whole point of the module.** `Request::authorize` is set by the
/// sink, which is the only layer that knows where a URL came from; an upload
/// session's `uploadUrl` is named by a response body, points at `up.1drv.com`,
/// and carries its own pre-authorisation. Attaching the Graph token to it hands
/// a live write credential for the user's entire drive to whatever host that
/// body named.
///
/// Two conditions, both checked here, at the point the header is added — not
/// upstream, not by convention:
///
/// * the caller said so, and
/// * the URL is on the Graph endpoint, judged by scheme, host and port.
///
/// Neither alone is enough. The flag alone trusts every present and future call
/// site to remember `.unauthorized()`, and forgetting it is silent. The origin
/// alone overrides a caller that deliberately said no.
///
/// The flag-set-but-wrong-host case is an **error, not a downgrade**. Sending
/// it anyway without the header would turn a credential leak into a confusing
/// 401 from a host we never meant to talk to — and if that host answers 200, a
/// stranger has just been handed the request body. The request is not sent.
///
/// This is not redundant with the driver's own `on_the_graph_endpoint` calls.
/// The driver checks `nextLink` and `deltaLink` as it reads them off a page,
/// but `PageSource::resume` is handed a token read back out of the *state
/// store* — a file on disk, written by some earlier version of this program —
/// and nothing re-checks that on the way in. This is where that URL is judged.
fn may_authorize(url: &str, authorize: bool) -> io::Result<bool> {
    if !authorize {
        return Ok(false);
    }
    if !on_the_graph_endpoint(url) {
        // The URL is not named, here or anywhere below: if it is a session URL
        // it *is* a credential, and an error message is a thing that gets
        // logged.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a request marked for the account credential addressed a host that is \
             not the Graph endpoint; it was not sent",
        ));
    }
    Ok(true)
}

/// The caller's headers, validated.
///
/// `Request::headers` is an ordinary `Vec` that any call site can push onto, so
/// an `authorization` header placed there would walk straight past
/// [`may_authorize`] and be sent to whatever host the request names. Refused
/// rather than dropped: a caller that set one meant something by it, and
/// silently discarding it would leave that intent unmet and unreported.
///
/// `HeaderName`/`HeaderValue` parsing is also the CRLF check — a value
/// containing a newline is request splitting, and both constructors reject it.
fn caller_headers(headers: &[(String, String)]) -> io::Result<Vec<(HeaderName, HeaderValue)>> {
    let mut out = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("cookie")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("`{name}` is the transport's to set, and this request set it itself"),
            ));
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a header name is not one"))?;
        let value = HeaderValue::from_str(value).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "a header value is not one")
        })?;
        out.push((name, value));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Retry-After
// ---------------------------------------------------------------------------

/// `Retry-After`, in either of the two forms RFC 9110 defines.
///
/// A number is delta-seconds. Anything else is an HTTP-date, and the wait is
/// the distance from now to then.
///
/// **Zero is reported as `None`, not as `Some(Duration::ZERO)`**, and so is any
/// date already in the past. That is not tidiness. Both callers above this seam
/// do `retry_after.unwrap_or(BLIND_BACKOFF)` — `Some(0)` therefore means
/// "re-issue immediately", against an endpoint that has just said it is
/// overloaded, four times in a row as fast as the socket allows. `None` means
/// "the server named no delay", which is the truth, and the five-second floor
/// above applies. A clock that is a few seconds ahead of the server's is enough
/// to produce a past date from a perfectly well-formed reply, so this is a live
/// path and not a hostile one.
///
/// Unparseable is `None` for the same reason: a header nobody can read is a
/// server that named no delay.
fn parse_retry_after(raw: &str, now: SystemTime) -> Option<Duration> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let waited = if raw.bytes().all(|b| b.is_ascii_digit()) {
        // Saturating rather than `ok()?`: a value too long for a u64 is a very
        // large delay, not an absent one, and it is about to be clamped anyway.
        Duration::from_secs(raw.parse::<u64>().unwrap_or(u64::MAX))
    } else {
        let when = httpdate::parse_http_date(raw).ok()?;
        // `duration_since` errors when `when` is before `now`; a date in the
        // past is a delay of nothing.
        when.duration_since(now).unwrap_or(Duration::ZERO)
    };

    if waited.is_zero() {
        return None;
    }
    Some(waited.min(MAX_RETRY_AFTER))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A transport failure, said without saying where.
///
/// The URL never appears in the message and the underlying error is never put
/// in the source chain for anything off the Graph endpoint. A `uploadUrl` is a
/// bearer credential in URL form — that is why the documentation says to strip
/// `Authorization` when using it — and `source()` is walked when an error is
/// rendered, so wrapping a ureq error that happens to carry the URI would put
/// that credential in a log the first time an upload failed.
fn wire_error(url: &str, e: ureq::Error) -> io::Error {
    if !on_the_graph_endpoint(url) {
        return io::Error::other("the request could not be completed");
    }
    match e {
        // Kept whole: the `ErrorKind` is the only structured thing a caller
        // gets, and `TimedOut` versus `ConnectionRefused` is the difference
        // between "later" and "never".
        ureq::Error::Io(e) => e,
        ureq::Error::Timeout(_) => io::Error::new(io::ErrorKind::TimedOut, "the request timed out"),
        ureq::Error::HostNotFound => io::Error::new(
            io::ErrorKind::NotFound,
            "the Graph endpoint did not resolve",
        ),
        ureq::Error::BodyExceedsLimit(_) => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the reply was larger than the {MAX_REPLY_BYTES} byte ceiling"),
        ),
        other => io::Error::other(format!("{other}")),
    }
}

// ---------------------------------------------------------------------------
// The identity platform
// ---------------------------------------------------------------------------

/// The socket the refresh POST goes out on: [`TokenTransport`], shipped.
///
/// Without this, the single most sensitive request in the system — the one
/// carrying a single-use refresh token — is the one request with no client, and
/// whoever wires the daemon up writes their own. None of `agent`'s work would
/// apply to it: not the pinned root program, not `https_only`, not the refusal
/// to follow a redirect, not the timeouts. That is the wrong request to leave as
/// an exercise.
///
/// Stateless apart from its connection pool, and `&self` throughout, so one of
/// these is shared by every [`crate::auth::TokenCache`] in the process.
pub struct GraphTokens {
    agent: ureq::Agent,
}

impl GraphTokens {
    pub fn new() -> Self {
        Self {
            agent: token_agent(),
        }
    }
}

impl Default for GraphTokens {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenTransport for GraphTokens {
    /// One form POST, one reply, no interpretation.
    ///
    /// The URL is not checked here and does not need to be: [`TokenRequest`] has
    /// no public constructor, and `TokenCache` re-checks the authority against
    /// its own validated config immediately before calling this. What *is*
    /// enforced here is the scheme — `https_only` on the agent — because a
    /// plaintext token endpoint is the refresh token in the clear.
    fn post(&self, request: &TokenRequest) -> io::Result<TokenReply> {
        let built = ureq::http::Request::builder()
            .method("POST")
            .uri(request.url())
            .header(ureq::http::header::CONTENT_TYPE, TokenRequest::CONTENT_TYPE)
            .header(ureq::http::header::ACCEPT, "application/json")
            .body(request.body().as_bytes())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the token request could not be composed",
                )
            })?;

        let mut response = self.agent.run(built).map_err(token_error)?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_TOKEN_REPLY_BYTES)
            .read_to_vec()
            .map_err(token_error)?;
        Ok(TokenReply::new(status, body))
    }
}

/// A token-endpoint failure, reduced to its kind.
///
/// Deliberately not [`wire_error`], which keeps ureq's own error whole for Graph
/// URLs so that a caller can read its `ErrorKind` and its message. The request
/// that failed here had a refresh token in its *body*, and a client that quotes
/// what it was sending — a debug build, a proxy wrapper, a middleware someone
/// adds later — would put that in the message. `auth` reduces this to a kind
/// again on the way in, and that is a second line of defence rather than a
/// reason to skip the first: this is the door, and the check belongs at the
/// door.
fn token_error(e: ureq::Error) -> io::Error {
    let kind = match &e {
        ureq::Error::Io(e) => e.kind(),
        ureq::Error::Timeout(_) => io::ErrorKind::TimedOut,
        ureq::Error::HostNotFound => io::ErrorKind::NotFound,
        ureq::Error::BodyExceedsLimit(_) => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, "the token endpoint request could not be completed")
}

// ---------------------------------------------------------------------------
// The one request
// ---------------------------------------------------------------------------

struct Answer {
    status: u16,
    retry_after: Option<Duration>,
    body: Vec<u8>,
}

impl<T: TokenSource> GraphHttp<T> {
    /// Send one request and read one reply. Nothing else in this module talks
    /// to the network, and this function retries nothing: retry policy is above
    /// the seam, where a test can drive it without a clock.
    fn round_trip(
        &mut self,
        method: Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        authorize: bool,
    ) -> io::Result<Answer> {
        // A GET or DELETE with nothing to send carries no `content-length` at
        // all; anything else carries one, *including a zero* — a PUT of an
        // empty file is a real request, and a PUT with no length is not the
        // same thing as a PUT of nothing.
        let mut response = self.send_response(method, url, headers, body, authorize)?;

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(ureq::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| parse_retry_after(v, SystemTime::now()));
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_REPLY_BYTES)
            .read_to_vec()
            .map_err(|e| wire_error(url, e))?;

        Ok(Answer {
            status,
            retry_after,
            body,
        })
    }

    /// Stream one drive item's content without buffering it in the daemon.
    ///
    /// Graph normally answers `/content` with a pre-authorized HTTPS URL. The
    /// first request carries the account token; the second emphatically does
    /// not. Redirect following stays disabled in the agent so this boundary is
    /// visible here rather than delegated to a client default.
    pub fn download_content(
        &mut self,
        key: &crate::ObjectKey,
        expected: u64,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        let graph_url = crate::item_content_url(key);
        let headers = [("accept".to_string(), "application/octet-stream".to_string())];
        let mut response = self.send_response(Method::Get, &graph_url, &headers, &[], true)?;

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(ureq::http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .filter(|url| safe_download_url(url))
                .map(str::to_owned)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Graph returned an unsafe content redirect; it was not followed",
                    )
                })?;
            response = self.send_response(Method::Get, &location, &headers, &[], false)?;
        }

        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Graph content request returned HTTP {}",
                response.status().as_u16()
            )));
        }
        copy_exact(response.body_mut().as_reader(), out, expected)
    }
}

fn safe_download_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@')
}

fn copy_exact(mut source: impl Read, out: &mut dyn Write, expected: u64) -> io::Result<()> {
    let copied = io::copy(&mut source, out)?;
    if copied != expected {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("Graph returned {copied} content bytes; expected {expected}"),
        ));
    }
    Ok(())
}

fn bad_request(_: ureq::http::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the request could not be composed",
    )
}

/// The `Authorization` header, and the one place a [`TokenSource`]'s failure is
/// allowed to become this module's.
///
/// The kind is kept and the message is replaced with a literal. That is not
/// tidiness — it is the same rule as [`crate::auth::AuthError::Transport`], applied at
/// the other end of the same wire. A `TokenSource` is free to be anything: a
/// keyring binding, a broker, another process's cache, a wrapper somebody adds
/// around one of those. Its `io::Error` is the *only* error on this path not
/// built from a constant in this crate, and this path ends at
/// `PageSource`/`Transport`, where the round driver logs whatever it is handed.
/// A source that says what it could not do ("refresh POST failed: refresh_token
/// =1//0eXy…") would put a credential in that log line, once, and then in every
/// copy of it.
fn authorization_header<T: TokenSource + ?Sized>(token: &mut T) -> io::Result<HeaderValue> {
    let raw = token
        .authorization()
        .map_err(|e| io::Error::new(e.kind(), "the access token could not be obtained"))?;
    let mut value = HeaderValue::from_str(&raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the access token is not a header value",
        )
    })?;
    // Marks it as redacted in `http`'s own `Debug`, which is what ends up in a
    // panic message or a dropped request dump.
    value.set_sensitive(true);
    Ok(value)
}

// ---------------------------------------------------------------------------
// The read half
// ---------------------------------------------------------------------------

impl<T: TokenSource> PageSource for GraphHttp<T> {
    fn first(&mut self, scope: &DriveScope) -> io::Result<RawPage> {
        self.page(&delta_url(scope))
    }

    fn next(&mut self, link: &NextLink) -> io::Result<RawPage> {
        self.page(link.as_str())
    }

    /// The link comes back out of the state store, not off a page, so this is
    /// the first time anything has looked at it since it was written. See
    /// [`may_authorize`].
    fn resume(&mut self, link: &DeltaLink) -> io::Result<RawPage> {
        self.page(link.as_str())
    }

    fn latest(&mut self, scope: &DriveScope) -> io::Result<RawPage> {
        self.page(&latest_url(scope))
    }
}

impl<T: TokenSource> GraphHttp<T> {
    fn page(&mut self, url: &str) -> io::Result<RawPage> {
        let answer = self.round_trip(
            Method::Get,
            url,
            &[("accept".to_string(), "application/json".to_string())],
            &[],
            true,
        )?;
        Ok(RawPage {
            status: answer.status,
            retry_after: answer.retry_after,
            body: answer.body,
        })
    }
}

// ---------------------------------------------------------------------------
// The write half
// ---------------------------------------------------------------------------

impl<T: TokenSource> Transport for GraphHttp<T> {
    fn send(&mut self, request: &Request) -> io::Result<Reply> {
        let answer = self.round_trip(
            request.method,
            &request.url,
            &request.headers,
            &request.body,
            request.authorize,
        )?;
        Ok(Reply {
            status: answer.status,
            retry_after: answer.retry_after,
            body: answer.body,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
//
// Everything below the seam that can be decided without a socket, decided
// without one. What is left untested here is the socket itself, and that is
// the part a unit test cannot honestly cover.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthConfig, RefreshToken};

    const GRAPH: &str = "https://graph.microsoft.com/v1.0/drives/d/root/delta";
    // Where a real upload session lives: a host this crate never composed.
    const SESSION: &str = "https://up.1drv.com/upload.aspx?token=abc";
    const CLIENT: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn content_redirect_must_be_https_without_userinfo() {
        assert!(safe_download_url(
            "https://public.dm.files.1drv.com/content?q=token"
        ));
        assert!(!safe_download_url(
            "http://public.dm.files.1drv.com/content"
        ));
        assert!(!safe_download_url("https://token@evil.example/content"));
        assert!(!safe_download_url("not a url"));
    }

    #[test]
    fn streamed_content_must_match_the_promised_size() {
        let mut out = Vec::new();
        copy_exact(&b"content"[..], &mut out, 7).unwrap();
        assert_eq!(out, b"content");

        let err = copy_exact(&b"short"[..], &mut Vec::new(), 6).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    // --- doubles for the auth seams ----------------------------------------
    //
    // Small and local. The point of these tests is the *join* between `auth`
    // and this module; `auth`'s own suite covers what the cache does once it
    // has a reply.

    /// An identity platform that always answers the same way.
    struct OneReply(&'static str);

    impl TokenTransport for OneReply {
        fn post(&self, _request: &TokenRequest) -> io::Result<TokenReply> {
            Ok(TokenReply::new(200, self.0.as_bytes().to_vec()))
        }
    }

    struct Frozen;

    impl Clock for Frozen {
        fn now(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&self, _how_long: Duration) {}
    }

    struct NoStore;

    impl CredentialStore for NoStore {
        fn load(&self) -> io::Result<Option<RefreshToken>> {
            Ok(None)
        }
        fn save(&self, _refresh: &RefreshToken) -> io::Result<()> {
            Ok(())
        }
    }

    type TestCache = TokenCache<OneReply, Frozen, NoStore>;

    fn cache(reply: &'static str) -> Arc<TestCache> {
        Arc::new(TokenCache::new(
            AuthConfig::public_client(CLIENT),
            OneReply(reply),
            Frozen,
            NoStore,
        ))
    }

    // --- the two modules are joined ----------------------------------------

    /// The seam between `auth` and this module exists, and it is
    /// shape-compatible.
    ///
    /// Catches the state this crate was in: `auth::TokenCache` produced an
    /// `Authorization` value, `TokenSource` wanted a bare token, and `Secret`
    /// let neither of them meet — so putting a cached token on a request meant
    /// `header_value()[7..]` in whatever glue code got written last, hand-slicing
    /// a credential. It catches that same bridge being written *here*: a
    /// `TokenSource` that stripped the prefix would produce `"ACCESS-1"`, and
    /// the assertion is on the exact bytes that go on the wire.
    ///
    /// If the impl is simply missing, this does not compile — which is the same
    /// finding, said earlier.
    #[test]
    fn a_token_cache_is_a_token_source_with_no_slicing_in_between() {
        let cache = cache(r#"{"access_token":"ACCESS-1","expires_in":3600,"refresh_token":"R2"}"#);
        cache.sign_in_with(RefreshToken::new("R1"));

        let mut source = Arc::clone(&cache);
        assert_eq!(source.authorization().expect("a token"), "Bearer ACCESS-1");

        // And that value is what reaches the header, marked so that `http`'s own
        // `Debug` redacts it.
        let header = authorization_header(&mut source).expect("a header");
        assert_eq!(header.to_str().expect("ascii"), "Bearer ACCESS-1");
        assert!(header.is_sensitive());
    }

    /// The wiring a daemon writes, type-checked: **one** cache, two clients.
    ///
    /// Two `GraphHttp`s are needed because `PageSource` and `Transport` are
    /// `&mut self`, and the whole of `auth`'s single-flight guarantee is that
    /// they share one cache. Catches a `TokenSource` impl that exists only for
    /// an owned `TokenCache`, which would force a second cache per thread — the
    /// exact failure `auth` was written to prevent, reintroduced by the wiring.
    #[test]
    fn one_cache_serves_both_halves_of_the_transport() {
        fn reads_pages<P: PageSource>(_: &P) {}
        fn writes<T: Transport>(_: &T) {}

        let cache = cache(r#"{"access_token":"A","expires_in":3600}"#);
        let delta = GraphHttp::new(Arc::clone(&cache));
        let upload = GraphHttp::new(Arc::clone(&cache));
        reads_pages(&delta);
        writes(&upload);
        assert_eq!(Arc::strong_count(&cache), 3);
    }

    /// POSITIVE CONTROL for the error mapping: a cache with no credential must
    /// say so in a way the caller can act on, without opening a socket.
    ///
    /// Catches flattening every `AuthError` to `io::ErrorKind::Other`, which
    /// leaves "prompt the user for a sign-in" indistinguishable from "the
    /// network is down" at the only layer that could tell them apart.
    #[test]
    fn a_signed_out_cache_asks_for_a_sign_in_rather_than_a_socket() {
        let mut source = cache(r#"{"access_token":"A","expires_in":3600}"#);
        let e = source.authorization().expect_err("no credential is held");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    /// The refresh POST has a shipped client, and it is configured like every
    /// other request this crate makes.
    ///
    /// Catches `auth::TokenTransport` having no implementation at all — the
    /// state this crate was in, where the one request carrying a single-use
    /// refresh token was the one request left for a caller to wire up with an
    /// HTTP client of its own. None of the work in [`agent`] would have applied
    /// to it: not the pinned root program, not `https_only`, not the refusal to
    /// follow a redirect.
    #[test]
    fn the_refresh_post_goes_through_this_modules_client() {
        fn is_a_token_transport<T: TokenTransport>(_: &T) {}
        is_a_token_transport(&GraphTokens::new());

        let client = token_agent();
        let token = client.config();
        let client = agent();
        let graph = client.config();

        assert!(
            !token.tls_config().disable_verification(),
            "certificate verification is off for the one request that carries \
             the refresh token"
        );
        assert_eq!(token.tls_config().provider(), graph.tls_config().provider());
        assert!(matches!(
            token.tls_config().root_certs(),
            ureq::tls::RootCerts::WebPki
        ));
        assert!(
            token.https_only(),
            "a plaintext token endpoint is the refresh token in the clear"
        );
        assert_eq!(token.max_redirects(), 0);
        assert!(
            !token.http_status_as_error(),
            "`authorization_pending` and `invalid_grant` both arrive as HTTP 400 \
             with the answer in the body; a client that refused to read a 400's \
             body could not tell 'the user has not clicked yet' from 'you are \
             signed out'"
        );
    }

    /// The deadline `auth::TOKEN_POST_DEADLINE` states is actually enforced by
    /// the shipped transport.
    ///
    /// Catches an agent built without a whole-call timeout. The per-phase
    /// timeouts do not compose into one — a connection that establishes, then
    /// trickles, then stalls resets each of them in turn — and the cache holds
    /// its mutex across this call, so a `post` that never returns wedges every
    /// thread in the process inside `token()`, permanently, with no error.
    #[test]
    fn the_token_client_bounds_the_whole_call() {
        let client = token_agent();
        let global = client.config().timeouts().global.expect(
            "the token client has no whole-call timeout; a refresh POST that \
             hangs holds the cache's mutex and wedges every thread in the \
             process in `token()`",
        );
        assert!(
            global <= crate::auth::TOKEN_POST_DEADLINE,
            "the shipped transport allows {global:?}, which is longer than the \
             {:?} its own seam promises",
            crate::auth::TOKEN_POST_DEADLINE
        );
        // And the Graph client deliberately has none: the largest request this
        // crate sends is a 10 MiB fragment, and a whole-call ceiling a slow link
        // can reach turns a working upload into a retry loop.
        let client = agent();
        assert_eq!(client.config().timeouts().global, None);
    }

    // --- the credential ----------------------------------------------------

    /// A `TokenSource` that says what it failed on — a broker, a keyring
    /// binding, a debug build, a wrapper somebody adds later.
    struct LoudSource;

    impl TokenSource for LoudSource {
        fn authorization(&mut self) -> io::Result<String> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refresh POST failed for refresh_token=REFRESH-1: 400",
            ))
        }
    }

    /// Catches `self.token.bearer()?` — the bare `?` that propagated a
    /// `TokenSource`'s `io::Error` verbatim out of `PageSource` and `Transport`,
    /// where the round driver logs it. It was the only error on that path not
    /// built from a literal in this crate; `auth::AuthError::Transport` and
    /// `TokenCache::persist` both reduce to `e.kind()` for precisely this
    /// reason, and this is the same wire seen from the other end.
    #[test]
    fn a_token_sources_error_message_cannot_reach_the_driver() {
        let e = authorization_header(&mut LoudSource).expect_err("the source failed");
        assert!(
            !format!("{e}").contains("REFRESH-1"),
            "the token source's message reached the error: {e}"
        );
        assert!(
            !format!("{e:?}").contains("REFRESH-1"),
            "the token source's message reached the error's Debug: {e:?}"
        );
        // POSITIVE CONTROL: the kind is the part a caller can act on, so
        // flattening it to `Other` is the other way to get this wrong.
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    /// POSITIVE CONTROL for the header builder: an ordinary token still becomes
    /// an ordinary header. A sanitiser that refused everything would satisfy the
    /// test above while shipping a client that cannot authenticate.
    #[test]
    fn positive_control_a_static_token_becomes_the_header_it_should() {
        let header = authorization_header(&mut StaticToken::new("ACCESS-1")).expect("a header");
        assert_eq!(header.to_str().expect("ascii"), "Bearer ACCESS-1");
    }

    #[test]
    fn the_token_goes_to_graph_when_the_caller_says_so() {
        assert!(may_authorize(GRAPH, true).unwrap());
    }

    #[test]
    fn the_token_is_withheld_when_the_caller_says_no() {
        assert!(!may_authorize(GRAPH, false).unwrap());
        assert!(!may_authorize(SESSION, false).unwrap());
    }

    #[test]
    fn an_authorized_request_to_a_foreign_host_is_refused_not_downgraded() {
        let e = may_authorize(SESSION, true).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        // And the URL is not in the message: it is itself a credential.
        assert!(!format!("{e}").contains("1drv"));
        assert!(!format!("{e}").contains("token=abc"));
    }

    #[test]
    fn the_lookalike_hosts_are_refused() {
        for url in [
            "https://graph.microsoft.com.evil.example/v1.0/me",
            "https://graph.microsoft.com@evil.example/v1.0/me",
            "https://user@graph.microsoft.com@evil.example/v1.0/me",
            "http://graph.microsoft.com/v1.0/me",
            "//graph.microsoft.com/v1.0/me",
            "https://evil.example/graph.microsoft.com/v1.0/me",
        ] {
            assert!(
                may_authorize(url, true).is_err(),
                "{url} was treated as the Graph endpoint"
            );
        }
    }

    #[test]
    fn a_caller_cannot_smuggle_its_own_authorization_header() {
        for name in ["authorization", "Authorization", "PROXY-AUTHORIZATION"] {
            let headers = vec![(name.to_string(), "Bearer stolen".to_string())];
            assert!(
                caller_headers(&headers).is_err(),
                "`{name}` passed through the header check"
            );
        }
    }

    #[test]
    fn a_header_that_would_split_the_request_is_refused() {
        assert!(caller_headers(&[("if-match".into(), "a\r\nx-evil: 1".into())]).is_err());
        assert!(caller_headers(&[("if\r\n-match".into(), "a".into())]).is_err());
    }

    #[test]
    fn ordinary_headers_pass() {
        let ok = caller_headers(&[
            ("content-type".into(), "application/octet-stream".into()),
            ("content-range".into(), "bytes 0-99/100".into()),
        ])
        .unwrap();
        assert_eq!(ok.len(), 2);
    }

    // --- Retry-After -------------------------------------------------------

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn retry_after_in_seconds() {
        assert_eq!(
            parse_retry_after("120", at(0)),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after("  7 ", at(0)),
            Some(Duration::from_secs(7))
        );
    }

    #[test]
    fn retry_after_as_an_http_date() {
        // 1970-01-01 00:02:00 GMT, ninety seconds after `now`.
        let now = at(30);
        assert_eq!(
            parse_retry_after("Thu, 01 Jan 1970 00:02:00 GMT", now),
            Some(Duration::from_secs(90))
        );
    }

    #[test]
    fn retry_after_accepts_the_obsolete_date_forms() {
        // RFC 9110 requires a recipient to parse all three. These are the two
        // nobody writes any more and every client is still obliged to read.
        let now = at(30);
        assert_eq!(
            parse_retry_after("Thursday, 01-Jan-70 00:02:00 GMT", now),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            parse_retry_after("Thu Jan  1 00:02:00 1970", now),
            Some(Duration::from_secs(90))
        );
    }

    #[test]
    fn a_zero_delay_is_none_so_the_floor_above_applies() {
        // The whole reason this function returns `Option`: both callers do
        // `retry_after.unwrap_or(BLIND_BACKOFF)`, so `Some(0)` is an immediate
        // re-issue against an endpoint that has just said it is overloaded.
        assert_eq!(parse_retry_after("0", at(0)), None);
    }

    #[test]
    fn a_date_already_past_is_none_not_zero() {
        // A clock a few seconds ahead of the server's produces this from a
        // perfectly well-formed reply.
        assert_eq!(
            parse_retry_after("Thu, 01 Jan 1970 00:00:10 GMT", at(60)),
            None
        );
    }

    #[test]
    fn an_unreadable_retry_after_is_none() {
        for raw in [
            "",
            "   ",
            "soon",
            "-5",
            "12.5",
            "Fri, 99 Xxx 1970 00:00:00 GMT",
        ] {
            assert_eq!(parse_retry_after(raw, at(0)), None, "{raw:?}");
        }
    }

    #[test]
    fn an_absurd_retry_after_is_clamped_rather_than_obeyed() {
        assert_eq!(parse_retry_after("86400", at(0)), Some(MAX_RETRY_AFTER));
        assert_eq!(
            parse_retry_after("99999999999999999999999", at(0)),
            Some(MAX_RETRY_AFTER)
        );
        assert_eq!(
            parse_retry_after("Fri, 01 Jan 2100 00:00:00 GMT", at(0)),
            Some(MAX_RETRY_AFTER)
        );
    }

    // --- the configuration that fails silently -----------------------------

    #[test]
    fn verification_is_on() {
        // This test exists because turning verification off produces no error,
        // no warning and a working connection. If someone ever "fixes a cert
        // problem" by flipping one of these, this is what says so.
        let agent = agent();
        let config = agent.config();
        assert!(
            !config.tls_config().disable_verification(),
            "certificate verification has been disabled"
        );
        assert!(
            config.https_only(),
            "plaintext requests have been allowed; an upload URL comes from a \
             response body and would put file contents on the wire in the clear"
        );
        assert_eq!(
            config.tls_config().provider(),
            ureq::tls::TlsProvider::Rustls
        );
        assert!(matches!(
            config.tls_config().root_certs(),
            ureq::tls::RootCerts::WebPki
        ));
    }

    #[test]
    fn a_redirect_is_a_status_not_a_second_request() {
        let agent = agent();
        let config = agent.config();
        assert_eq!(config.max_redirects(), 0);
        assert!(!config.max_redirects_will_error());
    }

    #[test]
    fn a_status_code_is_data() {
        // 429, 410 and 404 each mean something specific above this seam; a
        // client that turned them into `Err` would hide all three.
        assert!(!agent().config().http_status_as_error());
    }

    // --- the URLs ----------------------------------------------------------

    #[test]
    fn the_urls_this_module_composes_are_on_the_endpoint() {
        let scope = DriveScope::primary(crate::DriveId::parse("d").unwrap());
        assert!(may_authorize(&delta_url(&scope), true).unwrap());
        assert!(may_authorize(&latest_url(&scope), true).unwrap());
        assert!(latest_url(&scope).contains("token=latest"));
    }
}
