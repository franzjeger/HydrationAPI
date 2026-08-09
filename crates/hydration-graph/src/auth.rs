//! OAuth 2.0 for the Graph provider: the device code flow that signs a desktop
//! client in, and the token cache the provider instances share.
//!
//! Two things live here and nothing else does. The **device code flow**, because
//! a daemon has no browser and no redirect URI to be called back on. And the
//! **token cache**, because `PROVIDER.md:224-229` describes the one failure this
//! module exists to make impossible:
//!
//! > the shipped daemon builds a *separate* instance per role — the startup
//! > check, the upload thread, the delta thread, the fetch loop — and three of
//! > those run concurrently. So one instance never races itself, but your
//! > implementation does race itself […] MSAL rotates the refresh token on use,
//! > and two concurrent refreshes of a single-use token produce `invalid_grant`.
//!
//! The consequence of getting that wrong is not a failed request. It is a signed
//! out user: the second refresh presents a token the first one already consumed,
//! the service revokes the whole chain, and every instance on the machine is
//! dead until a human types a code into a web page again.
//!
//! ## How concurrent refresh is made impossible
//!
//! Not with a flag, not with a "refreshing" bool, not with a comment asking the
//! next reader to be careful. The refresh token lives *inside* a [`std::sync::Mutex`], and
//! [`crate::auth::TokenCache`] exposes no method that copies it out — [`crate::auth::RefreshToken`] is not
//! `Clone`, has no `Display`, and the only borrow of it that exists is the one
//! `AuthConfig::refresh_request` takes while the guard is held. So the request
//! that spends the credential cannot be *built* outside the critical section,
//! and the guard is not dropped until the reply has been read and the rotated
//! token installed.
//!
//! That deliberately holds a lock across a network call. It is the point rather
//! than an oversight: the alternative — release the lock, refresh, take it again
//! — is exactly the double-checked pattern that produces two in-flight refreshes
//! under the three-thread startup the framework actually performs. A thread that
//! blocks here wakes up holding a *valid* token, which is what it wanted; a
//! thread that does not block here wakes up signed out.
//!
//! ## What a *failed* refresh does
//!
//! Holding the lock across the request deduplicates threads that queue behind a
//! refresh which *succeeds* — they wake to a live token and make no request.
//! That is not enough on its own. A refresh that fails leaves no live token, so
//! a re-check of "is there a token now?" is `None` for every waiter and the lock
//! has serialised N refreshes rather than deduplicating them: N requests, N
//! rotations spent, against an endpoint that is already refusing. So a waiter
//! also compares the number of *completed* attempts against the number it read
//! before it queued, and takes the failure of the attempt it waited through
//! instead of issuing its own. See `State::waited_out`.
//!
//! Two further bounds, because "the refresh failed" is not one situation:
//!
//!  * **A credential can be dead, and that has to be sayable.** The service
//!    rotates on use, so a reply that is lost in transit leaves this process
//!    holding a token the service has already retired. Every subsequent refresh
//!    answers `invalid_grant`, forever. One `invalid_grant` is not evidence of
//!    that — it is also what a service blip and a lost race look like, and
//!    discarding a good credential on one is the sign-out this module exists to
//!    prevent. [`crate::auth::MAX_REJECTIONS`] consecutive ones are evidence. At that point
//!    the credential is marked rejected: [`crate::auth::TokenCache::is_signed_in`] answers
//!    `false`, [`crate::auth::TokenCache::token`] answers [`crate::auth::AuthError::CredentialRejected`]
//!    without a request, and the caller has the one fact it needs to prompt for
//!    a new device code flow.
//!  * **A failing refresh must not be a hot loop.** `complete_device_code`
//!    bounds its polling; this bounds its retrying, with the same reasoning and
//!    the opposite mechanism, because a refresh has no natural end. The first
//!    failure costs nothing — a dropped connection must not delay the retry that
//!    fixes it — and from the second onwards the wait doubles from
//!    [`crate::auth::REFRESH_BACKOFF_STEP`] up to [`crate::auth::MAX_REFRESH_BACKOFF`]. Inside that window
//!    the stored failure is returned and no request is made.
//!
//! ## Seams
//!
//! [`crate::auth::TokenTransport`] and [`crate::auth::Clock`] mirror the crate's [`Transport`](crate::Transport)
//! and [`Sleeper`](crate::Sleeper), for the same reason: a suite that needs a
//! socket, a credential or a real seven-second poll interval is a suite nobody
//! runs. They differ from their models in taking `&self` rather than `&mut self`,
//! because this object is shared — `Arc<TokenCache>` across three threads — and a
//! `&mut` seam would need a second lock outside the first.
//!
//! [`crate::auth::TokenTransport`] is implemented by `http::GraphTokens` behind the `http`
//! feature, over the same `ureq::Agent` configuration — the same certificate
//! verification, the same root store, the same refusal to follow a redirect — as
//! the Graph transport. It is the request that carries the refresh token, so it
//! is the last one that should have been left for a caller to wire up with a
//! client of its own.
//!
//! [`crate::auth::CredentialStore`] is a third seam, and not an optional one. The service
//! rotates the refresh token on every use, so the token in memory after a
//! refresh is the only one that still works: a cache that never writes it back
//! signs the user out at the next restart just as thoroughly as a concurrent
//! refresh does, only slower.
//!
//! ## What is unverified, and why
//!
//! **Nothing in this module has ever been run against a Microsoft endpoint.**
//! There is no tenant, no app registration and no test account here, and this
//! module was not permitted to acquire one. Every response it is tested against
//! is a byte string written by hand in this file from the published protocol
//! documents. So the following are *unverified assumptions*, each of which would
//! fail in a way no test below can see:
//!
//!  * **The wire shapes.** That the device code endpoint answers with
//!    `device_code` / `user_code` / `verification_uri` / `interval` /
//!    `expires_in`, that the token endpoint answers with `access_token` /
//!    `expires_in` / `refresh_token`, and that errors arrive as
//!    `{"error":"authorization_pending", …}` with HTTP 400. Field spellings are
//!    from documentation, not observation. (`verification_url`, the v1 spelling,
//!    is accepted too, because the two endpoints disagree in public.)
//!  * **That the refusal codes are the ones sent.** `authorization_pending`,
//!    `slow_down`, `expired_token`, `access_denied` and `invalid_grant` are
//!    handled distinctly and by exact string. A service that sends
//!    `AuthorizationPending`, or nests the code under `error.code` the way Graph
//!    proper does, falls into the "some other OAuth error" arm and stops the
//!    sign-in dead.
//!  * **That rotation happens at all, and on which grants.** The single-flight
//!    design is built on the claim that a refresh token is single-use. If it is
//!    not, this module is merely more careful than it needed to be. If it is
//!    single-use in a way not modelled here — a grace window, a per-scope chain
//!    — that is not visible from here either.
//!  * **Clock skew against the service.** [`crate::auth::EXPIRY_SKEW`] is a guess at how
//!    early to refresh. Only a real endpoint can say whether it is enough.
//!  * **Throttling.** The token endpoint's own 429 behaviour is not modelled;
//!    a 429 here is just a non-2xx status.
//!  * **The URLs.** `login.microsoftonline.com/{tenant}/oauth2/v2.0/…` is
//!    composed from documentation. A wrong path is a 404 on first use — the one
//!    failure in this list that is loud.
//!
//! ## Two limits that are not about the service, and are not enforceable here
//!
//!  * **One cache, or none of this matters.** The single-flight guarantee is a
//!    property of one [`crate::auth::TokenCache`] shared between callers. Three provider
//!    instances each constructing their *own* cache over the same stored
//!    credential reproduces the exact failure this module was written to
//!    prevent, and no type here can refuse it: a constructor cannot tell that
//!    another instance exists. The wiring that builds the daemon's providers is
//!    what has to hold an `Arc` and pass clones of it, and the tests below
//!    cannot see whether it does.
//!  * **One process.** A [`std::sync::Mutex`] serialises threads, not processes. Two
//!    binaries signed into the same account through the same
//!    [`crate::auth::CredentialStore`] will spend the same single-use token, and the cure is
//!    a lock on the store rather than in memory. Not implemented, because
//!    nothing in this workspace authenticates from two processes today —
//!    stated so that the day something does, this is already written down.
//!
//! What the tests below *do* establish is everything that is a property of this
//! code rather than of the service: that one refresh happens when two threads
//! ask at once **whether it succeeds or fails**, that a rotated token replaces
//! the stored one, that a failed refresh leaves the credential intact, that a
//! credential the service keeps refusing is eventually reported as dead rather
//! than retried forever, that `slow_down` lengthens the interval, that an
//! expired device code stops the poll, and that no credential reaches a `Debug`
//! output.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::Value;

// ---------------------------------------------------------------------------
// Credentials
//
// One type carries plaintext, and it renders as a placeholder. Everything that
// is a credential is built out of it, so the redaction is written once and
// cannot be forgotten by a `#[derive(Debug)]` added later.
// ---------------------------------------------------------------------------

/// A string that must not be printed.
///
/// `Debug` prints a placeholder. There is deliberately no `Display`, no `Deref`,
/// no `AsRef<str>` and no `Into<String>`: `format!("{secret}")` does not compile,
/// which is the only form of "never logged" that survives contact with a hurried
/// afternoon.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// Module-private. The plaintext leaves this file through exactly two
    /// doors: [`AccessToken::header_value`] and
    /// [`RefreshToken::expose_for_storage`], both named so that `grep` finds
    /// every use in the workspace.
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A bearer token, good for an hour or so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessToken(Secret);

impl AccessToken {
    /// The one legitimate use: the value of an `Authorization` header.
    ///
    /// Returns a fresh `String` rather than a borrow so that the plaintext is
    /// not sitting behind a reference that outlives the header it was built for.
    pub fn header_value(&self) -> String {
        format!("Bearer {}", self.0.expose())
    }
}

/// The long-lived half, and the one that must never be spent twice.
///
/// Not `Clone`, on purpose. A `Clone` is how a second copy reaches a second
/// thread, and a second copy of a single-use credential is the `invalid_grant`
/// this module exists to prevent. The cache holds exactly one, inside a mutex,
/// and hands out nothing but borrows taken under that mutex.
#[derive(Debug, PartialEq, Eq)]
pub struct RefreshToken(Secret);

impl RefreshToken {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(Secret::new(raw))
    }

    /// The plaintext, for a [`CredentialStore`] to write down and nothing else.
    ///
    /// This is a hole in "the bytes never leave", and it is a deliberate one: a
    /// rotated token that is not written down has already signed the user out,
    /// it just takes a restart to notice. The name is long and unpleasant so
    /// that a second caller of it stands out in review.
    pub fn expose_for_storage(&self) -> &str {
        self.0.expose()
    }
}

/// What a successful token response carries.
///
/// `refresh_token` is optional because a reply that omits it is not a reply that
/// revokes ours — see [`install`].
#[derive(Debug)]
pub struct Tokens {
    access: AccessToken,
    expires_in: Duration,
    refresh: Option<RefreshToken>,
}

impl Tokens {
    pub fn access(&self) -> &AccessToken {
        &self.access
    }
    pub fn expires_in(&self) -> Duration {
        self.expires_in
    }
    pub fn rotated(&self) -> bool {
        self.refresh.is_some()
    }
}

// ---------------------------------------------------------------------------
// Errors
//
// Every variant is built from something this module chose. No response body, no
// transport message and no server-supplied free text reaches an `AuthError`,
// because an `AuthError` is the thing a caller logs.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The user has not finished signing in yet. Not a failure: keep polling.
    AuthorizationPending,
    /// Polling too fast. The interval must grow.
    SlowDown,
    /// The device code's lifetime ran out. Start a new sign-in.
    DeviceCodeExpired,
    /// The user said no, or an administrator did.
    AccessDenied,
    /// The refresh token is dead — spent, revoked, or rotated by someone else.
    /// The only cure is a new device code flow.
    ///
    /// One of these is *not* a conclusion. It is equally what a service blip and
    /// a lost race look like, so the credential is kept and the next call
    /// retries it. See [`AuthError::CredentialRejected`] for the conclusion.
    InvalidGrant,
    /// The credential is dead and this cache has stopped pretending otherwise.
    ///
    /// Reached after [`MAX_REJECTIONS`] consecutive `invalid_grant`s, which is
    /// the shape of the one unrecoverable failure this module has: the service
    /// received a refresh POST and rotated the token, and the reply never
    /// arrived. The bytes in memory are then a credential the service has
    /// already retired, and no amount of retrying changes that.
    ///
    /// This is the error that means *prompt the user*. [`TokenCache::token`]
    /// returns it without making a request, and
    /// [`TokenCache::is_signed_in`] answers `false` from the moment it is set,
    /// so a health check reports the truth rather than `true` forever against a
    /// daemon whose every request 401s.
    CredentialRejected,
    /// Some other OAuth error. `code` is sanitised: see [`sanitise_code`].
    Oauth { code: String },
    /// A reply this layer could not read as a token response.
    ///
    /// `&'static str` and not `String`, so that a response body — which on the
    /// success path *is* the credential — cannot be quoted into an error that
    /// something later prints.
    Malformed(&'static str),
    /// A non-2xx status carrying nothing this layer could name.
    HttpStatus(u16),
    /// The transport could not complete the request.
    ///
    /// The kind only. The message is dropped on purpose: a transport that put
    /// its own request body into an `io::Error` — a debug build, a retry
    /// wrapper, a proxy library — would otherwise carry the refresh token into
    /// every log line that prints this.
    Transport { kind: io::ErrorKind },
    /// No credential is held. Run the device code flow.
    SignedOut,
    /// A request was about to be sent somewhere that is not the token endpoint.
    ForeignEndpoint,
    /// The poll ran for more attempts than any real device code allows.
    PollLimit { attempts: u32 },
    /// The configuration would compose a URL this module will not send a
    /// credential to.
    BadConfig(&'static str),
}

// ---------------------------------------------------------------------------
// Configuration
//
// The tenant lands in a URL *path* and the authority in its *authority*, so both
// are validated where they are set rather than where they are joined. An
// unvalidated host is not a cosmetic problem: `format!("https://{host}/…")` with
// `host = "login.microsoftonline.com@evil.example"` posts the refresh token to
// evil.example, and every character of that string came from a config file.
// ---------------------------------------------------------------------------

/// The public cloud's identity platform.
pub const DEFAULT_AUTHORITY_HOST: &str = "login.microsoftonline.com";

/// Without this scope the service returns no refresh token at all, and the user
/// signs in again every hour. Always requested; never removable.
pub const OFFLINE_ACCESS: &str = "offline_access";

/// The grant name for RFC 8628.
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthConfig {
    client_id: String,
    tenant: String,
    authority_host: String,
    scopes: Vec<String>,
}

impl AuthConfig {
    /// A desktop client.
    ///
    /// There is no client secret here and no way to add one. A secret shipped in
    /// a binary on a user's laptop is a published secret, and the device code
    /// flow is a public-client flow precisely so that none is needed.
    pub fn public_client(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            tenant: "common".to_string(),
            authority_host: DEFAULT_AUTHORITY_HOST.to_string(),
            scopes: vec![OFFLINE_ACCESS.to_string()],
        }
    }

    pub fn with_tenant(mut self, tenant: &str) -> Result<Self, AuthError> {
        check_tenant(tenant)?;
        self.tenant = tenant.to_string();
        Ok(self)
    }

    /// For a sovereign cloud, or a test double's origin.
    pub fn with_authority_host(mut self, host: &str) -> Result<Self, AuthError> {
        check_host(host)?;
        self.authority_host = host.to_string();
        Ok(self)
    }

    /// Replaces the scope list, and re-adds [`OFFLINE_ACCESS`] whatever the
    /// caller passed.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        if !self.scopes.iter().any(|s| s == OFFLINE_ACCESS) {
            self.scopes.push(OFFLINE_ACCESS.to_string());
        }
        self
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn authority_host(&self) -> &str {
        &self.authority_host
    }

    pub fn device_code_url(&self) -> String {
        format!(
            "https://{}/{}/oauth2/v2.0/devicecode",
            self.authority_host, self.tenant
        )
    }

    pub fn token_url(&self) -> String {
        format!(
            "https://{}/{}/oauth2/v2.0/token",
            self.authority_host, self.tenant
        )
    }

    fn scope_param(&self) -> String {
        self.scopes.join(" ")
    }

    fn device_code_request(&self) -> TokenRequest {
        TokenRequest {
            grant: Grant::DeviceCode,
            url: self.device_code_url(),
            body: form(&[
                ("client_id", &self.client_id),
                ("scope", &self.scope_param()),
            ]),
        }
    }

    fn device_token_request(&self, device_code: &Secret) -> TokenRequest {
        TokenRequest {
            grant: Grant::DeviceToken,
            url: self.token_url(),
            body: form(&[
                ("client_id", &self.client_id),
                ("grant_type", DEVICE_CODE_GRANT),
                ("device_code", device_code.expose()),
            ]),
        }
    }

    /// Takes a borrow, and can therefore only be called by something already
    /// holding the cache's guard. That is the whole of the single-flight
    /// guarantee, stated as a signature.
    fn refresh_request(&self, refresh: &RefreshToken) -> TokenRequest {
        TokenRequest {
            grant: Grant::Refresh,
            url: self.token_url(),
            body: form(&[
                ("client_id", &self.client_id),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.0.expose()),
                ("scope", &self.scope_param()),
            ]),
        }
    }
}

/// A tenant is a path segment. Anything that could end the segment early, or
/// climb out of it, is refused rather than escaped.
fn check_tenant(tenant: &str) -> Result<(), AuthError> {
    if tenant.is_empty() || tenant.len() > 64 {
        return Err(AuthError::BadConfig("tenant is empty or too long"));
    }
    if tenant == "." || tenant == ".." {
        return Err(AuthError::BadConfig("tenant is a relative path"));
    }
    if !tenant
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(AuthError::BadConfig("tenant is not a bare path segment"));
    }
    Ok(())
}

/// A host is a host: labels of letters, digits and hyphens, separated by dots.
///
/// This is the check that decides where the refresh token goes. Everything a URL
/// can use to make one host look like another — a `@` making the real host into
/// userinfo, a `/` starting a path, a `:` adding a port, a `%2f`, a scheme — is
/// outside this character set and therefore refused at the moment the config is
/// built, rather than sanitised later at the moment it is joined.
fn check_host(host: &str) -> Result<(), AuthError> {
    if host.is_empty() || host.len() > 253 {
        return Err(AuthError::BadConfig("authority host is empty or too long"));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(AuthError::BadConfig("authority host has an empty label"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(AuthError::BadConfig("authority host label is malformed"));
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(AuthError::BadConfig("authority host is not a bare host"));
        }
    }
    Ok(())
}

/// Whether a URL addresses the authority we are configured for.
///
/// The same reasoning as [`crate::delta_url`]'s origin check, and the same
/// refusal to do prefix or substring arithmetic: `contains(host)` follows
/// `https://login.microsoftonline.com.evil.example/…`, and `starts_with` follows
/// `https://login.microsoftonline.com@evil.example/…`, because everything before
/// the last `@` in an authority is userinfo and the host is what follows it.
fn on_the_authority(url: &str, host: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = match authority.rsplit_once('@') {
        Some((_userinfo, h)) => h,
        None => authority,
    };
    let (found, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => (host_port, ""),
    };
    found.eq_ignore_ascii_case(host) && (port.is_empty() || port == "443")
}

// ---------------------------------------------------------------------------
// The HTTP seam
// ---------------------------------------------------------------------------

/// Which of the three requests this is. Carried so a transport, a log or a test
/// double can tell them apart without reading the body — which is where the
/// credential is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Grant {
    /// Ask for a device code.
    DeviceCode,
    /// Poll for the token that device code will eventually yield.
    DeviceToken,
    /// Spend the refresh token.
    Refresh,
}

/// One form POST to the identity platform.
///
/// Constructible only by [`AuthConfig`]'s three private builders, all of which
/// address [`AuthConfig::token_url`] or [`AuthConfig::device_code_url`]. There is
/// no public constructor, so "the refresh token is only ever sent to the token
/// endpoint" is a property of what can be built rather than of what is
/// remembered.
pub struct TokenRequest {
    grant: Grant,
    url: String,
    body: String,
}

impl TokenRequest {
    /// What every one of these must be sent as.
    pub const CONTENT_TYPE: &'static str = "application/x-www-form-urlencoded";

    pub fn grant(&self) -> Grant {
        self.grant
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The encoded body. Carries the credential — this is the value the
    /// transport writes to the socket, and the only thing that may read it is
    /// the code doing the writing.
    pub fn body(&self) -> &str {
        &self.body
    }
}

impl fmt::Debug for TokenRequest {
    /// The URL and the grant. Never the body: on a refresh it *is* the
    /// credential, and a derived `Debug` here would put it in the first log line
    /// anyone adds while chasing a 400.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant", &self.grant)
            .field("url", &self.url)
            .field("body", &"<redacted>")
            .finish()
    }
}

/// One reply, before anything reads it as a token.
pub struct TokenReply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl TokenReply {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
}

impl fmt::Debug for TokenReply {
    /// A successful body holds both tokens in plaintext, so it is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenReply")
            .field("status", &self.status)
            .field("body", &format_args!("<{} bytes redacted>", self.body.len()))
            .finish()
    }
}

/// The longest one [`TokenTransport::post`] may take before it must give up.
///
/// Not advisory, and not a nicety. [`TokenCache::token`] holds the cache's mutex
/// across this call — that is the whole single-flight guarantee — so a `post`
/// that never returns does not stall one request. It wedges *every* thread in
/// the process inside `token()`, permanently, with no timeout, no error and no
/// way back short of killing the daemon; the upload queue, the delta thread and
/// the fetch loop all stop, and the only symptom is that nothing happens.
///
/// A transport that cannot complete within this must return an error — an
/// `io::ErrorKind::TimedOut` — rather than keep waiting. The shipped
/// implementation enforces it with a whole-call timeout on its HTTP client.
///
/// [`TokenCache`] cannot *impose* it: `post` is a blocking call on a thread this
/// module does not own, and by the time control comes back the damage is done.
/// What it does instead is refuse to hide a violation — the elapsed time is
/// measured against the injected [`Clock`] and an overrun is recorded where
/// [`TokenCache::last_slow_post`] and the `Debug` output will show it.
pub const TOKEN_POST_DEADLINE: Duration = Duration::from_secs(120);

/// Where the identity platform is.
///
/// Implemented behind the crate's `http` feature by `GraphTokens`, over the same
/// client configuration as the Graph transport. It is deliberately still a seam:
/// the request built here carries the refresh token, and a suite that could only
/// exercise it by sending that token somewhere is a suite nobody runs.
///
/// `&self`, unlike [`crate::Transport`]: this seam is reached from an
/// `Arc<TokenCache>` shared between threads, and a `&mut` one would need its own
/// lock outside the cache's — which is a second lock ordering to get wrong.
///
/// # Contract
///
///  * **`post` must return within [`TOKEN_POST_DEADLINE`].** See that constant:
///    the caller is holding a mutex that every thread in the process needs.
///  * **The error must not quote the request.** On a refresh the body *is* the
///    credential; [`TokenCache`] reduces whatever comes back to its
///    [`io::ErrorKind`], but an implementation that puts the body in the message
///    has already written it wherever that error is rendered on the way here.
pub trait TokenTransport: Send + Sync {
    fn post(&self, request: &TokenRequest) -> io::Result<TokenReply>;
}

/// Time, injected so a poll interval is asserted rather than lived.
///
/// [`Clock::now`] is a reading on an arbitrary origin: only differences between
/// two readings mean anything, so the implementation may be monotonic and need
/// not be a wall clock. That is deliberate — a token lifetime measured against a
/// wall clock is a token that expires when the user changes timezone.
pub trait Clock: Send + Sync {
    fn now(&self) -> Duration;
    fn sleep(&self, how_long: Duration);
}

/// Where the rotated refresh token is written.
///
/// Both halves are fallible and neither is optional. See the module docs: the
/// service rotates on use, so the credential in memory after a refresh is the
/// only one that still works.
pub trait CredentialStore: Send + Sync {
    fn load(&self) -> io::Result<Option<RefreshToken>>;
    fn save(&self, refresh: &RefreshToken) -> io::Result<()>;
}

// Shared ownership for all three seams, so `Arc<TokenCache<Arc<T>, …>>` — the
// shape the provider instances actually need — does not require a wrapper type
// at each use site.
impl<T: TokenTransport + ?Sized> TokenTransport for Arc<T> {
    fn post(&self, request: &TokenRequest) -> io::Result<TokenReply> {
        (**self).post(request)
    }
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now(&self) -> Duration {
        (**self).now()
    }
    fn sleep(&self, how_long: Duration) {
        (**self).sleep(how_long)
    }
}

impl<S: CredentialStore + ?Sized> CredentialStore for Arc<S> {
    fn load(&self) -> io::Result<Option<RefreshToken>> {
        (**self).load()
    }
    fn save(&self, refresh: &RefreshToken) -> io::Result<()> {
        (**self).save(refresh)
    }
}

// ---------------------------------------------------------------------------
// Reading a reply
// ---------------------------------------------------------------------------

/// How early to treat an access token as spent.
///
/// A token handed out with two seconds left is a token that expires between the
/// header being written and the request being read, which is a 401 in the middle
/// of a round rather than a refresh before it.
pub const EXPIRY_SKEW: Duration = Duration::from_secs(60);

/// A ceiling on a lifetime the service reports.
///
/// An `expires_in` of a year is either a different service or a mistake, and
/// believing it means never refreshing until every request fails.
const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// RFC 8628's step when the service says `slow_down`.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// RFC 8628's default when the device code response omits `interval`.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// A ceiling on the interval the service may ask for.
///
/// A poll thread told to wait a day is a sign-in that never completes and a
/// thread that cannot be joined.
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// A ceiling on poll attempts, independent of the clock.
///
/// The device code's own deadline is the real bound; this one exists because the
/// deadline is measured with an injected clock, and a clock that does not
/// advance would otherwise turn the sign-in into a permanent request loop
/// against the endpoint most likely to start throttling.
const MAX_POLL_ATTEMPTS: u32 = 512;

/// The wait after the *second* consecutive failed refresh, and the step the
/// wait doubles from.
///
/// The first failure costs nothing on purpose. A dropped connection, a DNS
/// hiccup or a single 503 is fixed by the very next attempt, and a client that
/// makes the caller wait five seconds to find that out has turned a recovered
/// fault into a visible stall.
pub const REFRESH_BACKOFF_STEP: Duration = Duration::from_secs(5);

/// The ceiling on that wait.
///
/// A refresh has no natural end the way a device code poll does, so this is what
/// bounds the request rate of a cache whose credential is simply not working:
/// one attempt per five minutes per process, rather than one per call from every
/// thread that wants a token.
pub const MAX_REFRESH_BACKOFF: Duration = Duration::from_secs(300);

/// How many consecutive `invalid_grant`s make a credential dead rather than
/// unlucky.
///
/// One is not evidence — see [`AuthError::InvalidGrant`]. Three in a row, with
/// the backoff above between them, is not a blip: it is a credential the service
/// has retired, and continuing to present it is a loop that never terminates.
pub const MAX_REJECTIONS: u32 = 3;

/// How long to wait before the `n`th consecutive refresh attempt.
fn backoff(failures: u32) -> Duration {
    if failures < 2 {
        return Duration::ZERO;
    }
    let doublings = (failures - 2).min(16);
    REFRESH_BACKOFF_STEP
        .checked_mul(1u32 << doublings)
        .unwrap_or(MAX_REFRESH_BACKOFF)
        .min(MAX_REFRESH_BACKOFF)
}

/// Seconds, whether the service sent a number or a string.
///
/// Both spellings appear in the wild across the v1 and v2 endpoints. Neither may
/// be defaulted: `unwrap_or(0)` produces a token that is expired on arrival and
/// therefore a refresh on every single call — which is the rotation storm this
/// module exists to prevent, arrived at from the other direction.
fn seconds(v: &Value, key: &str) -> Option<Duration> {
    let raw = v.get(key)?;
    let secs = match raw {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => s.parse::<u64>().ok()?,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

fn non_empty_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// An OAuth error code, reduced to something that cannot be a credential.
///
/// RFC 6749 codes are lowercase snake case (`invalid_grant`, `slow_down`). A
/// bearer token is base64url — digits, hyphens, underscores, dots and mixed
/// case — so a server echoing one back into the `error` field survives this
/// filter as a short run of unrelated lowercase letters rather than as a
/// credential in a log file. Real codes pass through untouched.
fn sanitise_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_lowercase() || *c == '_')
        .take(40)
        .collect()
}

fn oauth_error(v: &Value) -> Option<AuthError> {
    let code = v.get("error").and_then(Value::as_str)?;
    Some(match code {
        "authorization_pending" => AuthError::AuthorizationPending,
        "slow_down" => AuthError::SlowDown,
        "expired_token" => AuthError::DeviceCodeExpired,
        "access_denied" => AuthError::AccessDenied,
        "invalid_grant" => AuthError::InvalidGrant,
        other => AuthError::Oauth {
            code: sanitise_code(other),
        },
    })
}

fn body_json(reply: &TokenReply) -> Result<Value, AuthError> {
    serde_json::from_slice(&reply.body)
        .map_err(|_| AuthError::Malformed("the reply was not JSON"))
}

/// A token response, or the named reason it is not one.
///
/// The error key is read before the status, because the identity platform
/// answers `authorization_pending` with HTTP 400 — and a status-first reader
/// turns "the user has not clicked yet" into a hard failure that ends the
/// sign-in.
fn read_token_reply(reply: &TokenReply) -> Result<Tokens, AuthError> {
    let v = body_json(reply)?;
    if let Some(e) = oauth_error(&v) {
        return Err(e);
    }
    if !(200..300).contains(&reply.status) {
        return Err(AuthError::HttpStatus(reply.status));
    }
    let Some(access) = non_empty_str(&v, "access_token") else {
        return Err(AuthError::Malformed("no access_token in the reply"));
    };
    let Some(expires_in) = seconds(&v, "expires_in") else {
        return Err(AuthError::Malformed("no usable expires_in in the reply"));
    };
    Ok(Tokens {
        access: AccessToken(Secret::new(access)),
        expires_in: expires_in.min(MAX_TOKEN_LIFETIME),
        refresh: non_empty_str(&v, "refresh_token").map(RefreshToken::new),
    })
}

// ---------------------------------------------------------------------------
// The device code flow
// ---------------------------------------------------------------------------

/// What the user has to be shown, and what the poll needs.
///
/// The service's own `message` field is deliberately *not* carried. It is a
/// server-supplied string whose only purpose is to be printed to a terminal,
/// which makes it a place to put escape sequences; and the two facts a prompt
/// actually needs — the code and where to type it — are right here.
#[derive(Debug)]
pub struct DeviceCode {
    device_code: Secret,
    user_code: String,
    verification_uri: String,
    interval: Duration,
    /// A [`Clock::now`] reading, not a lifetime.
    expires_at: Duration,
}

impl DeviceCode {
    /// Show this to the user.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }
    /// And send them here.
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }
    pub fn interval(&self) -> Duration {
        self.interval
    }
    pub fn expires_at(&self) -> Duration {
        self.expires_at
    }
}

/// Refuse anything that would be printed to a terminal and is not text.
///
/// A user code is meant to be read aloud and typed. A control character in one
/// is either a different protocol or an attempt to write on the terminal of
/// whoever is signing in.
fn printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && !s.chars().any(|c| c.is_control())
}

fn read_device_code(reply: &TokenReply, now: Duration) -> Result<DeviceCode, AuthError> {
    let v = body_json(reply)?;
    if let Some(e) = oauth_error(&v) {
        return Err(e);
    }
    if !(200..300).contains(&reply.status) {
        return Err(AuthError::HttpStatus(reply.status));
    }
    let Some(device_code) = non_empty_str(&v, "device_code") else {
        return Err(AuthError::Malformed("no device_code in the reply"));
    };
    let Some(user_code) = non_empty_str(&v, "user_code") else {
        return Err(AuthError::Malformed("no user_code in the reply"));
    };
    // The two endpoints disagree in public about the spelling, so both are read
    // and the v2 one wins.
    let uri = non_empty_str(&v, "verification_uri")
        .or_else(|| non_empty_str(&v, "verification_url"));
    let Some(uri) = uri else {
        return Err(AuthError::Malformed("no verification_uri in the reply"));
    };
    if !printable(user_code, 64) {
        return Err(AuthError::Malformed("the user_code is not printable text"));
    }
    if !printable(uri, 512) || !uri.starts_with("https://") {
        return Err(AuthError::Malformed(
            "the verification_uri is not a printable https URL",
        ));
    }
    let Some(expires_in) = seconds(&v, "expires_in") else {
        return Err(AuthError::Malformed("no usable expires_in in the reply"));
    };
    let interval = seconds(&v, "interval")
        .unwrap_or(DEFAULT_POLL_INTERVAL)
        .clamp(DEFAULT_POLL_INTERVAL, MAX_POLL_INTERVAL);
    Ok(DeviceCode {
        device_code: Secret::new(device_code),
        user_code: user_code.to_string(),
        verification_uri: uri.to_string(),
        interval,
        expires_at: now.saturating_add(expires_in.min(MAX_TOKEN_LIFETIME)),
    })
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

/// Everything mutable, behind one lock.
///
/// One lock and not two. Separate locks for "the access token" and "the refresh
/// token" would let a thread read a stale access token while another rotated the
/// credential underneath it, which is the same race in a costume.
#[derive(Debug, Default)]
struct State {
    access: Option<AccessToken>,
    /// A [`Clock::now`] reading past which `access` must not be handed out.
    expires_at: Duration,
    refresh: Option<RefreshToken>,
    refreshes: u64,
    store_error: Option<io::ErrorKind>,
    /// Consecutive failed refresh attempts of any kind. Drives the backoff.
    failures: u32,
    /// Consecutive `invalid_grant`s specifically. Drives the death sentence —
    /// and it is a *separate* count on purpose: an outage is not evidence that
    /// the credential is wrong, and counting the two together would sign the
    /// user out for a bad afternoon on the network.
    rejections: u32,
    /// The service has refused this credential [`MAX_REJECTIONS`] times running.
    rejected: bool,
    /// A [`Clock::now`] reading before which no new attempt may be made.
    next_attempt_at: Duration,
    /// How the most recent attempt failed, and which attempt that was.
    last_failure: Option<Failure>,
}

/// One failed refresh, tagged with the attempt number it belongs to.
#[derive(Debug)]
struct Failure {
    /// The value [`TokenCache::attempts`] took *after* this attempt finished.
    attempt: u64,
    error: AuthError,
}

impl State {
    fn live(&self, now: Duration) -> Option<AccessToken> {
        let access = self.access.as_ref()?;
        if now.saturating_add(EXPIRY_SKEW) < self.expires_at {
            Some(access.clone())
        } else {
            None
        }
    }

    /// The answer for a caller that was already queued for the lock when the
    /// attempt recorded here finished.
    ///
    /// This is the half of single-flight that holding the lock does not buy.
    /// A refresh that *succeeds* deduplicates its waiters for free — they wake
    /// up, find a live token and return it. A refresh that *fails* leaves
    /// nothing behind, so every waiter's re-check says "still no token" and
    /// each in turn spends a rotation against a service that is already
    /// refusing. `arrived` is read before queueing, so
    /// `failure.attempt > arrived` is exactly "an attempt began and finished
    /// while I was waiting", and its answer is my answer.
    fn waited_out(&self, arrived: u64) -> Option<AuthError> {
        let failure = self.last_failure.as_ref()?;
        (failure.attempt > arrived).then(|| failure.error.clone())
    }

    fn clear_failures(&mut self) {
        self.failures = 0;
        self.rejections = 0;
        self.rejected = false;
        self.next_attempt_at = Duration::ZERO;
        self.last_failure = None;
    }
}

/// The facts a health check reads, mirrored out from under the refresh lock.
///
/// Not a second source of truth and not a second lock ordering to get wrong.
/// `State`'s mutex is *deliberately* held across the network call, so an
/// accessor that took it would block a `/healthz` handler for as long as the
/// token endpoint feels like taking — which is the one thing a liveness check
/// must never do, and it is worst precisely when it matters most. So the
/// answers are republished here by [`TokenCache::publish`] at the end of every
/// path that changes one.
///
/// The order is `state` then `observed`, never the reverse, and `observed` is
/// never held across anything that can block — a field assignment and nothing
/// else. That is what makes it a leaf rather than a deadlock waiting to happen.
#[derive(Clone, Copy, Debug, Default)]
struct Observed {
    refreshes: u64,
    signed_in: bool,
    store_error: Option<io::ErrorKind>,
    /// The last [`TokenTransport::post`] that broke [`TOKEN_POST_DEADLINE`].
    slow_post: Option<Duration>,
}

/// Install a token response. Reports whether the credential rotated.
///
/// A reply that carries no `refresh_token` keeps the one already held. The
/// tempting `state.refresh = tokens.refresh` is a one-word difference and it
/// signs the user out on the first reply that happens to omit the field: there
/// is then no credential to refresh with, and nothing on disk to fall back to
/// either, because the same assignment would have been persisted.
fn install(state: &mut State, tokens: Tokens, now: Duration) -> (AccessToken, bool) {
    let Tokens {
        access,
        expires_in,
        refresh,
    } = tokens;
    state.access = Some(access.clone());
    state.expires_at = now.saturating_add(expires_in);
    let rotated = match refresh {
        Some(new) => {
            let changed = state.refresh.as_ref() != Some(&new);
            state.refresh = Some(new);
            changed
        }
        None => false,
    };
    (access, rotated)
}

/// The shared token cache. One per machine, wrapped in an [`Arc`] and handed to
/// every provider instance.
///
/// This is the shared cache that `docs/GRAPH-GROUNDWORK.md` §2 puts *behind*
/// the `PageSource` implementation: `http::GraphHttp` holds an
/// `Arc<TokenCache<…>>` as its `TokenSource`, so the mapping layer above it has
/// no concept of a credential at all.
pub struct TokenCache<T: TokenTransport, C: Clock, S: CredentialStore> {
    config: AuthConfig,
    transport: T,
    clock: C,
    store: S,
    state: Mutex<State>,
    /// Refresh attempts that have *finished*, successfully or not.
    ///
    /// Outside the mutex, because its whole job is to be readable by a thread
    /// that has not got the lock yet — see [`State::waited_out`]. Incremented
    /// after the request returns rather than before it is sent, so a thread
    /// that reads it while an attempt is in flight reads the value from before
    /// that attempt, and therefore recognises the attempt's failure as one it
    /// waited through.
    attempts: AtomicU64,
    observed: Mutex<Observed>,
}

impl<T: TokenTransport, C: Clock, S: CredentialStore> TokenCache<T, C, S> {
    pub fn new(config: AuthConfig, transport: T, clock: C, store: S) -> Self {
        Self {
            config,
            transport,
            clock,
            store,
            state: Mutex::new(State::default()),
            attempts: AtomicU64::new(0),
            observed: Mutex::new(Observed::default()),
        }
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// The guard, poisoning ignored.
    ///
    /// A panic inside the critical section leaves the state exactly as it was —
    /// every field is assigned after the reply has been read, so there is no
    /// half-installed credential to protect anyone from. Propagating the poison
    /// instead would turn one panic into a permanently signed-out daemon, which
    /// is a worse answer to a fault that has already been survived.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The observability mirror's guard. Same poisoning rule, and the same
    /// reasoning: there is nothing half-written behind it to protect anyone
    /// from.
    fn observed(&self) -> MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Republish what a health check may read. Called with the state guard
    /// held, at the end of every path that changes one of these.
    fn publish(&self, state: &State) {
        let mut observed = self.observed();
        observed.refreshes = state.refreshes;
        observed.signed_in = state.refresh.is_some() && !state.rejected;
        observed.store_error = state.store_error;
    }

    /// A valid access token, refreshing if necessary — and refreshing **once**
    /// however many threads ask at the same moment.
    ///
    /// The guard is taken before the cache is read and is not released until any
    /// refresh has finished. A second thread arriving mid-refresh blocks here,
    /// and when it wakes the token it wanted is already installed, so it makes
    /// no request at all. That is the whole mechanism; there is no flag to
    /// forget to set and no window between the check and the spend.
    ///
    /// And when the refresh it waited through *failed*, the woken thread takes
    /// that failure rather than issuing its own request — the lock alone
    /// serialises those, it does not deduplicate them. See `State::waited_out`,
    /// and note that `attempts` is read here, before the queue, because after
    /// the queue it is indistinguishable from the value this thread's own
    /// attempt would produce.
    pub fn token(&self) -> Result<AccessToken, AuthError> {
        let arrived = self.attempts.load(Ordering::SeqCst);
        let mut state = self.state();
        if let Some(live) = state.live(self.clock.now()) {
            return Ok(live);
        }
        if let Some(failure) = state.waited_out(arrived) {
            return Err(failure);
        }
        self.refresh_holding(&mut state)
    }

    /// Replace a token the service has rejected.
    ///
    /// For the one case the expiry clock cannot see: a 401 against a token this
    /// cache still believes in — a revoked session, a changed password, a clock
    /// further out than [`EXPIRY_SKEW`] covers.
    ///
    /// It takes the token that failed rather than being a bare `refresh()`,
    /// because three provider instances share this cache and a 401 does not
    /// arrive at one of them. All three fail on the *same* token within a few
    /// milliseconds, and a bare force-refresh would spend three rotations to fix
    /// one problem — which is the rotation storm again, triggered by the very
    /// error it is trying to recover from. Naming the failed token makes the
    /// second and third calls into no-ops: whoever gets the lock first refreshes,
    /// and the others find a token that is no longer the one they were rejected
    /// for and take it.
    pub fn refresh_if_stale(&self, stale: &AccessToken) -> Result<AccessToken, AuthError> {
        let arrived = self.attempts.load(Ordering::SeqCst);
        let mut state = self.state();
        if let Some(current) = state.access.as_ref() {
            if current != stale {
                return Ok(current.clone());
            }
        }
        if let Some(failure) = state.waited_out(arrived) {
            return Err(failure);
        }
        self.refresh_holding(&mut state)
    }

    /// Requires the guard, by signature. Nothing else can spend the credential.
    fn refresh_holding(&self, state: &mut State) -> Result<AccessToken, AuthError> {
        if state.rejected {
            // No request, ever again, until somebody signs in. The alternative
            // is every thread in the process presenting a retired credential to
            // `login.microsoftonline.com` for as long as the daemon runs.
            return Err(AuthError::CredentialRejected);
        }
        let now = self.clock.now();
        if now < state.next_attempt_at {
            // Inside the backoff window. The stored failure is the honest
            // answer: it is what the last attempt was told, and re-asking
            // sooner is what the window exists to prevent.
            return Err(state
                .last_failure
                .as_ref()
                .map(|f| f.error.clone())
                .unwrap_or(AuthError::SignedOut));
        }
        let Some(refresh) = state.refresh.as_ref() else {
            // No credential, so no request: posting `refresh_token=` here would
            // be a well-formed grant for the empty string, which is a 400 the
            // service counts against the app registration rather than against
            // this user.
            return Err(AuthError::SignedOut);
        };
        let request = self.config.refresh_request(refresh);
        let outcome = self
            .post(&request)
            .and_then(|reply| read_token_reply(&reply));
        // After the request, not before it: a waiter reads this counter before
        // it queues, and the whole point is that an attempt in flight has not
        // yet bumped it.
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;

        // Every failure path leaves `state.refresh` exactly as it was. The
        // service saying no is not evidence that the bytes we hold are the
        // wrong bytes — an outage says the same thing — and clearing them turns
        // a five-minute service fault into a mandatory re-sign-in on every
        // machine the user owns. What *is* recorded is that it failed, so that
        // the failure can be deduplicated, backed off, and — once the service
        // has said `invalid_grant` enough times to have meant it — reported.
        let tokens = match outcome {
            Ok(tokens) => tokens,
            Err(e) => {
                self.note_failure(state, attempt, e.clone(), now);
                return Err(e);
            }
        };
        let (access, rotated) = install(state, tokens, self.clock.now());
        state.refreshes += 1;
        state.clear_failures();
        if rotated {
            self.persist(state);
        }
        self.publish(state);
        Ok(access)
    }

    /// Record a failed attempt: the backoff, the death count, and the answer
    /// waiters will be given.
    fn note_failure(&self, state: &mut State, attempt: u64, error: AuthError, now: Duration) {
        state.failures = state.failures.saturating_add(1);
        if error == AuthError::InvalidGrant {
            state.rejections = state.rejections.saturating_add(1);
            state.rejected = state.rejections >= MAX_REJECTIONS;
        } else {
            // Not consecutive any more. A transport failure between two
            // `invalid_grant`s is not a third strike, and treating it as one
            // would sign the user out over a flaky link.
            state.rejections = 0;
        }
        state.next_attempt_at = now.saturating_add(backoff(state.failures));
        state.last_failure = Some(Failure { attempt, error });
        self.publish(state);
    }

    fn post(&self, request: &TokenRequest) -> Result<TokenReply, AuthError> {
        // Belt on top of the braces: `TokenRequest` has no public constructor,
        // so every URL here was composed from a validated host. The check costs
        // a string comparison and closes the hole that a fourth request builder,
        // added later by someone who has not read this file, would open.
        if !on_the_authority(request.url(), &self.config.authority_host) {
            return Err(AuthError::ForeignEndpoint);
        }
        let started = self.clock.now();
        let out = self.transport.post(request);
        let took = self.clock.now().saturating_sub(started);
        if took > TOKEN_POST_DEADLINE {
            // Nothing here can cancel a call that has already returned, and
            // nothing here could have cancelled it while it was outstanding
            // either — see [`TOKEN_POST_DEADLINE`]. What this can do is stop the
            // violation being invisible: a transport that parks every thread in
            // the process for ten minutes should not look like a slow network.
            self.observed().slow_post = Some(took);
        }
        out.map_err(|e| AuthError::Transport { kind: e.kind() })
    }

    /// Write the credential down. A failure is recorded, never returned.
    ///
    /// The refresh already succeeded and the access token in hand is good for an
    /// hour. Failing the call because the disk is full would convert a problem
    /// that costs one re-sign-in at the next restart into an immediate sync
    /// outage — while silently ignoring it would let the same restart fail with
    /// nothing anywhere to explain why. So it is remembered and readable.
    fn persist(&self, state: &mut State) {
        let Some(refresh) = state.refresh.as_ref() else {
            return;
        };
        state.store_error = match self.store.save(refresh) {
            Ok(()) => None,
            Err(e) => Some(e.kind()),
        };
    }

    /// Adopt a credential obtained elsewhere.
    pub fn sign_in_with(&self, refresh: RefreshToken) {
        let mut state = self.state();
        // A new credential invalidates any access token minted from the old one.
        state.access = None;
        state.expires_at = Duration::ZERO;
        state.refresh = Some(refresh);
        // And it clears the record of the old one's failures, including a death
        // sentence: these are *different bytes*, and refusing to try them
        // because their predecessor was refused is the sign-out again, arrived
        // at from the cure.
        state.clear_failures();
        self.publish(&state);
    }

    /// Load the stored credential. `Ok(false)` means there was none.
    ///
    /// The store's own error message is dropped and only its [`io::ErrorKind`]
    /// kept — the same rule as [`AuthError::Transport`] and `TokenCache::persist`,
    /// and for the same reason. A `CredentialStore` is the one seam whose whole
    /// subject is the credential, so a store that says what it failed on ("could
    /// not parse `1//0eXy…` at line 1") is a store that has written the refresh
    /// token into whatever logs the `io::Error` this returns.
    pub fn resume(&self) -> io::Result<bool> {
        let loaded = self
            .store
            .load()
            .map_err(|e| io::Error::new(e.kind(), "the stored credential could not be read"))?;
        let Some(refresh) = loaded else {
            return Ok(false);
        };
        self.sign_in_with(refresh);
        Ok(true)
    }

    /// Ask for a device code. Show the user what comes back, then call
    /// [`TokenCache::complete_device_code`].
    pub fn begin_device_code(&self) -> Result<DeviceCode, AuthError> {
        let request = self.config.device_code_request();
        let reply = self.post(&request)?;
        read_device_code(&reply, self.clock.now())
    }

    /// Poll until the user finishes, refuses, or runs out of time.
    ///
    /// Four service answers are distinguished, because collapsing any two of
    /// them breaks the flow in a different way:
    ///
    ///  * `authorization_pending` — the user has not finished. Keep going. Read
    ///    as a failure, every sign-in fails on its first poll.
    ///  * `slow_down` — we are polling too fast. Lengthen the interval *and*
    ///    keep going. Read as pending, the interval never grows and the app
    ///    registration is what gets throttled, so the penalty lands on every
    ///    user of this client rather than on this one.
    ///  * `expired_token` — the code is dead. Stop. Read as pending, the poll
    ///    runs forever against an endpoint that will never say yes.
    ///  * `access_denied` — the user said no. Stop, and do not retry: retrying
    ///    is a prompt the user already refused, sent again.
    pub fn complete_device_code(&self, code: &DeviceCode) -> Result<(), AuthError> {
        let mut interval = code.interval;
        for _ in 0..MAX_POLL_ATTEMPTS {
            // Before the first request as well as between them: RFC 8628 says
            // the client waits the interval, and a client that polls the instant
            // it has a code has spent a request on a user who has not yet
            // finished reading the code to themselves.
            self.clock.sleep(interval);
            if self.clock.now() >= code.expires_at {
                // The service is not the only thing that knows the code is dead,
                // and it is not the thing this loop can rely on: a service that
                // keeps answering `authorization_pending` past the deadline
                // would otherwise be polled forever.
                return Err(AuthError::DeviceCodeExpired);
            }
            let request = self.config.device_token_request(&code.device_code);
            let reply = self.post(&request)?;
            match read_token_reply(&reply) {
                Ok(tokens) => {
                    let mut state = self.state();
                    let (_, rotated) = install(&mut state, tokens, self.clock.now());
                    // A completed device code flow is the cure for a rejected
                    // credential, so it is also what lifts the sentence.
                    state.clear_failures();
                    if rotated {
                        self.persist(&mut state);
                    }
                    self.publish(&state);
                    return Ok(());
                }
                Err(AuthError::AuthorizationPending) => continue,
                Err(AuthError::SlowDown) => {
                    interval = interval.saturating_add(SLOW_DOWN_STEP).min(MAX_POLL_INTERVAL);
                    continue;
                }
                Err(other) => return Err(other),
            }
        }
        Err(AuthError::PollLimit {
            attempts: MAX_POLL_ATTEMPTS,
        })
    }

    // --- observability -----------------------------------------------------
    //
    // None of these touches `state`. `state`'s lock is held across the refresh
    // request by design, so an accessor that took it would make a health check
    // block for the transport's full duration — a `/healthz` that hangs for a
    // minute because the token endpoint is slow reads, to everything watching
    // it, as a daemon that has died. They read the mirror instead: see
    // [`Observed`], and `Debug` below, which has always refused to take the
    // refresh lock for exactly this reason.

    /// How many refreshes this cache has performed. The number the concurrency
    /// tests assert on, and the number worth putting in a metric.
    pub fn refreshes(&self) -> u64 {
        self.observed().refreshes
    }

    /// Whether a usable credential is held.
    ///
    /// `false` once the service has refused the stored one [`MAX_REJECTIONS`]
    /// times running. The bytes are still in memory at that point — nothing
    /// discards them — but answering `true` for them would be a lie that costs
    /// the user a daemon which reports itself healthy while every request 401s.
    pub fn is_signed_in(&self) -> bool {
        self.observed().signed_in
    }

    /// The last failure to write the credential down, if it has not since
    /// succeeded.
    pub fn last_store_error(&self) -> Option<io::ErrorKind> {
        self.observed().store_error
    }

    /// The last [`TokenTransport::post`] that overran [`TOKEN_POST_DEADLINE`],
    /// and by how much it overran.
    ///
    /// `Some` here means a transport is holding the cache's lock — and with it
    /// every thread that wants a token — for longer than it promised. It is a
    /// bug in the transport, and this is the only place it is visible.
    pub fn last_slow_post(&self) -> Option<Duration> {
        self.observed().slow_post
    }
}

impl<T: TokenTransport, C: Clock, S: CredentialStore> fmt::Debug for TokenCache<T, C, S> {
    /// `try_lock`, because this is the type most likely to be `dbg!`ed from
    /// inside the critical section it locks — which with `lock()` is a deadlock
    /// in the debugger rather than an answer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("TokenCache");
        out.field("authority", &self.config.authority_host);
        // The mirror, which is never held across anything, so these four are
        // always answerable — including from inside the refresh this is most
        // likely to be printed from.
        let observed = *self.observed();
        out.field("signed_in", &observed.signed_in)
            .field("refreshes", &observed.refreshes)
            .field("store_error", &observed.store_error)
            .field("slow_post", &observed.slow_post);
        match self.state.try_lock() {
            Ok(state) => out
                .field("has_access_token", &state.access.is_some())
                .field("expires_at", &state.expires_at)
                .field("failures", &state.failures)
                .field("rejected", &state.rejected)
                .field("next_attempt_at", &state.next_attempt_at),
            Err(_) => out.field("state", &"<locked>"),
        };
        out.finish()
    }
}

// ---------------------------------------------------------------------------
// Form encoding
// ---------------------------------------------------------------------------

/// `application/x-www-form-urlencoded`, by the book.
///
/// Space becomes `+` and everything outside the unreserved set becomes `%XX`,
/// including `+` itself — which matters, because base64 credentials contain them
/// and a `+` sent raw is decoded by the service as a space, turning a valid
/// refresh token into an invalid one that looks like a revocation.
fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        escape_into(&mut out, k);
        out.push('=');
        escape_into(&mut out, v);
    }
    out
}

fn escape_into(out: &mut String, raw: &str) {
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
//
// Inline rather than in `tests/`, because half of what has to be proved is about
// what is *not* reachable from outside this module: an integration test cannot
// tell a redacted `Debug` from a type that simply has no public accessor, and it
// cannot call `refresh_request` to check what the credential is spent on.
//
// Three construction rules, inherited from `tests/discover.rs` and paid for by
// the same critiques:
//
//   * **The wrong branch is scripted to succeed.** The second refresh in the
//     concurrency test returns a well-formed token response — it is the *third*
//     scripted reply, `invalid_grant`, that a racing implementation reaches. A
//     test that passes because the bad path errored for an unrelated reason is
//     a test that passes for the wrong reason.
//   * **Every refusal has a positive control.** "Never refresh", "never poll"
//     and "refuse every reply" satisfy whole classes of these tests while
//     shipping a client that cannot sign in.
//   * **Nothing sleeps and nothing touches a socket**, with one stated
//     exception: the concurrency test's transport really does block for a few
//     milliseconds, because a race window that exists only in the injected clock
//     is not a race window at all.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};

    const CLIENT: &str = "11111111-2222-3333-4444-555555555555";

    // --- the doubles -------------------------------------------------------

    /// Everything the seams did, in the order they did it.
    ///
    /// The interleaving is the assertion in the poll tests: "slept 5s then
    /// posted" and "posted then slept 5s" are different clients, and only one of
    /// them respects an interval.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Ev {
        Slept(Duration),
        Posted(Grant),
    }

    #[derive(Default)]
    struct Journal(Mutex<Vec<Ev>>);

    impl Journal {
        fn push(&self, e: Ev) {
            self.0.lock().expect("journal").push(e);
        }
        fn events(&self) -> Vec<Ev> {
            self.0.lock().expect("journal").clone()
        }
        fn sleeps(&self) -> Vec<Duration> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    Ev::Slept(d) => Some(d),
                    _ => None,
                })
                .collect()
        }
        fn posts(&self) -> usize {
            self.events()
                .iter()
                .filter(|e| matches!(e, Ev::Posted(_)))
                .count()
        }
    }

    /// A clock that only moves when something sleeps. Every test below is
    /// therefore instantaneous and deterministic.
    struct TestClock {
        journal: Arc<Journal>,
        now: Mutex<Duration>,
    }

    impl TestClock {
        fn new(journal: Arc<Journal>) -> Self {
            Self {
                journal,
                now: Mutex::new(Duration::ZERO),
            }
        }
        fn advance(&self, by: Duration) {
            let mut now = self.now.lock().expect("clock");
            *now = now.saturating_add(by);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Duration {
            *self.now.lock().expect("clock")
        }
        fn sleep(&self, how_long: Duration) {
            self.journal.push(Ev::Slept(how_long));
            self.advance(how_long);
        }
    }

    /// A clock that reports the same instant forever. A broken monotonic source,
    /// or a suspended VM.
    struct FrozenClock(Arc<Journal>);

    impl Clock for FrozenClock {
        fn now(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&self, how_long: Duration) {
            self.0.push(Ev::Slept(how_long));
        }
    }

    /// A place to stop a request in the middle of the wire.
    ///
    /// The concurrency test needs one thread to be *provably* inside the network
    /// call while another asks for a token. Sleeps cannot establish that — they
    /// make it likely, which is how a concurrency test comes to pass against an
    /// implementation that races. So the transport blocks here until the test
    /// releases it, and the test asserts about the world while it is stopped.
    #[derive(Default)]
    struct Gate {
        state: Mutex<GateState>,
        cv: std::sync::Condvar,
    }

    #[derive(Default)]
    struct GateState {
        entered: u32,
        released: bool,
    }

    impl Gate {
        /// Called from inside the transport. Blocks until [`Gate::release`].
        fn enter(&self) {
            let mut state = self.state.lock().expect("gate");
            state.entered += 1;
            self.cv.notify_all();
            while !state.released {
                let (next, timeout) = self
                    .cv
                    .wait_timeout(state, Duration::from_secs(10))
                    .expect("gate");
                state = next;
                if timeout.timed_out() {
                    // Never wedge the suite on a bug in the thing under test.
                    break;
                }
            }
        }

        fn wait_for_entry(&self, n: u32) {
            let mut state = self.state.lock().expect("gate");
            while state.entered < n {
                let (next, timeout) = self
                    .cv
                    .wait_timeout(state, Duration::from_secs(10))
                    .expect("gate");
                state = next;
                assert!(!timeout.timed_out(), "no request arrived at the transport");
            }
        }

        fn entered(&self) -> u32 {
            self.state.lock().expect("gate").entered
        }

        fn release(&self) {
            let mut state = self.state.lock().expect("gate");
            state.released = true;
            self.cv.notify_all();
        }
    }

    /// Scripted replies, plus the requests that fetched them.
    struct Script {
        journal: Arc<Journal>,
        replies: Mutex<VecDeque<io::Result<TokenReply>>>,
        /// Served once the queue empties, so a poll loop can be driven forever.
        repeating: Mutex<Option<String>>,
        /// `(grant, url, body)`. The body holds the credential, which is exactly
        /// what several tests are about.
        seen: Mutex<Vec<(Grant, String, String)>>,
        in_flight: AtomicU32,
        max_in_flight: AtomicU32,
        /// Where a request stops, when the test wants it stopped.
        gate: Mutex<Option<Arc<Gate>>>,
    }

    impl Script {
        fn new(journal: Arc<Journal>, replies: Vec<io::Result<TokenReply>>) -> Arc<Self> {
            Arc::new(Self {
                journal,
                replies: Mutex::new(replies.into_iter().collect()),
                repeating: Mutex::new(None),
                seen: Mutex::new(Vec::new()),
                in_flight: AtomicU32::new(0),
                max_in_flight: AtomicU32::new(0),
                gate: Mutex::new(None),
            })
        }

        /// Served once the scripted queue empties.
        fn repeating(self: Arc<Self>, body: &str) -> Arc<Self> {
            *self.repeating.lock().expect("script") = Some(body.to_string());
            self
        }

        /// Stop every request until the test says otherwise.
        fn gated(self: Arc<Self>, gate: Arc<Gate>) -> Arc<Self> {
            *self.gate.lock().expect("script") = Some(gate);
            self
        }

        fn seen(&self) -> Vec<(Grant, String, String)> {
            self.seen.lock().expect("script").clone()
        }

        fn remaining(&self) -> usize {
            self.replies.lock().expect("script").len()
        }

        fn max_in_flight(&self) -> u32 {
            self.max_in_flight.load(Ordering::SeqCst)
        }
    }

    impl TokenTransport for Script {
        fn post(&self, request: &TokenRequest) -> io::Result<TokenReply> {
            self.journal.push(Ev::Posted(request.grant()));
            self.seen.lock().expect("script").push((
                request.grant(),
                request.url().to_string(),
                request.body().to_string(),
            ));

            let live = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(live, Ordering::SeqCst);
            let gate = self.gate.lock().expect("script").clone();
            if let Some(gate) = gate {
                gate.enter();
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);

            let next = self.replies.lock().expect("script").pop_front();
            match next {
                Some(r) => r,
                None => match self.repeating.lock().expect("script").clone() {
                    Some(body) => Ok(TokenReply::new(400, body.into_bytes())),
                    None => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "the script ran out of replies",
                    )),
                },
            }
        }
    }

    /// A transport that takes longer than [`TOKEN_POST_DEADLINE`] allows.
    ///
    /// The overrun is spent on the injected clock rather than on the wall, so
    /// this test is instantaneous and a real ten-minute stall is what it
    /// describes.
    struct SlowTransport {
        clock: Arc<TestClock>,
        took: Duration,
    }

    impl TokenTransport for SlowTransport {
        fn post(&self, _request: &TokenRequest) -> io::Result<TokenReply> {
            self.clock.advance(self.took);
            Err(io::Error::new(io::ErrorKind::TimedOut, "still going"))
        }
    }

    /// A credential store in memory, with a switch for making it fail.
    #[derive(Default)]
    struct MemStore {
        saved: Mutex<Vec<String>>,
        seeded: Mutex<Option<String>>,
        fail: Mutex<bool>,
        /// What `load` should fail with, message included — the point of
        /// several tests being that the message must not survive.
        load_error: Mutex<Option<(io::ErrorKind, String)>>,
    }

    impl MemStore {
        fn seeded(with: &str) -> Arc<Self> {
            let s = Arc::new(Self::default());
            *s.seeded.lock().expect("store") = Some(with.to_string());
            s
        }
        fn saved(&self) -> Vec<String> {
            self.saved.lock().expect("store").clone()
        }
        fn failing(&self) {
            *self.fail.lock().expect("store") = true;
        }
        fn failing_load(&self, kind: io::ErrorKind, message: &str) {
            *self.load_error.lock().expect("store") = Some((kind, message.to_string()));
        }
    }

    impl CredentialStore for MemStore {
        fn load(&self) -> io::Result<Option<RefreshToken>> {
            if let Some((kind, message)) = self.load_error.lock().expect("store").clone() {
                return Err(io::Error::new(kind, message));
            }
            Ok(self
                .seeded
                .lock()
                .expect("store")
                .clone()
                .map(RefreshToken::new))
        }
        fn save(&self, refresh: &RefreshToken) -> io::Result<()> {
            if *self.fail.lock().expect("store") {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "read only"));
            }
            self.saved
                .lock()
                .expect("store")
                .push(refresh.expose_for_storage().to_string());
            Ok(())
        }
    }

    // --- bodies ------------------------------------------------------------

    fn ok_tokens(access: &str, refresh: &str, expires_in: u64) -> io::Result<TokenReply> {
        Ok(TokenReply::new(
            200,
            format!(
                r#"{{"token_type":"Bearer","scope":"Files.ReadWrite.All offline_access",
                     "expires_in":{expires_in},"access_token":"{access}",
                     "refresh_token":"{refresh}"}}"#
            )
            .into_bytes(),
        ))
    }

    fn oauth(code: &str) -> io::Result<TokenReply> {
        Ok(TokenReply::new(
            400,
            format!(
                r#"{{"error":"{code}","error_description":"AADSTS70016: pending","error_codes":[70016]}}"#
            )
            .into_bytes(),
        ))
    }

    fn device_code_body(interval: u64, expires_in: u64) -> io::Result<TokenReply> {
        Ok(TokenReply::new(
            200,
            format!(
                r#"{{"device_code":"DEV-SECRET","user_code":"FJKR2N9P",
                     "verification_uri":"https://microsoft.com/devicelogin",
                     "expires_in":{expires_in},"interval":{interval},
                     "message":"To sign in, use a web browser..."}}"#
            )
            .into_bytes(),
        ))
    }

    // --- the rig -----------------------------------------------------------

    type Cache = TokenCache<Arc<Script>, Arc<TestClock>, Arc<MemStore>>;

    struct Rig {
        journal: Arc<Journal>,
        script: Arc<Script>,
        store: Arc<MemStore>,
        clock: Arc<TestClock>,
    }

    impl Rig {
        fn new(replies: Vec<io::Result<TokenReply>>) -> Self {
            Self::with_store(replies, Arc::new(MemStore::default()))
        }

        fn with_store(replies: Vec<io::Result<TokenReply>>, store: Arc<MemStore>) -> Self {
            let journal = Arc::new(Journal::default());
            let script = Script::new(Arc::clone(&journal), replies);
            let clock = Arc::new(TestClock::new(Arc::clone(&journal)));
            Self {
                journal,
                script,
                store,
                clock,
            }
        }

        fn cache(&self) -> Cache {
            TokenCache::new(
                AuthConfig::public_client(CLIENT),
                Arc::clone(&self.script),
                Arc::clone(&self.clock),
                Arc::clone(&self.store),
            )
        }

        /// A cache already holding a credential, with no access token.
        fn signed_in(&self, refresh: &str) -> Cache {
            let cache = self.cache();
            cache.sign_in_with(RefreshToken::new(refresh));
            cache
        }
    }

    fn bodies_of(script: &Script, grant: Grant) -> Vec<String> {
        script
            .seen()
            .into_iter()
            .filter(|(g, _, _)| *g == grant)
            .map(|(_, _, b)| b)
            .collect()
    }

    // =======================================================================
    // Single-flight refresh
    // =======================================================================

    /// THE test this module exists for. `PROVIDER.md:224-229`: three provider
    /// instances on three threads, a refresh token the service rotates on use.
    ///
    /// Catches every implementation that lets a second thread reach the token
    /// endpoint while the first one's refresh is in flight — the double-checked
    /// shape, the `refreshing: bool` shape, and the lock-free shape. All of them
    /// spend a single-use credential twice, which is an `invalid_grant` and a
    /// signed-out user on every machine the account is on.
    ///
    /// **The timing is not left to chance**, because a concurrency test that
    /// relies on two threads happening to interleave is a test that passes
    /// against a racing implementation most of the time — and only most of the
    /// time is how this defect ships. So the transport *stops* mid-request, and
    /// the assertions are made while it is stopped:
    ///
    ///  * with the first refresh provably in flight, the cache's lock is held.
    ///    An implementation that releases it around the network call fails here
    ///    and fails every time;
    ///  * a second thread asking during that window reaches the transport zero
    ///    times;
    ///  * and when both are let go, they return the *same new* token, so a
    ///    correct-but-useless implementation that serialises and then hands the
    ///    loser a stale or expired token fails too.
    ///
    /// The second scripted reply is a perfectly good token response, so a racing
    /// implementation cannot be rescued by the wrong branch erroring for an
    /// unrelated reason; the third is what the real service says to a token that
    /// has already been spent.
    #[test]
    fn two_threads_refreshing_at_once_issue_one_refresh_and_both_get_the_new_token() {
        let journal = Arc::new(Journal::default());
        let gate = Arc::new(Gate::default());
        let script = Script::new(
            Arc::clone(&journal),
            vec![
                ok_tokens("ACCESS-2", "REFRESH-2", 3600),
                ok_tokens("ACCESS-3", "REFRESH-3", 3600),
                oauth("invalid_grant"),
            ],
        )
        .gated(Arc::clone(&gate));
        let clock = Arc::new(TestClock::new(Arc::clone(&journal)));
        let store = Arc::new(MemStore::default());
        let cache = Arc::new(TokenCache::new(
            AuthConfig::public_client(CLIENT),
            Arc::clone(&script),
            Arc::clone(&clock),
            Arc::clone(&store),
        ));
        cache.sign_in_with(RefreshToken::new("REFRESH-1"));

        // The delta thread asks first, and stops inside the network call.
        let first = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.token())
        };
        gate.wait_for_entry(1);

        // The invariant, stated directly rather than inferred from a race: the
        // credential is locked away for as long as the request that spends it is
        // outstanding. Reaching into the private field is the point — this is a
        // claim about the construction, and an integration test could only ever
        // approximate it by timing.
        assert!(
            cache.state.try_lock().is_err(),
            "the refresh released the cache lock while its request was in \
             flight; a second thread can now spend the same single-use token"
        );

        // The upload thread asks while the first request is still outstanding.
        let second = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.token())
        };
        // Long enough for a thread that is going to reach the transport to have
        // reached it. Nothing depends on it being long enough in the *passing*
        // direction: the assertions after the join hold whatever this thread
        // did with the time.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            gate.entered(),
            1,
            "a second request reached the token endpoint while the first was \
             still in flight"
        );

        gate.release();
        let got = vec![
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];

        assert_eq!(
            script.seen().len(),
            1,
            "the refresh was issued more than once: {:?}",
            script.seen().iter().map(|(g, _, _)| *g).collect::<Vec<_>>()
        );
        assert_eq!(
            script.max_in_flight(),
            1,
            "two requests were in flight at once"
        );
        assert_eq!(cache.refreshes(), 1);
        for r in &got {
            let token = r.as_ref().expect("both threads must get a token");
            assert_eq!(token.header_value(), "Bearer ACCESS-2");
        }
        // The rotated credential, written down exactly once.
        assert_eq!(store.saved(), vec!["REFRESH-2".to_string()]);
    }

    /// A 401 arrives at all three instances at once, on the same token. Only one
    /// of them may act on it.
    ///
    /// Catches a bare `refresh()` — the obvious API — which is correct for one
    /// caller and spends one rotation per instance for three. Same gated
    /// construction and the same deterministic assertions as the test above: the
    /// lock is held across the request, and the second thread reaches the
    /// transport zero times.
    #[test]
    fn a_401_driven_refresh_is_single_flight_too() {
        let journal = Arc::new(Journal::default());
        let gate = Arc::new(Gate::default());
        let script = Script::new(
            Arc::clone(&journal),
            vec![
                ok_tokens("ACCESS-2", "REFRESH-2", 3600),
                ok_tokens("ACCESS-3", "REFRESH-3", 3600),
                oauth("invalid_grant"),
            ],
        );
        let clock = Arc::new(TestClock::new(Arc::clone(&journal)));
        let cache = Arc::new(TokenCache::new(
            AuthConfig::public_client(CLIENT),
            Arc::clone(&script),
            Arc::clone(&clock),
            Arc::new(MemStore::default()),
        ));
        cache.sign_in_with(RefreshToken::new("REFRESH-1"));

        // Everyone is holding this one, and the service has started refusing it.
        let stale = cache.token().expect("a token to be rejected");
        assert_eq!(stale.header_value(), "Bearer ACCESS-2");
        // Only now does the transport start stopping.
        Arc::clone(&script).gated(Arc::clone(&gate));

        let first = {
            let (cache, stale) = (Arc::clone(&cache), stale.clone());
            std::thread::spawn(move || cache.refresh_if_stale(&stale))
        };
        gate.wait_for_entry(1);
        assert!(
            cache.state.try_lock().is_err(),
            "the 401 path released the cache lock while its request was in flight"
        );

        let second = {
            let (cache, stale) = (Arc::clone(&cache), stale.clone());
            std::thread::spawn(move || cache.refresh_if_stale(&stale))
        };
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            gate.entered(),
            1,
            "the second 401 spent a second rotation on a problem already fixed"
        );

        gate.release();
        for handle in [first, second] {
            let got = handle.join().expect("thread").expect("a fresh token");
            assert_eq!(got.header_value(), "Bearer ACCESS-3");
        }
        // One for the original token, one for the 401. Not three.
        assert_eq!(cache.refreshes(), 2);
    }

    /// The other half of single-flight, and the half holding a lock does not
    /// buy: a refresh that **fails**.
    ///
    /// Catches the waiter whose only re-check is `state.live(now)`. That is
    /// `Some` only when the previous refresh succeeded, so after a failed one
    /// every waiter's re-check says "still no token" and each in turn spends a
    /// rotation of its own. The lock has serialised N refreshes; it has not
    /// deduplicated them. Against a service that is refusing because the token
    /// was already rotated, that is N presentations of a dead credential from
    /// the three threads the daemon starts with.
    ///
    /// Constructed like the success case and for the same reason: the transport
    /// *stops* mid-request, so the second thread is provably inside `token()`
    /// while the first one's refresh is outstanding, rather than probably.
    ///
    /// **The second scripted reply is a perfectly good token response.** An
    /// implementation that lets the waiter through therefore returns
    /// `Ok("Bearer ACCESS-9")` rather than erroring for some unrelated reason —
    /// so this test fails on the defect itself and not on a side effect of it.
    #[test]
    fn two_threads_refreshing_through_a_failure_still_issue_one_refresh() {
        let journal = Arc::new(Journal::default());
        let gate = Arc::new(Gate::default());
        let script = Script::new(
            Arc::clone(&journal),
            vec![
                // What a token the service has already rotated is answered with.
                oauth("invalid_grant"),
                // The wrong branch, scripted to succeed.
                ok_tokens("ACCESS-9", "REFRESH-9", 3600),
                ok_tokens("ACCESS-8", "REFRESH-8", 3600),
            ],
        )
        .gated(Arc::clone(&gate));
        let clock = Arc::new(TestClock::new(Arc::clone(&journal)));
        let cache = Arc::new(TokenCache::new(
            AuthConfig::public_client(CLIENT),
            Arc::clone(&script),
            Arc::clone(&clock),
            Arc::new(MemStore::default()),
        ));
        cache.sign_in_with(RefreshToken::new("REFRESH-1"));

        let first = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.token())
        };
        gate.wait_for_entry(1);
        assert!(
            cache.state.try_lock().is_err(),
            "the refresh released the cache lock while its request was in flight"
        );

        let second = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.token())
        };
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            gate.entered(),
            1,
            "a second request reached the token endpoint while the first was \
             still in flight"
        );

        gate.release();
        let first = first.join().expect("first thread");
        let second = second.join().expect("second thread");

        assert_eq!(first, Err(AuthError::InvalidGrant));
        assert_eq!(
            second,
            Err(AuthError::InvalidGrant),
            "the thread that waited out a failing refresh issued one of its own; \
             a single-use credential has now been presented twice"
        );
        assert_eq!(
            script.seen().len(),
            1,
            "the refresh was issued more than once: {:?}",
            script.seen().iter().map(|(g, _, _)| *g).collect::<Vec<_>>()
        );
        assert_eq!(script.remaining(), 2, "a scripted reply was consumed");
        assert_eq!(cache.refreshes(), 0, "a failed refresh is not a refresh");
    }

    /// POSITIVE CONTROL for the rule above. Deduplicating waiters must not
    /// become "remember the failure forever": a caller that asks again after
    /// the failed attempt has finished is not a waiter, and the retry that fixes
    /// a dropped connection is exactly that caller.
    ///
    /// Catches a dedup keyed on "has anything ever failed" rather than on "did
    /// an attempt finish while I was queued" — which turns one bad round into a
    /// permanently signed-out daemon.
    #[test]
    fn positive_control_a_caller_arriving_after_the_failure_still_gets_to_retry() {
        let rig = Rig::new(vec![
            oauth("invalid_grant"),
            ok_tokens("ACCESS-2", "REFRESH-2", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");

        assert_eq!(cache.token(), Err(AuthError::InvalidGrant));
        assert_eq!(
            cache.token().expect("the retry").header_value(),
            "Bearer ACCESS-2"
        );
        assert_eq!(rig.journal.posts(), 2);
    }

    /// The unrecoverable case, stated: the service received a refresh POST and
    /// rotated the token, and the reply was lost. The bytes in memory are now a
    /// credential the service has retired, every refresh answers
    /// `invalid_grant`, and nothing will ever change that.
    ///
    /// Catches a cache that has no way to record a dead credential — where
    /// `is_signed_in()` answers `true` forever while every request 401s, so a
    /// health check reports a healthy daemon, nothing prompts for a new sign-in,
    /// and the threads keep presenting the retired token to
    /// `login.microsoftonline.com` for as long as the process runs.
    ///
    /// The fourth scripted reply is a good token response, so an implementation
    /// that keeps trying gets a *token* rather than an error: only the post
    /// count and the returned value tell right from wrong.
    #[test]
    fn a_credential_the_service_keeps_refusing_is_declared_dead() {
        let rig = Rig::new(vec![
            oauth("invalid_grant"),
            oauth("invalid_grant"),
            oauth("invalid_grant"),
            ok_tokens("ACCESS-9", "REFRESH-9", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");

        assert_eq!(cache.token(), Err(AuthError::InvalidGrant));
        assert!(
            cache.is_signed_in(),
            "one invalid_grant is a blip, a lost race or a rotation someone else \
             won — not a conclusion"
        );
        // Past the backoff each time, so that it is the strike count and not
        // the clock deciding this.
        rig.clock.advance(MAX_REFRESH_BACKOFF);
        assert_eq!(cache.token(), Err(AuthError::InvalidGrant));
        assert!(cache.is_signed_in(), "two is still not a conclusion");
        rig.clock.advance(MAX_REFRESH_BACKOFF);
        assert_eq!(cache.token(), Err(AuthError::InvalidGrant));

        assert_eq!(rig.journal.posts(), 3);
        assert!(
            !cache.is_signed_in(),
            "the cache still reports a signed-in user against a credential the \
             service has refused {MAX_REJECTIONS} times running"
        );
        // And the answer changes to the one a caller can act on, without another
        // request: this is the bound on the hot loop.
        for _ in 0..20 {
            assert_eq!(cache.token(), Err(AuthError::CredentialRejected));
        }
        assert_eq!(
            rig.journal.posts(),
            3,
            "a credential known to be dead was presented again"
        );
        assert_eq!(rig.script.remaining(), 1);
    }

    /// POSITIVE CONTROL for the death sentence: it must be liftable, or the cure
    /// does not work. A new device code flow — or any new credential — is
    /// exactly the thing the rejection was telling the caller to go and get.
    ///
    /// Catches a `rejected` flag that is never cleared, which turns the one
    /// recoverable path out of a dead credential into a restart.
    #[test]
    fn positive_control_a_new_credential_lifts_the_rejection() {
        let rig = Rig::new(vec![
            oauth("invalid_grant"),
            oauth("invalid_grant"),
            oauth("invalid_grant"),
            ok_tokens("ACCESS-9", "REFRESH-9", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");

        for _ in 0..MAX_REJECTIONS {
            assert_eq!(cache.token(), Err(AuthError::InvalidGrant));
            rig.clock.advance(MAX_REFRESH_BACKOFF);
        }
        assert!(!cache.is_signed_in());

        cache.sign_in_with(RefreshToken::new("REFRESH-FRESH"));
        assert!(cache.is_signed_in(), "a new credential is a new chance");
        assert_eq!(
            cache.token().expect("the new credential works").header_value(),
            "Bearer ACCESS-9"
        );
        assert!(bodies_of(&rig.script, Grant::Refresh)[3].contains("refresh_token=REFRESH-FRESH"));
    }

    /// A failing refresh must not be a hot loop. `complete_device_code` bounds
    /// its polling; this bounds the retrying, and without it a credential that
    /// is simply not working means one request per `token()` call from every
    /// thread that wants one — against `login.microsoftonline.com`, which is the
    /// endpoint most likely to start throttling the whole app registration.
    ///
    /// Catches an implementation with no backoff at all, and catches one that
    /// backs off from the *first* failure — a dropped connection is fixed by the
    /// very next attempt, and making the caller wait five seconds to discover
    /// that converts a recovered fault into a visible stall.
    #[test]
    fn a_failing_refresh_backs_off_instead_of_hot_looping() {
        let dropped = || Err(io::Error::new(io::ErrorKind::ConnectionReset, "dropped"));
        let rig = Rig::new(vec![
            dropped(),
            dropped(),
            ok_tokens("ACCESS-2", "REFRESH-2", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");
        let reset = Err(AuthError::Transport {
            kind: io::ErrorKind::ConnectionReset,
        });

        // The first failure is free, and so is the attempt that follows it.
        assert_eq!(cache.token(), reset);
        assert_eq!(cache.token(), reset);
        assert_eq!(rig.journal.posts(), 2);

        // The third is not. Twenty threads asking inside the window get the last
        // answer, and the endpoint hears nothing.
        for _ in 0..20 {
            assert_eq!(cache.token(), reset);
        }
        assert_eq!(
            rig.journal.posts(),
            2,
            "a failing refresh hot-looped against the token endpoint"
        );
        assert_eq!(rig.script.remaining(), 1, "the good reply was consumed early");

        // POSITIVE CONTROL: the window ends, and it is the retry that fixes the
        // outage — a backoff that never expires is an outage that never ends.
        rig.clock.advance(REFRESH_BACKOFF_STEP);
        assert_eq!(
            cache.token().expect("the attempt after the backoff").header_value(),
            "Bearer ACCESS-2"
        );
        assert_eq!(rig.journal.posts(), 3);
        assert_eq!(cache.refreshes(), 1);
    }

    /// POSITIVE CONTROL for the stale check itself: an instance that 401s on a
    /// token another instance has already replaced must take the replacement, not
    /// refuse and not refresh. Catches `refresh_if_stale` implemented as an
    /// unconditional refresh, and catches one that returns an error when the
    /// token does not match.
    #[test]
    fn positive_control_a_401_on_a_superseded_token_takes_the_replacement() {
        let rig = Rig::new(vec![
            ok_tokens("ACCESS-2", "REFRESH-2", 3600),
            ok_tokens("ACCESS-3", "REFRESH-3", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");

        let stale = cache.token().expect("first token");
        // Another instance got there first.
        let fresh = cache.refresh_if_stale(&stale).expect("the real refresh");
        assert_eq!(fresh.header_value(), "Bearer ACCESS-3");

        let posts = rig.journal.posts();
        // A late 401 on the token that was already replaced.
        assert_eq!(
            cache
                .refresh_if_stale(&stale)
                .expect("must not fail")
                .header_value(),
            "Bearer ACCESS-3"
        );
        assert_eq!(rig.journal.posts(), posts, "a needless rotation was spent");
        assert_eq!(cache.refreshes(), 2);
    }

    /// POSITIVE CONTROL. Keeps the rule above from collapsing into "refresh at
    /// most once, ever" — a cache that latches after its first refresh works
    /// perfectly for an hour and then stops syncing for good.
    #[test]
    fn positive_control_a_second_refresh_after_the_first_still_happens() {
        let rig = Rig::new(vec![
            ok_tokens("ACCESS-2", "REFRESH-2", 3600),
            ok_tokens("ACCESS-3", "REFRESH-3", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");

        assert_eq!(
            cache.token().expect("first").header_value(),
            "Bearer ACCESS-2"
        );
        // Past the first token's life.
        rig.clock.advance(Duration::from_secs(3600));
        assert_eq!(
            cache.token().expect("second").header_value(),
            "Bearer ACCESS-3"
        );
        assert_eq!(cache.refreshes(), 2);
    }

    /// The rotation itself. Catches an implementation that spends the credential
    /// and keeps the old one — which works exactly once, and then presents a
    /// consumed token forever.
    ///
    /// Asserted on the wire, not on an accessor: the second refresh's body must
    /// carry `REFRESH-2`. Reading it back out of the cache would pass against an
    /// implementation that stores the new one and sends the old one.
    #[test]
    fn a_rotated_refresh_token_replaces_the_stored_one() {
        let rig = Rig::new(vec![
            ok_tokens("ACCESS-2", "REFRESH-2", 3600),
            ok_tokens("ACCESS-3", "REFRESH-3", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");

        cache.token().expect("first");
        rig.clock.advance(Duration::from_secs(3600));
        cache.token().expect("second");

        let sent = bodies_of(&rig.script, Grant::Refresh);
        assert_eq!(sent.len(), 2);
        assert!(
            sent[0].contains("refresh_token=REFRESH-1"),
            "the first refresh must spend the credential it was given: {}",
            sent[0]
        );
        assert!(
            sent[1].contains("refresh_token=REFRESH-2"),
            "the second refresh must spend the *rotated* credential: {}",
            sent[1]
        );
        // And each rotation is written down, in order, so a restart resumes the
        // one that still works.
        assert_eq!(
            rig.store.saved(),
            vec!["REFRESH-2".to_string(), "REFRESH-3".to_string()]
        );
    }

    /// Catches `state.refresh = tokens.refresh` — one word, and it discards the
    /// credential on the first reply that omits the field. There is then nothing
    /// to refresh with and nothing on disk either, because the same assignment
    /// would have been persisted.
    #[test]
    fn a_reply_without_a_refresh_token_keeps_the_one_we_have() {
        let no_rotation = Ok(TokenReply::new(
            200,
            br#"{"token_type":"Bearer","expires_in":3600,"access_token":"ACCESS-2"}"#.to_vec(),
        ));
        let rig = Rig::new(vec![no_rotation, ok_tokens("ACCESS-3", "REFRESH-3", 3600)]);
        let cache = rig.signed_in("REFRESH-1");

        cache.token().expect("first");
        assert!(cache.is_signed_in(), "the credential must survive");
        // Nothing rotated, so nothing was written: a store write is a disk write
        // on the delta thread's path, and re-writing the same bytes is one that
        // buys nothing.
        assert!(rig.store.saved().is_empty());

        rig.clock.advance(Duration::from_secs(3600));
        cache.token().expect("second");

        let sent = bodies_of(&rig.script, Grant::Refresh);
        assert!(
            sent[1].contains("refresh_token=REFRESH-1"),
            "a reply with no rotation must leave the credential alone: {}",
            sent[1]
        );
        // And the rotation that did happen is written, so this is not passing
        // because the store is never used at all.
        assert_eq!(rig.store.saved(), vec!["REFRESH-3".to_string()]);
    }

    /// A refresh that fails must not take the credential with it.
    ///
    /// Catches the shape that clears the cache on any error — "the token must be
    /// bad, throw it away" — which converts a dropped connection into a
    /// mandatory re-sign-in. Both failure kinds are covered: the transport never
    /// answering, and the service answering with a refusal.
    #[test]
    fn a_failed_refresh_does_not_destroy_the_stored_credential() {
        let rig = Rig::new(vec![
            Err(io::Error::new(io::ErrorKind::ConnectionReset, "dropped")),
            ok_tokens("ACCESS-2", "REFRESH-2", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");

        assert_eq!(
            cache.token(),
            Err(AuthError::Transport {
                kind: io::ErrorKind::ConnectionReset
            })
        );
        assert!(cache.is_signed_in(), "a dropped connection is not a logout");
        assert_eq!(cache.refreshes(), 0, "a failed refresh is not a refresh");

        // The retry spends the same credential, and works.
        assert_eq!(
            cache.token().expect("retry").header_value(),
            "Bearer ACCESS-2"
        );
        let sent = bodies_of(&rig.script, Grant::Refresh);
        assert!(sent[0].contains("refresh_token=REFRESH-1"));
        assert!(sent[1].contains("refresh_token=REFRESH-1"));
    }

    /// The specific failure `PROVIDER.md` names. `invalid_grant` is what a lost
    /// race looks like from the client, and it is also what a service blip looks
    /// like — so discarding the credential on it turns a recoverable moment into
    /// the very sign-out that was being avoided.
    ///
    /// Catches "clear the refresh token on invalid_grant", which is the
    /// obvious-looking reading of the error and is wrong.
    #[test]
    fn an_invalid_grant_does_not_discard_the_refresh_token() {
        let rig = Rig::new(vec![oauth("invalid_grant"), ok_tokens("A2", "R2", 3600)]);
        let cache = rig.signed_in("REFRESH-1");

        assert_eq!(cache.token(), Err(AuthError::InvalidGrant));
        assert!(cache.is_signed_in());
        assert_eq!(cache.token().expect("retry").header_value(), "Bearer A2");
    }

    /// POSITIVE CONTROL, and the other half of the rotation storm. A cache that
    /// refreshes whenever it is asked spends a single-use credential once per
    /// call — from three threads — which is the same `invalid_grant` reached
    /// without any race at all.
    #[test]
    fn positive_control_a_live_access_token_is_reused_without_a_request() {
        let rig = Rig::new(vec![ok_tokens("ACCESS-2", "REFRESH-2", 3600)]);
        let cache = rig.signed_in("REFRESH-1");

        for _ in 0..5 {
            assert_eq!(cache.token().expect("token").header_value(), "Bearer ACCESS-2");
        }
        assert_eq!(rig.journal.posts(), 1);
        assert_eq!(cache.refreshes(), 1);
    }

    /// A token with less than the skew left is spent, not handed out. Catches
    /// `now < expires_at`, which returns a token that dies between the header
    /// being written and the request being read — a 401 in the middle of a round
    /// rather than a refresh before it.
    #[test]
    fn an_access_token_inside_the_skew_is_refreshed_early() {
        let rig = Rig::new(vec![
            ok_tokens("ACCESS-2", "REFRESH-2", 3600),
            ok_tokens("ACCESS-3", "REFRESH-3", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");
        cache.token().expect("first");

        // 3570 of 3600 seconds gone: still valid by the naive comparison, and
        // 30 seconds is not enough to finish a round with.
        rig.clock.advance(Duration::from_secs(3570));
        assert_eq!(
            cache.token().expect("second").header_value(),
            "Bearer ACCESS-3"
        );
        assert_eq!(cache.refreshes(), 2);
    }

    /// A cache with no credential must ask for a sign-in, not post an empty
    /// grant. Catches `refresh_token=` being sent as a well-formed request for
    /// the empty string, which is a 400 the service counts against the app
    /// registration — so the penalty lands on every user of the client.
    #[test]
    fn a_signed_out_cache_makes_no_request_at_all() {
        let rig = Rig::new(vec![ok_tokens("ACCESS-2", "REFRESH-2", 3600)]);
        let cache = rig.cache();

        assert_eq!(cache.token(), Err(AuthError::SignedOut));
        assert_eq!(rig.journal.posts(), 0);
        assert_eq!(rig.script.remaining(), 1, "nothing was consumed");
    }

    /// POSITIVE CONTROL for the store seam: a restart must resume rather than
    /// demand a new device code. Catches a `resume` that reads nothing, and one
    /// that reads and discards.
    #[test]
    fn positive_control_resume_loads_the_stored_credential() {
        let rig = Rig::with_store(
            vec![ok_tokens("ACCESS-2", "REFRESH-2", 3600)],
            MemStore::seeded("REFRESH-FROM-DISK"),
        );
        let cache = rig.cache();

        assert!(cache.resume().expect("resume"));
        cache.token().expect("token");
        assert!(bodies_of(&rig.script, Grant::Refresh)[0].contains("refresh_token=REFRESH-FROM-DISK"));
    }

    /// A store that cannot write must not fail the refresh. Catches `self
    /// .store.save(..)?` — which converts a full disk into an immediate sync
    /// outage, while the access token that would have kept everything working is
    /// sitting in hand. And it catches the opposite: swallowing the failure
    /// silently, so the next restart demands a sign-in with nothing anywhere to
    /// say why.
    #[test]
    fn a_store_that_fails_does_not_lose_the_token_it_could_not_write() {
        let store = Arc::new(MemStore::default());
        store.failing();
        let rig = Rig::with_store(vec![ok_tokens("ACCESS-2", "REFRESH-2", 3600)], store);
        let cache = rig.signed_in("REFRESH-1");

        assert_eq!(
            cache.token().expect("the refresh itself succeeded").header_value(),
            "Bearer ACCESS-2"
        );
        assert_eq!(cache.last_store_error(), Some(io::ErrorKind::PermissionDenied));
        assert!(cache.is_signed_in());
    }

    // =======================================================================
    // The device code flow
    // =======================================================================

    /// `slow_down` must lengthen the interval. Catches treating it as another
    /// `authorization_pending` — the interval never grows, the polling never
    /// slows, and the throttle that earns is applied to the app registration,
    /// so it lands on every user of this client rather than on this one.
    ///
    /// The journal is asserted rather than a counter, because "slept longer
    /// somewhere" is not the claim: the *next* wait after the `slow_down` is.
    #[test]
    fn slow_down_lengthens_the_poll_interval() {
        let rig = Rig::new(vec![
            device_code_body(5, 900),
            oauth("authorization_pending"),
            oauth("slow_down"),
            oauth("authorization_pending"),
            ok_tokens("ACCESS-1", "REFRESH-1", 3600),
        ]);
        let cache = rig.cache();

        let code = cache.begin_device_code().expect("device code");
        cache.complete_device_code(&code).expect("sign in");

        assert_eq!(
            rig.journal.sleeps(),
            vec![
                Duration::from_secs(5),  // before the first poll
                Duration::from_secs(5),  // still 5 after `authorization_pending`
                Duration::from_secs(10), // +5 after `slow_down`
                Duration::from_secs(10), // and it stays lengthened
            ]
        );
    }

    /// RFC 8628 says the client waits the interval. Catches a poll loop that
    /// fires the instant it has a code — one wasted request per sign-in, sent
    /// before the user has finished reading the code out loud, and the shape
    /// that earns the `slow_down` above.
    #[test]
    fn the_first_poll_waits_the_interval_before_asking() {
        let rig = Rig::new(vec![
            device_code_body(5, 900),
            ok_tokens("ACCESS-1", "REFRESH-1", 3600),
        ]);
        let cache = rig.cache();
        let code = cache.begin_device_code().expect("device code");
        cache.complete_device_code(&code).expect("sign in");

        assert_eq!(
            rig.journal.events(),
            vec![
                Ev::Posted(Grant::DeviceCode),
                Ev::Slept(Duration::from_secs(5)),
                Ev::Posted(Grant::DeviceToken),
            ]
        );
    }

    /// POSITIVE CONTROL. `authorization_pending` is not a failure, and a client
    /// that reads it as one fails every sign-in on its first poll — which is
    /// every sign-in, since nobody types a code in under five seconds.
    #[test]
    fn positive_control_authorization_pending_keeps_polling() {
        let rig = Rig::new(vec![
            device_code_body(5, 900),
            oauth("authorization_pending"),
            oauth("authorization_pending"),
            ok_tokens("ACCESS-1", "REFRESH-1", 3600),
        ]);
        let cache = rig.cache();
        let code = cache.begin_device_code().expect("device code");

        cache.complete_device_code(&code).expect("sign in");
        assert!(cache.is_signed_in());
        // And the credential from a device code flow is written down, or the
        // next restart starts the whole dance again.
        assert_eq!(rig.store.saved(), vec!["REFRESH-1".to_string()]);
    }

    /// The service saying the code is dead stops the poll. Catches the
    /// `_ => continue` arm — every unrecognised code read as "keep going" — which
    /// polls an endpoint that will never say yes until the process is killed.
    #[test]
    fn an_expired_device_code_stops_rather_than_polling_forever() {
        let rig = Rig::new(vec![
            device_code_body(5, 900),
            oauth("authorization_pending"),
            oauth("expired_token"),
            // Scripted to succeed, so an implementation that keeps polling gets
            // a *token* rather than an error: only the returned value and the
            // post count tell right from wrong.
            ok_tokens("ACCESS-1", "REFRESH-1", 3600),
        ]);
        let cache = rig.cache();
        let code = cache.begin_device_code().expect("device code");

        assert_eq!(
            cache.complete_device_code(&code),
            Err(AuthError::DeviceCodeExpired)
        );
        assert!(!cache.is_signed_in());
        assert_eq!(rig.script.remaining(), 1, "polling continued past the refusal");
    }

    /// The client's own deadline, for the service that never says `expired_token`
    /// at all. Catches a loop whose only exit is a code the service has to
    /// volunteer — the code's 900-second life is known locally from the moment it
    /// is issued, and a poll that outlives it is a request that cannot succeed.
    ///
    /// The script repeats `authorization_pending` forever, so nothing but the
    /// deadline can end this.
    #[test]
    fn a_device_code_past_its_lifetime_stops_even_while_the_service_says_pending() {
        let journal = Arc::new(Journal::default());
        let script = Script::new(
            Arc::clone(&journal),
            vec![device_code_body(5, 30), oauth("authorization_pending")],
        )
        .repeating(r#"{"error":"authorization_pending"}"#);
        let clock = Arc::new(TestClock::new(Arc::clone(&journal)));
        let cache = TokenCache::new(
            AuthConfig::public_client(CLIENT),
            Arc::clone(&script),
            Arc::clone(&clock),
            Arc::new(MemStore::default()),
        );

        let code = cache.begin_device_code().expect("device code");
        assert_eq!(
            cache.complete_device_code(&code),
            Err(AuthError::DeviceCodeExpired)
        );
        // 30 seconds of life, five-second interval: six polls at most, and the
        // seventh wait crosses the deadline.
        assert!(
            journal.posts() <= 7,
            "the deadline did not bound the poll: {} requests",
            journal.posts()
        );
    }

    /// A clock that does not advance must not turn a sign-in into a permanent
    /// request loop. Catches a deadline that is the *only* bound: a suspended
    /// VM, a monotonic source that stalls, or a `Clock` double written later
    /// whose `sleep` forgets to advance, each of which would otherwise hammer
    /// the endpoint most likely to start throttling, forever, from a thread
    /// nobody is watching.
    #[test]
    fn a_frozen_clock_does_not_poll_forever() {
        let journal = Arc::new(Journal::default());
        let script = Script::new(
            Arc::clone(&journal),
            vec![device_code_body(5, 900), oauth("authorization_pending")],
        )
        .repeating(r#"{"error":"authorization_pending"}"#);
        let cache = TokenCache::new(
            AuthConfig::public_client(CLIENT),
            Arc::clone(&script),
            Arc::new(FrozenClock(Arc::clone(&journal))),
            Arc::new(MemStore::default()),
        );

        let code = cache.begin_device_code().expect("device code");
        assert_eq!(
            cache.complete_device_code(&code),
            Err(AuthError::PollLimit {
                attempts: MAX_POLL_ATTEMPTS
            })
        );
    }

    /// A refusal is final. Catches retrying `access_denied`, which re-sends a
    /// prompt the user has already declined — and catches folding it into the
    /// pending arm, which waits for a decision that has been made.
    #[test]
    fn access_denied_stops_immediately_and_does_not_retry() {
        let rig = Rig::new(vec![
            device_code_body(5, 900),
            oauth("access_denied"),
            ok_tokens("ACCESS-1", "REFRESH-1", 3600),
        ]);
        let cache = rig.cache();
        let code = cache.begin_device_code().expect("device code");

        assert_eq!(
            cache.complete_device_code(&code),
            Err(AuthError::AccessDenied)
        );
        assert_eq!(rig.script.remaining(), 1);
        assert!(!cache.is_signed_in());
    }

    /// Without `offline_access` the service returns no refresh token at all, so
    /// the daemon signs the user in again every hour — an interactive prompt on
    /// a headless machine. Catches a scope list built from the caller's request
    /// alone.
    #[test]
    fn every_request_asks_for_offline_access() {
        let rig = Rig::new(vec![
            device_code_body(5, 900),
            ok_tokens("ACCESS-1", "REFRESH-1", 3600),
        ]);
        let cache = TokenCache::new(
            // A caller who did not think about it.
            AuthConfig::public_client(CLIENT).with_scopes(["Files.ReadWrite.All"]),
            Arc::clone(&rig.script),
            Arc::clone(&rig.clock),
            Arc::clone(&rig.store),
        );

        let code = cache.begin_device_code().expect("device code");
        cache.complete_device_code(&code).expect("sign in");

        let asked = bodies_of(&rig.script, Grant::DeviceCode);
        assert!(
            asked[0].contains("offline_access"),
            "the device code request must ask for offline_access: {}",
            asked[0]
        );
    }

    /// The poll spends the device code, and the whole flow ends with a cache
    /// that answers without another request. End-to-end positive control for
    /// everything above.
    #[test]
    fn a_completed_device_code_flow_leaves_a_usable_cache() {
        let rig = Rig::new(vec![
            device_code_body(5, 900),
            ok_tokens("ACCESS-1", "REFRESH-1", 3600),
        ]);
        let cache = rig.cache();

        let code = cache.begin_device_code().expect("device code");
        assert_eq!(code.user_code(), "FJKR2N9P");
        assert_eq!(code.verification_uri(), "https://microsoft.com/devicelogin");
        cache.complete_device_code(&code).expect("sign in");

        let posts_before = rig.journal.posts();
        assert_eq!(
            cache.token().expect("token").header_value(),
            "Bearer ACCESS-1"
        );
        assert_eq!(
            rig.journal.posts(),
            posts_before,
            "the flow's own token must be used, not refreshed for"
        );
        let polls = bodies_of(&rig.script, Grant::DeviceToken);
        assert!(polls[0].contains("device_code=DEV-SECRET"), "{}", polls[0]);
        assert!(
            polls[0].contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"),
            "the device code grant must be named and encoded: {}",
            polls[0]
        );
    }

    /// A user code is printed to a terminal. Catches passing a server-supplied
    /// string through to a prompt unexamined, which is an escape sequence
    /// written to the console of whoever is signing in.
    #[test]
    fn a_user_code_carrying_control_characters_is_refused() {
        let body = "{\"device_code\":\"D\",\"user_code\":\"AB\\u001b[2JCD\",\
                    \"verification_uri\":\"https://microsoft.com/devicelogin\",\
                    \"expires_in\":900,\"interval\":5}";
        let rig = Rig::new(vec![Ok(TokenReply::new(200, body.as_bytes().to_vec()))]);
        let cache = rig.cache();

        assert_eq!(
            cache.begin_device_code().expect_err("must be refused"),
            AuthError::Malformed("the user_code is not printable text")
        );
    }

    // =======================================================================
    // Nothing leaks
    // =======================================================================

    /// The requirement stated directly: no credential in any `Debug` output.
    ///
    /// Every type a caller can hold is formatted here, in both `{:?}` and
    /// `{:#?}`. Catches a `#[derive(Debug)]` added to `Secret`, to `TokenRequest`
    /// (whose body *is* the refresh token), to `TokenReply` (whose body is both
    /// tokens), or to `DeviceCode`; and catches a `TokenCache` `Debug` that
    /// prints its state.
    #[test]
    fn no_credential_appears_in_any_debug_output() {
        let rig = Rig::new(vec![
            device_code_body(5, 900),
            ok_tokens("ACCESS-1", "REFRESH-2", 3600),
        ]);
        let cache = rig.signed_in("REFRESH-1");
        let code = cache.begin_device_code().expect("device code");
        cache.complete_device_code(&code).expect("sign in");

        let secret = Secret::new("REFRESH-1");
        let refresh = RefreshToken::new("REFRESH-1");
        let access = AccessToken(Secret::new("ACCESS-1"));
        let request = cache.config().refresh_request(&refresh);
        let reply = TokenReply::new(200, br#"{"refresh_token":"REFRESH-1"}"#.to_vec());
        let tokens = Tokens {
            access: access.clone(),
            expires_in: Duration::from_secs(3600),
            refresh: Some(RefreshToken::new("REFRESH-2")),
        };

        let rendered = vec![
            format!("{secret:?}"),
            format!("{secret:#?}"),
            format!("{refresh:?}"),
            format!("{refresh:#?}"),
            format!("{access:?}"),
            format!("{access:#?}"),
            format!("{request:?}"),
            format!("{request:#?}"),
            format!("{reply:?}"),
            format!("{reply:#?}"),
            format!("{tokens:?}"),
            format!("{tokens:#?}"),
            format!("{code:?}"),
            format!("{code:#?}"),
            format!("{cache:?}"),
            format!("{cache:#?}"),
        ];
        for text in &rendered {
            for needle in ["REFRESH-1", "REFRESH-2", "ACCESS-1", "DEV-SECRET"] {
                assert!(
                    !text.contains(needle),
                    "a credential reached a Debug output: {needle} in {text}"
                );
            }
        }
        // And the redaction is a placeholder rather than an empty string, so a
        // reader can tell "not printed" from "not present".
        assert!(format!("{secret:?}").contains("redacted"));
    }

    /// A transport that puts its request body into its error message — a debug
    /// build, a retry wrapper, a proxy library — must not carry the credential
    /// into an `AuthError` that something later logs. Catches
    /// `AuthError::Transport(e.to_string())`.
    #[test]
    fn a_transport_error_message_cannot_carry_the_credential() {
        let rig = Rig::new(vec![Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "POST /token failed: refresh_token=REFRESH-1",
        ))]);
        let cache = rig.signed_in("REFRESH-1");

        let err = cache.token().expect_err("must fail");
        assert!(
            !format!("{err:?}").contains("REFRESH-1"),
            "the transport's message reached the error: {err:?}"
        );
        assert_eq!(
            err,
            AuthError::Transport {
                kind: io::ErrorKind::ConnectionRefused
            }
        );
    }

    /// A malformed reply must not be quoted into the error. Catches
    /// `Malformed(format!("{body}"))`, which is the natural thing to write while
    /// chasing a parse failure — and which prints the whole token response,
    /// credentials included, on the one path where the body is *nearly* a
    /// successful one.
    #[test]
    fn a_malformed_reply_is_not_quoted_into_the_error() {
        let rig = Rig::new(vec![Ok(TokenReply::new(
            200,
            br#"{"refresh_token":"REFRESH-2","expires_in":3600}"#.to_vec(),
        ))]);
        let cache = rig.signed_in("REFRESH-1");

        let err = cache.token().expect_err("no access_token");
        assert_eq!(err, AuthError::Malformed("no access_token in the reply"));
        assert!(!format!("{err:?}").contains("REFRESH-2"));
    }

    /// A `CredentialStore` is the one seam whose entire subject is the
    /// credential, so its error message is the likeliest place for one to
    /// appear: "could not parse the credential file: refresh_token=… at line 1"
    /// is what a store written next year says while someone debugs a bad file.
    ///
    /// Catches `self.store.load()?` in [`TokenCache::resume`] — the only error
    /// on that path not built from a literal, where `persist` and the transport
    /// seam both reduce to `e.kind()` for exactly this reason. `resume` returns
    /// an `io::Error` to the caller's startup path, which logs it.
    #[test]
    fn a_credential_store_error_message_cannot_carry_the_credential() {
        let store = Arc::new(MemStore::default());
        store.failing_load(
            io::ErrorKind::InvalidData,
            "could not parse the credential file: refresh_token=REFRESH-1",
        );
        let rig = Rig::with_store(vec![], store);
        let cache = rig.cache();

        let err = cache.resume().expect_err("the store failed");
        assert!(
            !format!("{err}").contains("REFRESH-1"),
            "the store's message reached the error: {err}"
        );
        assert!(
            !format!("{err:?}").contains("REFRESH-1"),
            "the store's message reached the error's Debug: {err:?}"
        );
        // POSITIVE CONTROL: the kind is the part a caller can act on —
        // `NotFound` is "sign in", `PermissionDenied` is "fix the file" — so
        // flattening everything to `Other` would be the other way to fail this.
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A server-supplied error code is server-supplied text. Catches carrying it
    /// through untouched: a hostile or broken endpoint that echoes the submitted
    /// token back in the `error` field would otherwise put it in every log line
    /// that prints the resulting `AuthError`.
    #[test]
    fn an_error_code_that_echoes_a_credential_is_sanitised() {
        let rig = Rig::new(vec![Ok(TokenReply::new(
            400,
            br#"{"error":"REFRESH-1.eyJhbGciOiJIUzI1NiJ9"}"#.to_vec(),
        ))]);
        let cache = rig.signed_in("REFRESH-1");

        let err = cache.token().expect_err("must fail");
        assert!(!format!("{err:?}").contains("REFRESH-1"));
        // POSITIVE CONTROL: a real code survives the same filter intact, or the
        // sanitiser has made every unexpected error unreadable.
        assert_eq!(
            oauth_error(&serde_json::json!({"error": "unsupported_grant_type"})),
            Some(AuthError::Oauth {
                code: "unsupported_grant_type".to_string()
            })
        );
    }

    // =======================================================================
    // Observability, and the deadline
    // =======================================================================

    /// A health check must not block on the network.
    ///
    /// `state`'s lock is held across the refresh request on purpose — that is
    /// the single-flight guarantee — so an accessor that takes it inherits the
    /// transport's whole duration. Catches `self.state().refreshes`,
    /// `self.state().refresh.is_some()` and `self.state().store_error`: with a
    /// real transport, a `/healthz` hit during a slow refresh hangs for a
    /// minute, which is indistinguishable from a daemon that has died and is
    /// the moment the check is most needed. `Debug` already used `try_lock` for
    /// this reason; these three did not.
    ///
    /// The query runs on its own thread behind a `recv_timeout`, so a blocking
    /// implementation fails in half a second rather than eventually passing once
    /// the gate's own timeout lets the request through.
    #[test]
    fn the_health_check_accessors_do_not_block_on_a_refresh_in_flight() {
        let journal = Arc::new(Journal::default());
        let gate = Arc::new(Gate::default());
        let script = Script::new(
            Arc::clone(&journal),
            vec![ok_tokens("ACCESS-2", "REFRESH-2", 3600)],
        )
        .gated(Arc::clone(&gate));
        let clock = Arc::new(TestClock::new(Arc::clone(&journal)));
        let cache = Arc::new(TokenCache::new(
            AuthConfig::public_client(CLIENT),
            Arc::clone(&script),
            Arc::clone(&clock),
            Arc::new(MemStore::default()),
        ));
        cache.sign_in_with(RefreshToken::new("REFRESH-1"));

        let refreshing = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.token())
        };
        gate.wait_for_entry(1);
        assert!(
            cache.state.try_lock().is_err(),
            "the refresh is not holding the lock, so this test proves nothing"
        );

        let (tx, rx) = std::sync::mpsc::channel();
        {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || {
                let _ = tx.send((
                    cache.refreshes(),
                    cache.is_signed_in(),
                    cache.last_store_error(),
                    cache.last_slow_post(),
                ));
            });
        }
        let answered = rx.recv_timeout(Duration::from_millis(500)).expect(
            "a health check blocked while a refresh was in flight; against a \
             real transport it would have blocked for the request's whole \
             duration",
        );
        assert_eq!(
            answered,
            (0, true, None, None),
            "the accessors answered, but with the wrong answers"
        );

        gate.release();
        refreshing.join().expect("thread").expect("a token");
        // POSITIVE CONTROL: the mirror is not simply frozen at its initial
        // values — an accessor that never blocks because it never reads
        // anything would satisfy everything above.
        assert_eq!(cache.refreshes(), 1);
    }

    /// A transport that overruns [`TOKEN_POST_DEADLINE`] holds the cache's lock,
    /// and with it every thread in the process, for as long as it likes. It
    /// cannot be cancelled from here — it is a blocking call on a thread this
    /// module does not own — so what the seam owes is that the violation is not
    /// silent.
    ///
    /// Catches a `TokenTransport` whose timeout requirement is prose and nothing
    /// else: with no measurement at the seam, a transport that parks `token()`
    /// for ten minutes is indistinguishable from a slow network, and the only
    /// symptom anywhere is that the daemon stops doing anything.
    #[test]
    fn a_transport_that_overruns_the_deadline_is_recorded() {
        let journal = Arc::new(Journal::default());
        let clock = Arc::new(TestClock::new(Arc::clone(&journal)));
        let took = TOKEN_POST_DEADLINE + Duration::from_secs(1);
        let cache = TokenCache::new(
            AuthConfig::public_client(CLIENT),
            Arc::new(SlowTransport {
                clock: Arc::clone(&clock),
                took,
            }),
            Arc::clone(&clock),
            Arc::new(MemStore::default()),
        );
        cache.sign_in_with(RefreshToken::new("REFRESH-1"));

        assert_eq!(
            cache.token(),
            Err(AuthError::Transport {
                kind: io::ErrorKind::TimedOut
            })
        );
        assert_eq!(
            cache.last_slow_post(),
            Some(took),
            "a transport that broke the deadline was not recorded anywhere"
        );
        // And it is in the one rendering somebody chasing a stall will reach for.
        assert!(format!("{cache:?}").contains("slow_post"));
    }

    /// POSITIVE CONTROL. A deadline check that fires on every request reports
    /// nothing, because "always slow" and "never slow" carry the same
    /// information.
    #[test]
    fn positive_control_a_transport_inside_the_deadline_is_not_called_slow() {
        let rig = Rig::new(vec![ok_tokens("ACCESS-2", "REFRESH-2", 3600)]);
        let cache = rig.signed_in("REFRESH-1");
        cache.token().expect("token");
        assert_eq!(cache.last_slow_post(), None);
    }

    // =======================================================================
    // Where the credential goes
    // =======================================================================

    /// The refresh token goes to the token endpoint and nowhere else. Catches a
    /// URL built from the Graph host — the host every other URL in this crate
    /// uses — which would hand a live refresh token to the resource server.
    #[test]
    fn the_refresh_token_is_addressed_to_the_token_endpoint() {
        let rig = Rig::new(vec![ok_tokens("A2", "R2", 3600)]);
        let cache = rig.signed_in("REFRESH-1");
        cache.token().expect("token");

        let (_, url, body) = rig.script.seen().into_iter().next().expect("a request");
        assert_eq!(
            url,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        );
        assert!(on_the_authority(&url, DEFAULT_AUTHORITY_HOST));
        assert!(!on_the_authority(&url, "graph.microsoft.com"));
        assert!(body.contains("grant_type=refresh_token"));
    }

    /// The authority is where the credential goes, so anything that could make
    /// one host look like another is refused when the config is built rather
    /// than escaped when the URL is joined.
    ///
    /// Catches `format!("https://{host}/…")` over an unvalidated string: every
    /// entry below composes a URL whose real host is `evil.example`, and each
    /// one arrives from a config file.
    #[test]
    fn an_authority_host_that_is_not_a_bare_host_is_refused() {
        for hostile in [
            "login.microsoftonline.com@evil.example",
            "login.microsoftonline.com/../evil.example",
            "evil.example#login.microsoftonline.com",
            "login.microsoftonline.com:8443",
            "https://login.microsoftonline.com",
            "login.microsoftonline.com/token",
            "",
            "login..com",
            "-lead.example",
        ] {
            assert!(
                AuthConfig::public_client(CLIENT)
                    .with_authority_host(hostile)
                    .is_err(),
                "accepted a hostile authority host: {hostile:?}"
            );
        }
        // POSITIVE CONTROL: real hosts, including a sovereign cloud, must pass —
        // a check that refuses everything is a client that only works in one
        // cloud.
        for good in [
            DEFAULT_AUTHORITY_HOST,
            "login.microsoftonline.us",
            "login.partner.microsoftonline.cn",
        ] {
            assert!(AuthConfig::public_client(CLIENT)
                .with_authority_host(good)
                .is_ok());
        }
    }

    /// The tenant lands in a URL path. Catches joining it unchecked, which lets a
    /// config value end the path early or climb out of it.
    #[test]
    fn a_tenant_that_is_not_a_bare_path_segment_is_refused() {
        for hostile in ["../../evil", "common/x", "", "..", "a?b", "a#b", "a%2f"] {
            assert!(
                AuthConfig::public_client(CLIENT).with_tenant(hostile).is_err(),
                "accepted a hostile tenant: {hostile:?}"
            );
        }
        let ok = AuthConfig::public_client(CLIENT)
            .with_tenant("contoso.onmicrosoft.com")
            .expect("a real tenant must pass");
        assert_eq!(
            ok.token_url(),
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
        );
    }

    /// Direct coverage of the origin check, since it is the function that
    /// decides where the credential goes and every branch of it is a real attack.
    #[test]
    fn the_origin_check_compares_hosts_rather_than_substrings() {
        let host = DEFAULT_AUTHORITY_HOST;
        for hostile in [
            "https://login.microsoftonline.com.evil.example/token",
            "https://login.microsoftonline.com@evil.example/token",
            "https://user@login.microsoftonline.com@evil.example/token",
            "http://login.microsoftonline.com/token",
            "//login.microsoftonline.com/token",
            "https://evil.example/login.microsoftonline.com",
            "https://login.microsoftonline.com:8443/token",
        ] {
            assert!(
                !on_the_authority(hostile, host),
                "followed a hostile URL: {hostile}"
            );
        }
        assert!(on_the_authority(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            host
        ));
        assert!(on_the_authority(
            "https://LOGIN.microsoftonline.COM:443/common/oauth2/v2.0/token",
            host
        ));
    }

    // =======================================================================
    // Reading a reply
    // =======================================================================

    /// `expires_in` may arrive as a string. Catches `as_u64().unwrap_or(0)`,
    /// which produces a token that is expired on arrival — so every single call
    /// refreshes, which spends a single-use credential at the rate the daemon
    /// makes requests. That is the rotation storm reached without any race at
    /// all, and it looks like "auth is just slow" in a log.
    #[test]
    fn a_string_expires_in_is_honoured_rather_than_defaulted() {
        let rig = Rig::new(vec![Ok(TokenReply::new(
            200,
            br#"{"access_token":"ACCESS-2","expires_in":"3600","refresh_token":"R2"}"#.to_vec(),
        ))]);
        let cache = rig.signed_in("REFRESH-1");

        cache.token().expect("first");
        for _ in 0..3 {
            cache.token().expect("cached");
        }
        assert_eq!(cache.refreshes(), 1, "the lifetime was not read");
    }

    /// An absent lifetime is refused rather than assumed. Catches both defaults:
    /// zero refreshes on every call, and an hour hands out a token that may
    /// already be dead — a 401 storm mid-round with nothing to explain it.
    #[test]
    fn an_absent_expires_in_is_refused() {
        let rig = Rig::new(vec![Ok(TokenReply::new(
            200,
            br#"{"access_token":"ACCESS-2","refresh_token":"R2"}"#.to_vec(),
        ))]);
        let cache = rig.signed_in("REFRESH-1");

        assert_eq!(
            cache.token(),
            Err(AuthError::Malformed("no usable expires_in in the reply"))
        );
    }

    /// The identity platform answers `authorization_pending` with HTTP 400.
    /// Catches judging the status before the body, which turns "the user has not
    /// clicked yet" into a hard failure and ends every sign-in on its first poll.
    #[test]
    fn an_error_body_is_read_before_the_status() {
        let pending = TokenReply::new(400, br#"{"error":"authorization_pending"}"#.to_vec());
        assert_eq!(
            read_token_reply(&pending).expect_err("400 is not a token"),
            AuthError::AuthorizationPending
        );
        // And a non-2xx with nothing to name is still refused, rather than
        // parsed as a token response.
        let empty = TokenReply::new(503, b"{}".to_vec());
        assert_eq!(
            read_token_reply(&empty).expect_err("503 is not a token"),
            AuthError::HttpStatus(503)
        );
    }

    /// A `+` in a credential must reach the wire as `%2B`. Catches raw
    /// concatenation: the service decodes an unescaped `+` in a form body as a
    /// space, so a valid refresh token arrives corrupted and is refused as
    /// `invalid_grant` — which reads exactly like the concurrency bug this
    /// module is about, and is not it.
    #[test]
    fn a_credential_containing_form_metacharacters_is_escaped() {
        let rig = Rig::new(vec![ok_tokens("A2", "R2", 3600)]);
        let cache = rig.signed_in("aa+bb/cc=dd&ee");
        cache.token().expect("token");

        let body = &rig.script.seen()[0].2;
        assert!(
            body.contains("refresh_token=aa%2Bbb%2Fcc%3Ddd%26ee"),
            "the credential was not escaped: {body}"
        );
        // POSITIVE CONTROL: the escaping is not so eager that the form itself is
        // unreadable.
        assert!(body.contains("&grant_type=refresh_token&"));
    }
}
