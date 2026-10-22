//! The HTTPS client (feature `client`). See the crate docs for the policy.

use std::fmt;
use std::io::Read;
use std::time::{Duration, Instant};

use crate::url::{Url, UrlError};

/// The most a response may be capped at, whatever a caller asks.
pub const MAX_RESPONSE_LIMIT: usize = 8 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl Method {
    pub fn parse(text: &str) -> Option<Method> {
        Some(match text.to_ascii_uppercase().as_str() {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "DELETE" => Method::Delete,
            "OPTIONS" => Method::Options,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
        }
    }
}

/// A finished request. The URL is a string so that the client parses it with
/// [`Url`], the same parser the caller checked the host with.
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The most response body to keep (clamped to [`MAX_RESPONSE_LIMIT`]).
    pub max_response: usize,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub connect_timeout: Duration,
    /// For the whole call, redirects included.
    pub total_timeout: Duration,
    /// How many same-host redirects are followed.
    pub max_redirects: u32,
    /// Connect to a name that resolves to a loopback, private, link-local or
    /// unspecified address. Off: such an answer is refused (DNS rebinding).
    pub allow_private: bool,
    /// Trust this PEM certificate instead of the public roots (tests only).
    #[cfg(feature = "test-roots")]
    pub extra_root_pem: Option<Vec<u8>>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            connect_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(30),
            max_redirects: 3,
            allow_private: false,
            #[cfg(feature = "test-roots")]
            extra_root_pem: None,
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// Lowercase names; the headers that carry credentials are left out.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The body was cut at the cap.
    pub truncated: bool,
    /// Set when a redirect was not followed, and why. The response is then the
    /// redirect itself.
    pub redirect_stopped: Option<String>,
}

/// Why no response came. The text never carries the URL.
#[derive(Debug)]
pub enum Error {
    Url(UrlError),
    /// A header the client will not send.
    Header(String),
    Timeout,
    Connect(String),
    Tls(String),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Url(e) => e.fmt(f),
            Error::Header(m) => write!(f, "header refused: {m}"),
            Error::Timeout => f.write_str("the request timed out"),
            Error::Connect(m) => write!(f, "cannot connect: {m}"),
            Error::Tls(m) => write!(f, "TLS error: {m}"),
            Error::Other(m) => write!(f, "the request failed: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<UrlError> for Error {
    fn from(e: UrlError) -> Error {
        Error::Url(e)
    }
}

/// Headers the client sets itself or that change how the connection works.
fn forbidden_request_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "te"
            | "trailer"
            | "expect"
            | "keep-alive"
    ) || name.starts_with("proxy-")
}

/// Response headers that carry credentials or session state: never returned.
fn credential_response_header(name: &str) -> bool {
    name == "set-cookie"
        || name == "set-cookie2"
        || name.contains("authorization")
        || name.contains("api-key")
        || name.contains("apikey")
        || name.contains("token")
        || name.contains("secret")
        || name.contains("session")
}

fn check_headers(headers: &[(String, String)]) -> Result<(), Error> {
    for (name, value) in headers {
        let token = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        if !token {
            return Err(Error::Header("a header name is not a token".to_string()));
        }
        if forbidden_request_header(&name.to_ascii_lowercase()) {
            return Err(Error::Header(format!(
                "{} is set by the client",
                name.to_ascii_lowercase()
            )));
        }
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(Error::Header(
                "a header value has a control character".to_string(),
            ));
        }
    }
    Ok(())
}

fn agent(options: &Options, remaining: Duration) -> Result<ureq::Agent, Error> {
    let tls = ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::Rustls);
    #[cfg(feature = "test-roots")]
    let tls = match &options.extra_root_pem {
        Some(pem) => {
            let cert = ureq::tls::Certificate::from_pem(pem)
                .map_err(|_| Error::Tls("the extra test root is not a certificate".to_string()))?;
            tls.root_certs(ureq::tls::RootCerts::new_with_certs(&[cert]))
        }
        None => tls,
    };
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        // Redirects are the caller's loop below, not the library's.
        .max_redirects(0)
        .max_redirects_will_error(false)
        .proxy(None)
        .tls_config(tls.build())
        .timeout_connect(Some(options.connect_timeout.min(remaining)))
        .timeout_global(Some(remaining))
        .user_agent("vahta-http")
        .build();
    Ok(ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::new(),
        PublicOnly {
            inner: ureq::unversioned::resolver::DefaultResolver::default(),
            allow_private: options.allow_private,
        },
    ))
}

/// The refusal the resolver gives, carried through ureq's I/O error.
#[derive(Debug)]
struct PrivateAnswer(String);

impl fmt::Display for PrivateAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PrivateAnswer {}

/// The system resolver, minus the addresses a public name must not lead to
/// (unless the rule allowed them). Connecting uses what this returns, so the
/// answer that was checked is the one connected to.
#[derive(Debug)]
struct PublicOnly {
    inner: ureq::unversioned::resolver::DefaultResolver,
    allow_private: bool,
}

impl ureq::unversioned::resolver::Resolver for PublicOnly {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let all = self.inner.resolve(uri, config, timeout)?;
        if self.allow_private {
            return Ok(all);
        }
        let mut kept = self.empty();
        let mut first_refused = None;
        for addr in all.iter() {
            match crate::private_kind(addr.ip()) {
                None => kept.push(*addr),
                Some(kind) => {
                    first_refused.get_or_insert((addr.ip(), kind));
                }
            }
        }
        match (kept.is_empty(), first_refused) {
            (true, Some((ip, kind))) => {
                let host = uri.host().unwrap_or("the host");
                let text = crate::refusal_text(host, ip, kind);
                Err(ureq::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    PrivateAnswer(text),
                )))
            }
            _ => Ok(kept),
        }
    }
}

fn map_error(e: ureq::Error) -> Error {
    match e {
        ureq::Error::Timeout(_) => Error::Timeout,
        ureq::Error::HostNotFound => Error::Connect("the host name was not found".to_string()),
        // rustls reports a bad certificate as invalid data from the socket.
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::InvalidData => Error::Tls(
            io.get_ref()
                .map_or_else(|| "invalid data".to_string(), |inner| inner.to_string()),
        ),
        ureq::Error::Io(io) => match io.get_ref().and_then(|e| e.downcast_ref::<PrivateAnswer>()) {
            Some(refusal) => Error::Connect(refusal.0.clone()),
            None => Error::Connect(format!("{:?}", io.kind())),
        },
        ureq::Error::Rustls(e) => Error::Tls(e.to_string()),
        ureq::Error::ConnectionFailed => Error::Connect("the connection failed".to_string()),
        _ => Error::Other("an HTTP error".to_string()),
    }
}

/// Send `request`, following at most `options.max_redirects` redirects to the
/// same host and port. A redirect elsewhere (another host or port, or `http`)
/// is not followed: the redirect itself comes back with `redirect_stopped` set.
pub fn fetch(request: &Request, options: &Options) -> Result<Response, Error> {
    check_headers(&request.headers)?;
    let limit = request.max_response.min(MAX_RESPONSE_LIMIT);
    let start = Instant::now();
    let mut url = Url::parse(&request.url)?;
    let origin = (url.host.clone(), url.port);
    let mut method = request.method;
    let mut body: &[u8] = &request.body;
    let mut hops = 0;
    loop {
        let remaining = options
            .total_timeout
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or(Error::Timeout)?;
        let agent = agent(options, remaining)?;
        let mut builder = ureq::http::Request::builder()
            .method(method.as_str())
            .uri(url.to_url_string());
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let built = builder
            .body(body)
            .map_err(|_| Error::Header("a header is not valid".to_string()))?;
        let response = agent.run(built).map_err(map_error)?;
        let status = response.status().as_u16();
        let (parts, body_reader) = response.into_parts();
        let location = parts
            .headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if matches!(status, 301 | 302 | 303 | 307 | 308)
            && let Some(location) = location
        {
            match url.join(&location) {
                Ok(next) if (next.host.clone(), next.port) == origin => {
                    if hops < options.max_redirects {
                        hops += 1;
                        if status == 303 || (matches!(status, 301 | 302) && method != Method::Head)
                        {
                            method = Method::Get;
                            body = &[];
                        }
                        url = next;
                        continue;
                    }
                    return finish(
                        status,
                        &parts,
                        body_reader,
                        limit,
                        Some("too many redirects".to_string()),
                    );
                }
                Ok(next) => {
                    let to = if next.port == crate::url::DEFAULT_PORT {
                        next.host
                    } else {
                        format!("{}:{}", next.host, next.port)
                    };
                    return finish(
                        status,
                        &parts,
                        body_reader,
                        limit,
                        Some(format!("a redirect to {to} was not followed")),
                    );
                }
                Err(e) => {
                    return finish(
                        status,
                        &parts,
                        body_reader,
                        limit,
                        Some(format!("a redirect was not followed: {e}")),
                    );
                }
            }
        }
        return finish(status, &parts, body_reader, limit, None);
    }
}

fn finish(
    status: u16,
    parts: &ureq::http::response::Parts,
    body: ureq::Body,
    limit: usize,
    redirect_stopped: Option<String>,
) -> Result<Response, Error> {
    let mut headers = Vec::new();
    for (name, value) in &parts.headers {
        let name = name.as_str().to_ascii_lowercase();
        if credential_response_header(&name) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            headers.push((name, v.to_string()));
        }
    }
    let mut data = Vec::new();
    let mut reader = body.into_reader().take(limit as u64 + 1);
    reader.read_to_end(&mut data).map_err(|e| match e.kind() {
        std::io::ErrorKind::TimedOut => Error::Timeout,
        kind => Error::Connect(format!("{kind:?}")),
    })?;
    let truncated = data.len() > limit;
    data.truncate(limit);
    Ok(Response {
        status,
        headers,
        body: data,
        truncated,
        redirect_stopped,
    })
}
