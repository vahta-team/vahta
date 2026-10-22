//! Vahta's only network code.
//!
//! `vahta http` is the one operation in Vahta that opens a connection, and it
//! is the person who binds a secret to the hosts it may go to. Everything that
//! can open a socket is in this crate, behind the `client` feature, so that a
//! build without it (`--no-default-features` of the `vahta` binary) contains no
//! HTTP or TLS client at all, and CI can check that no other crate depends on
//! one.
//!
//! * [`Url`] (always built, no dependencies) is the strict `https` URL parser.
//!   The daemon checks a request's host with it and the client connects to what
//!   it parsed, so the two cannot disagree about where a URL points.
//! * [`fetch`] (feature `client`) is a deliberately small HTTPS client: https
//!   only, certificates checked against the Mozilla root store (`webpki-roots`)
//!   with rustls and `ring`, **no redirects followed by the library** (this
//!   crate follows at most [`Options::max_redirects`] itself, and only to the
//!   same host and port), no cookies, **no proxy** (the `*_PROXY` variables are
//!   not read: a proxy would see the request in the clear or break the
//!   host binding), timeouts, and a cap on the response. Response headers that
//!   carry credentials are dropped.
//!
//! Nothing here knows about secrets: a caller hands it a finished request.

mod private;
mod url;
pub use private::{private_kind, refusal_text};
pub use url::{DEFAULT_PORT, Url, UrlError, encode_component};

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
pub use client::{Error, Method, Options, Request, Response, fetch};

#[cfg(feature = "test-roots")]
pub mod test_server;
