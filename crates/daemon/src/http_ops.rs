//! `vahta http`: one HTTPS request, made by the daemon, with a secret put into
//! a header or a query value.
//!
//! The client never holds a value: it sends templates (`Authorization: Bearer
//! {API_KEY}`, `--query key={API_KEY}`), and the daemon fills them in, sends
//! the request and returns the response with every value taken out.
//!
//! **Where a value may go.** Only where a `{NAME}` placeholder of a declared
//! secret stands in a header value or a query value. Never the URL path: a path
//! is logged by servers, proxies and CDNs everywhere, and a client that put a
//! key there would have shown it to all of them. Never the body: a body is
//! what servers echo back, validation errors and all, and the scrubber is the
//! last line, not the first; a provider that needs its key in a JSON body is a
//! later decision (an explicit body placeholder, by the person's approval).
//! A `{NAME}` anywhere else is refused, not sent.
//!
//! **Host binding.** A secret may be sent only to hosts its approved rule set
//! names (`Network::Hosts`): the URL's host equal to a rule's host, or beneath
//! it when the rule has `subdomains`; the URL's port equal to the rule's, or any
//! when the rule has none (the URL's port is 443 unless it says otherwise). No
//! rule set, no network rule (`Network::None`), and the application's own
//! network (`Network::App`, whatever a format 1 binding or a `vahta bind` of
//! commands approved) are all refused before any window: the person has not
//! said where this secret may go. All the secrets of one request must pass.
//! Redirects are followed by the client only on the same host and port.
//!
//! **Values.** The same path as `vahta run`: [`run_ops::unlock_values`] (a
//! session that covers the names, else a window for this one request; each-use
//! secrets always ask; a delegated session cannot ask for more).
//!
//! **The response** has the values (and their encoded forms) taken out of the
//! body and the headers, by the scrubber `vahta run` uses; headers that carry
//! credentials are dropped by the client. The journal gets `http_request`: the
//! names, method, host, status and size; never the path, the query or a value.

use std::time::Duration;

use vahta_net::{Url, encode_component};
use vahta_vault::{Network, SecretValue, Vault};

use crate::journal::Entry;
use crate::ops::{Ctx, Flow, check_name, error, from_vault, refused, refused_names, unknown_name};
use crate::protocol::{ClientReply, NameIssue, RefusalKind, b64_decode};
use crate::run_ops::{self, Unlock};
use crate::scrub::Scrubber;

/// The largest request body, after base64 (it must fit in a frame).
const MAX_BODY: usize = 512 * 1024;
/// The response body kept when the client does not say.
const DEFAULT_RESPONSE: u64 = 4 << 20;
const MAX_RESPONSE: u64 = 8 << 20;
const MAX_TIMEOUT_SECS: u32 = 120;
const MAX_HEADERS: usize = 64;

/// What an `Http` request asked for.
pub(crate) struct HttpArgs {
    pub cwd: String,
    pub method: String,
    pub url: String,
    pub names: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
    pub body: Option<String>,
    pub max_response: Option<u64>,
    pub timeout_secs: Option<u32>,
    pub label: Option<String>,
    /// `--vault DIR`: the vault's project, when it is not the caller's.
    pub vault: Option<String>,
}

/// The reply and the body that follows it.
pub(crate) struct Answer {
    pub reply: ClientReply,
    pub body: Vec<u8>,
}

/// A request as the transport takes it.
#[cfg_attr(not(feature = "http"), allow(dead_code))]
struct Outgoing {
    allow_private: bool,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    max_response: usize,
    timeout: Option<Duration>,
}

#[cfg_attr(not(feature = "http"), allow(dead_code))]
struct Incoming {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    truncated: bool,
    redirect_stopped: Option<String>,
}

#[cfg(not(feature = "http"))]
fn transport(_: Outgoing) -> Result<Incoming, String> {
    Err(
        "this build of vahta has no network support (it was built without the `http` feature)"
            .to_string(),
    )
}

#[cfg(feature = "http")]
fn transport(out: Outgoing) -> Result<Incoming, String> {
    let method = vahta_net::Method::parse(&out.method).ok_or("the method is not allowed")?;
    #[allow(unused_mut)]
    let mut options = vahta_net::Options {
        allow_private: out.allow_private,
        ..vahta_net::Options::default()
    };
    if let Some(t) = out.timeout {
        options.total_timeout = t;
    }
    #[cfg(feature = "test-surface")]
    {
        options.extra_root_pem = crate::testing::http_root();
    }
    let request = vahta_net::Request {
        method,
        url: out.url,
        headers: out.headers,
        body: out.body,
        max_response: out.max_response,
    };
    let r = vahta_net::fetch(&request, &options).map_err(|e| e.to_string())?;
    Ok(Incoming {
        status: r.status,
        headers: r.headers,
        body: r.body,
        truncated: r.truncated,
        redirect_stopped: r.redirect_stopped,
    })
}

/// A template cut at its placeholders.
#[derive(Debug, PartialEq, Eq)]
enum Piece<'a> {
    Text(&'a str),
    /// The index in the declared names.
    Secret(usize),
}

/// Cut `template` at every `{NAME}` of a declared name. Any other brace text
/// is left in the text as it is.
fn pieces<'a>(template: &'a str, names: &[String]) -> Vec<Piece<'a>> {
    let mut out = Vec::new();
    let mut rest = template;
    let mut start = 0;
    while let Some(open) = rest[start..].find('{') {
        let open = start + open;
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        let close = open + close;
        match names.iter().position(|n| n == &rest[open + 1..close]) {
            Some(i) => {
                if open > 0 {
                    out.push(Piece::Text(&rest[..open]));
                }
                out.push(Piece::Secret(i));
                rest = &rest[close + 1..];
                start = 0;
            }
            None => start = open + 1,
        }
    }
    if !rest.is_empty() {
        out.push(Piece::Text(rest));
    }
    out
}

fn mentions(text: &str, names: &[String]) -> bool {
    pieces(text, names)
        .iter()
        .any(|p| matches!(p, Piece::Secret(_)))
}

/// `template` with its placeholders filled; the text of a value is UTF-8.
fn fill(template: &str, names: &[String], values: &[(String, SecretValue)]) -> Option<String> {
    let mut out = String::new();
    for piece in pieces(template, names) {
        match piece {
            Piece::Text(t) => out.push_str(t),
            Piece::Secret(i) => {
                let (_, v) = values.iter().find(|(n, _)| n == &names[i])?;
                out.push_str(std::str::from_utf8(v.expose()).ok()?);
            }
        }
    }
    Some(out)
}

/// Whether `url` is a destination one of `rules` approves.
pub(crate) fn host_allowed(rules: &[vahta_vault::HostRule], url: &Url) -> bool {
    rules.iter().any(|r| {
        let port_ok = r.port.is_none_or(|p| p == url.port);
        let ip = r.host.parse::<std::net::IpAddr>().is_ok();
        let host_ok = url.host == r.host
            || (r.subdomains && !ip && url.host.ends_with(&format!(".{}", r.host)));
        port_ok && host_ok
    })
}

/// Whether the rule that approves `url` lets its host resolve to a private
/// address (`private:HOST`).
fn private_allowed(rules: &[vahta_vault::HostRule], url: &Url) -> bool {
    rules
        .iter()
        .filter(|r| host_allowed(std::slice::from_ref(r), url))
        .all(|r| r.allows_private())
}

/// `host`, or `host:port` for a port that is not 443.
fn shown(url: &Url) -> String {
    let host = if url.host.contains(':') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    if url.port == vahta_net::DEFAULT_PORT {
        host
    } else {
        format!("{host}:{}", url.port)
    }
}

/// The hook's question (`CheckHttp`): would a request to `url` with these
/// secrets pass the host lists their rule sets approve? `Allowed` only when the
/// build can make requests, the URL is one `vahta http` accepts with no secret
/// in it, the vault is found and verified, and every name is a session-tier
/// secret whose approved network rule lists a host matching the URL (the very
/// function a request uses). Anything else is `NoOpinion`, and the request
/// itself says why. Nothing is journaled or opened.
pub(crate) fn check(
    ctx: &Ctx<'_>,
    cwd: &str,
    url: &str,
    names: Vec<String>,
    vault: Option<String>,
) -> ClientReply {
    let allowed = (|| -> Option<()> {
        if !cfg!(feature = "http") || names.is_empty() || mentions(url, &names) {
            return None;
        }
        let target = Url::parse(url).ok()?;
        let found = crate::remote::Target::for_check(ctx, cwd, vault.as_deref()).ok()?;
        let peek = Vault::peek(&found.vault_path).ok()?;
        peek.verified(ctx.store()).ok()?;
        let peek = found.view(peek);
        names
            .iter()
            .all(|n| {
                let session = peek
                    .entries
                    .iter()
                    .find(|e| &e.name == n)
                    .is_some_and(|e| e.tier != vahta_vault::Tier::EachUse);
                let hosts = peek.bindings.iter().find(|b| &b.name == n);
                session
                    && matches!(hosts.map(|r| &r.network),
                        Some(Network::Hosts(h)) if host_allowed(h, &target))
            })
            .then_some(())
    })();
    match allowed {
        Some(()) => ClientReply::Allowed {},
        None => ClientReply::NoOpinion {},
    }
}

fn issues(names: &[String], why: RefusalKind) -> Vec<NameIssue> {
    names
        .iter()
        .map(|n| NameIssue {
            name: n.clone(),
            why,
        })
        .collect()
}

pub(crate) fn http(ctx: &Ctx<'_>, args: HttpArgs) -> Flow<Answer> {
    if !cfg!(feature = "http") {
        return Err(error(
            "this build of vahta has no network support (it was built without the `http` feature)",
        ));
    }
    let HttpArgs {
        cwd,
        method,
        url,
        names,
        headers,
        query,
        body,
        max_response,
        timeout_secs,
        label,
        vault,
    } = args;

    // --- The request, checked before anything is opened. -------------------
    let method = method.to_ascii_uppercase();
    if !matches!(
        method.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    ) {
        return Err(error(
            "the method must be GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS",
        ));
    }
    let mut declared: Vec<String> = Vec::new();
    for n in names {
        check_name(&n)?;
        if !declared.contains(&n) {
            declared.push(n);
        }
    }
    if declared.is_empty() {
        return Err(refused(
            RefusalKind::NothingToDo,
            "name the secret with --secret NAME, and put {NAME} in a header or query value",
        ));
    }
    if mentions(&url, &declared) {
        return Err(error(
            "a secret cannot go in the URL: put {NAME} in a header value or a --query value",
        ));
    }
    let mut target = Url::parse(&url).map_err(|e| error(e.to_string()))?;
    if headers.len() > MAX_HEADERS || query.len() > MAX_HEADERS {
        return Err(error("too many headers or query values"));
    }
    for (name, _) in headers.iter().chain(query.iter()) {
        if mentions(name, &declared) {
            return Err(error(
                "a secret goes in a header's value or a query value, not in a name",
            ));
        }
    }
    let body = match body {
        Some(text) => {
            if text.len() > MAX_BODY {
                return Err(error("the body is too large (512 KiB at most)"));
            }
            let bytes = b64_decode(&text).ok_or_else(|| error("the body is not valid"))?;
            if std::str::from_utf8(&bytes).is_ok_and(|t| mentions(t, &declared)) {
                return Err(error(
                    "a secret is not put in the body (servers echo bodies back): put {NAME} in a \
                     header value or a --query value",
                ));
            }
            bytes
        }
        None => Vec::new(),
    };
    let mut used = vec![false; declared.len()];
    for (_, value) in headers.iter().chain(query.iter()) {
        for piece in pieces(value, &declared) {
            if let Piece::Secret(i) = piece {
                used[i] = true;
            }
        }
    }
    if let Some(i) = used.iter().position(|u| !u) {
        return Err(error(format!(
            "{} is named with --secret but no header or query value has {{{}}}",
            declared[i], declared[i]
        )));
    }

    // --- The vault, and where each secret is approved to go. ----------------
    let found = crate::remote::Target::resolve(ctx, &cwd, vault.as_deref())?;
    let (project, vault_path) = (found.project.clone(), found.vault_path.clone());
    crate::guard_ops::note_project(ctx, &project.root);
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    peek.verified_for_unlock(ctx.store()).map_err(from_vault)?;
    let peek = found.view(peek);
    for n in &declared {
        if !peek.entries.iter().any(|e| &e.name == n) {
            return Err(unknown_name(n));
        }
    }
    // A session limited to a role: the role must give `http` at all, before
    // anything is said about hosts.
    let found_session = run_ops::find_session(ctx, &peek, found.used_from.as_deref())?;
    let role = crate::role_ops::active(ctx, found_session.as_ref().map(|f| f.0.as_str()))?;
    if let Some(a) = &role {
        crate::role_ops::require_action(ctx, a, vahta_vault::Action::Http, &peek, &declared)?;
    }
    let destination = shown(&target);
    let mut lines: Vec<String> = Vec::new();
    let mut failing: Vec<String> = Vec::new();
    for n in &declared {
        let rules = peek.bindings.iter().find(|b| &b.name == n);
        match rules.map(|r| &r.network) {
            Some(Network::Hosts(hosts)) if host_allowed(hosts, &target) => {}
            Some(Network::Hosts(hosts)) => {
                let list: Vec<&str> = hosts.iter().map(|h| h.text.as_str()).collect();
                lines.push(format!(
                    "{n} is not approved for {destination} (it may go to: {})",
                    list.join(", ")
                ));
                failing.push(n.clone());
            }
            Some(Network::App) => {
                lines.push(format!(
                    "{n} is approved for the application's own network use, not for a list of \
                     hosts, and `vahta http` sends only to a list; the person can approve hosts \
                     with `vahta bind {n} --net hosts:HOST`"
                ));
                failing.push(n.clone());
            }
            Some(Network::None) => {
                lines.push(format!(
                    "{n} is approved for no network use; the person can approve hosts with \
                     `vahta bind {n} --net hosts:HOST`"
                ));
                failing.push(n.clone());
            }
            None => {
                lines.push(format!(
                    "{n} has no approved rules, so it is not bound to any host; propose one with \
                     `vahta bind {n} --net hosts:HOST` and the person approves it"
                ));
                failing.push(n.clone());
            }
        }
    }
    if !failing.is_empty() {
        let no_rules = failing
            .iter()
            .all(|n| !peek.bindings.iter().any(|b| &b.name == n));
        crate::report::rule_refusal(ctx, &failing, None, no_rules);
        ctx.journal(
            Entry::new("http_refused")
                .vault(&peek.vault_id)
                .names(&failing)
                .http(&method, &destination, None, None)
                .result("refused", Some("host_not_allowed")),
        );
        return Err(refused_names(
            RefusalKind::HostNotAllowed,
            format!("{}. Nothing was sent.", lines.join("; ")),
            issues(&failing, RefusalKind::HostNotAllowed),
        ));
    }

    // --- The values: the session or the window, as for a run. ---------------
    if let Some(a) = &role {
        crate::role_ops::narrow_http(ctx, a, &peek, &declared, &destination, |hosts| {
            host_allowed(hosts, &target)
        })?;
        crate::role_ops::check_uses(ctx, a, &peek, &declared)?;
        crate::role_ops::ask_use(
            ctx,
            a,
            &project,
            &vault_path,
            &peek,
            &declared,
            vec![format!("Request: {method} {destination}")],
        )?;
    }
    let (values, via) = run_ops::unlock_values(
        ctx,
        Unlock {
            project: &project,
            vault_path: &vault_path,
            peek: &peek,
            names: &declared,
            found: found_session,
            title: "Send a request",
            lines: vec![
                format!("Secrets: {}", declared.join(", ")),
                format!("Request: {method} {destination}"),
                "This request only; no session is opened.".to_string(),
            ],
            label: label.as_deref(),
            refused_event: "http_refused",
            nothing: "nothing was sent",
            action: vahta_auth::Action::Http {
                names: declared.clone(),
                host: destination.clone(),
            },
            used_from: found.used_from.as_deref(),
        },
    )?;

    if let Some(a) = &role {
        crate::role_ops::note_use(ctx, a);
    }
    let role_name = role.as_ref().map(|a| a.role.name.clone());

    // --- Fill in, send, scrub. ----------------------------------------------
    let unusable = || error("a secret's value cannot be put in a header or a query value");
    let mut out_headers = Vec::with_capacity(headers.len());
    for (name, value) in &headers {
        out_headers.push((
            name.clone(),
            fill(value, &declared, &values).ok_or_else(unusable)?,
        ));
    }
    let mut extra = String::new();
    for (key, value) in &query {
        let value = fill(value, &declared, &values).ok_or_else(unusable)?;
        if !extra.is_empty() {
            extra.push('&');
        }
        extra.push_str(&encode_component(key.as_bytes()));
        extra.push('=');
        extra.push_str(&encode_component(value.as_bytes()));
    }
    if !extra.is_empty() {
        target.query = Some(match target.query.take() {
            Some(q) if !q.is_empty() => format!("{q}&{extra}"),
            _ => extra,
        });
    }
    let held: Vec<(String, Vec<u8>)> = values
        .iter()
        .map(|(n, v)| (n.clone(), v.expose().to_vec()))
        .collect();
    drop(values);
    let scrub = |bytes: &[u8]| -> Vec<u8> {
        let mut s = Scrubber::with_encodings(held.clone());
        let mut out = s.push(bytes);
        out.extend(s.finish());
        out
    };
    let via_text = match &via {
        Some(id) => format!("session {id}"),
        None => "password".to_string(),
    };
    // Private resolution only when every secret's rule says so.
    let allow_private = declared.iter().all(|n| {
        matches!(peek.bindings.iter().find(|b| &b.name == n).map(|b| &b.network),
            Some(Network::Hosts(h)) if private_allowed(h, &target))
    });
    let sent = transport(Outgoing {
        allow_private,
        method: method.clone(),
        url: target.to_url_string(),
        headers: out_headers,
        body,
        max_response: max_response
            .unwrap_or(DEFAULT_RESPONSE)
            .clamp(1, MAX_RESPONSE) as usize,
        timeout: timeout_secs.map(|s| Duration::from_secs(u64::from(s.clamp(1, MAX_TIMEOUT_SECS)))),
    });
    let incoming = match sent {
        Ok(r) => r,
        Err(message) => {
            ctx.journal(
                Entry::new("http_request")
                    .vault(&peek.vault_id)
                    .names(&declared)
                    .role(role_name.as_deref())
                    .http(&method, &destination, None, None)
                    .result("error", Some(&format!("{message}; {via_text}"))),
            );
            let clean = String::from_utf8_lossy(&scrub(message.as_bytes())).into_owned();
            return Err(error(clean));
        }
    };
    let text = |s: &str| String::from_utf8_lossy(&scrub(s.as_bytes())).into_owned();
    let body = scrub(&incoming.body);
    ctx.journal(
        Entry::new("http_request")
            .vault(&peek.vault_id)
            .names(&declared)
            .role(role_name.as_deref())
            .http(
                &method,
                &destination,
                Some(incoming.status),
                Some(body.len() as u64),
            )
            .result("ok", Some(&via_text)),
    );
    Ok(Answer {
        reply: ClientReply::HttpResponse {
            status: incoming.status,
            headers: incoming
                .headers
                .iter()
                .map(|(n, v)| (n.clone(), text(v)))
                .collect(),
            truncated: incoming.truncated,
            redirect_stopped: incoming.redirect_stopped.as_deref().map(text),
        },
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn only_declared_names_are_placeholders() {
        let n = names(&["KEY", "OTHER"]);
        assert_eq!(
            pieces("Bearer {KEY}", &n),
            [Piece::Text("Bearer "), Piece::Secret(0)]
        );
        assert_eq!(
            pieces("{KEY}{OTHER}x{KEY", &n),
            [Piece::Secret(0), Piece::Secret(1), Piece::Text("x{KEY")]
        );
        assert_eq!(
            pieces("{nope} {\"a\":1}", &n),
            [Piece::Text("{nope} {\"a\":1}")]
        );
        assert!(!mentions("{KEYS}", &n) && mentions("a{OTHER}", &n));
        assert!(pieces("", &n).is_empty());
    }

    fn rule(host: &str, subdomains: bool, port: Option<u16>) -> vahta_vault::HostRule {
        vahta_vault::HostRule {
            text: host.to_string(),
            host: host.to_string(),
            subdomains,
            port,
        }
    }

    #[test]
    fn a_host_rule_matches_the_host_the_port_and_subdomains_when_asked() {
        let u = |s: &str| Url::parse(s).unwrap();
        let exact = [rule("api.example.com", false, None)];
        assert!(host_allowed(&exact, &u("https://api.example.com/x")));
        assert!(host_allowed(&exact, &u("https://API.example.com:8443/x")));
        assert!(!host_allowed(&exact, &u("https://v2.api.example.com/")));
        assert!(!host_allowed(&exact, &u("https://example.com/")));
        assert!(!host_allowed(&exact, &u("https://evilapi.example.com/")));
        assert!(!host_allowed(
            &exact,
            &u("https://api.example.com.evil.com/")
        ));
        let sub = [rule("example.com", true, Some(443))];
        assert!(host_allowed(&sub, &u("https://example.com/")));
        assert!(host_allowed(&sub, &u("https://a.b.example.com/")));
        assert!(!host_allowed(&sub, &u("https://notexample.com/")));
        assert!(!host_allowed(&sub, &u("https://a.example.com:444/")));
        let ip = [rule("127.0.0.1", true, None)];
        assert!(host_allowed(&ip, &u("https://127.0.0.1/")));
        assert!(!host_allowed(&ip, &u("https://a.127.0.0.1.nip.io/")));
    }
}
