//! The client against an in-process HTTPS server (see `test_server`).
//! The values here are made up and assembled at run time.

use vahta_net::test_server::{Reply, TestServer};
use vahta_net::{Error, Method, Options, Request, fetch};

fn options() -> Options {
    Options {
        extra_root_pem: Some(vahta_net::test_server::CA_PEM.to_vec()),
        ..Options::default()
    }
}

fn get(url: String) -> Request {
    Request {
        method: Method::Get,
        url,
        headers: Vec::new(),
        body: Vec::new(),
        max_response: 1 << 20,
    }
}

fn token() -> String {
    ["tok", "en", "-", "abc", "123"].concat()
}

#[test]
fn a_get_returns_status_headers_and_body_and_sends_the_header() {
    let want = token();
    let server = TestServer::start(move |seen| {
        let ok = seen.header("x-api-key") == Some(want.as_str());
        Reply {
            status: 200,
            headers: vec![("x-fine".into(), "yes".into())],
            body: if ok { b"yes".to_vec() } else { b"no".to_vec() },
        }
    });
    let mut req = get(format!("https://localhost:{}/p?a=1", server.port));
    req.headers.push(("X-Api-Key".into(), token()));
    let resp = fetch(&req, &options()).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"yes");
    assert!(resp.headers.contains(&("x-fine".into(), "yes".into())));
    assert_eq!(server.seen()[0].target, "/p?a=1");
}

#[test]
fn credentials_in_response_headers_are_dropped() {
    let server = TestServer::start(|_| Reply {
        status: 200,
        headers: vec![
            ("Set-Cookie".into(), "a=b".into()),
            ("X-Auth-Token".into(), "t".into()),
            ("Authorization".into(), "x".into()),
            ("Content-Type".into(), "text/plain".into()),
        ],
        body: Vec::new(),
    });
    let resp = fetch(
        &get(format!("https://localhost:{}/", server.port)),
        &options(),
    )
    .unwrap();
    let names: Vec<&str> = resp.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"content-type"));
    assert!(
        !names
            .iter()
            .any(|n| n.contains("cookie") || n.contains("auth"))
    );
}

#[test]
fn a_post_sends_its_body_and_an_ip_literal_works() {
    let server = TestServer::start(|seen| Reply::ok(&seen.body));
    let mut req = get(format!("https://127.0.0.1:{}/", server.port));
    req.method = Method::Post;
    req.body = b"hello".to_vec();
    let resp = fetch(&req, &options()).unwrap();
    assert_eq!(resp.body, b"hello");
}

#[test]
fn the_certificate_is_checked() {
    let server = TestServer::start(|_| Reply::ok(b""));
    // Without the extra root the public roots do not know this server.
    let err = fetch(
        &get(format!("https://localhost:{}/", server.port)),
        &Options::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Tls(_)), "{err}");
    // A name the certificate does not carry.
    let err = fetch(
        &get(format!("https://nobody.localhost:{}/", server.port)),
        &options(),
    )
    .unwrap_err();
    assert!(!matches!(err, Error::Url(_)), "{err}");
}

#[test]
fn plain_http_and_bad_headers_are_refused_before_any_connection() {
    let err = fetch(&get("http://localhost:1/".into()), &options()).unwrap_err();
    assert!(matches!(err, Error::Url(_)));
    let mut req = get("https://localhost:1/".into());
    req.headers.push(("X-A".into(), "a\r\nHost: evil".into()));
    assert!(matches!(fetch(&req, &options()), Err(Error::Header(_))));
    let mut req = get("https://localhost:1/".into());
    req.headers.push(("Host".into(), "evil".into()));
    assert!(matches!(fetch(&req, &options()), Err(Error::Header(_))));
}

#[test]
fn a_redirect_on_the_same_host_is_followed_and_to_another_host_is_not() {
    let server = TestServer::start(|seen| match seen.target.as_str() {
        "/start" => Reply {
            status: 302,
            headers: vec![("Location".into(), "/next".into())],
            body: Vec::new(),
        },
        "/next" => Reply::ok(b"arrived"),
        "/away" => Reply {
            status: 302,
            headers: vec![("Location".into(), "https://other.localhost/x?q=1".into())],
            body: b"moved".to_vec(),
        },
        "/plain" => Reply {
            status: 301,
            headers: vec![("Location".into(), "http://localhost/x".into())],
            body: Vec::new(),
        },
        "/loop" => Reply {
            status: 302,
            headers: vec![("Location".into(), "/loop".into())],
            body: Vec::new(),
        },
        _ => Reply {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        },
    });
    let url = |p: &str| format!("https://localhost:{}{p}", server.port);
    let resp = fetch(&get(url("/start")), &options()).unwrap();
    assert_eq!((resp.status, resp.body.as_slice()), (200, &b"arrived"[..]));
    assert!(resp.redirect_stopped.is_none());

    let resp = fetch(&get(url("/away")), &options()).unwrap();
    assert_eq!(resp.status, 302);
    assert_eq!(resp.body, b"moved");
    let why = resp.redirect_stopped.unwrap();
    assert!(
        why.contains("other.localhost") && !why.contains("q=1"),
        "{why}"
    );
    // Only the first request reached this server.
    assert_eq!(server.seen().iter().filter(|s| s.target == "/x").count(), 0);

    let resp = fetch(&get(url("/plain")), &options()).unwrap();
    assert!(resp.redirect_stopped.is_some());
    let resp = fetch(&get(url("/loop")), &options()).unwrap();
    assert_eq!(resp.redirect_stopped.as_deref(), Some("too many redirects"));
}

#[test]
fn a_302_after_a_post_becomes_a_get_without_the_body() {
    let server = TestServer::start(|seen| match seen.target.as_str() {
        "/form" => Reply {
            status: 302,
            headers: vec![("Location".into(), "/done".into())],
            body: Vec::new(),
        },
        _ => Reply::ok(seen.method.as_bytes()),
    });
    let mut req = get(format!("https://localhost:{}/form", server.port));
    req.method = Method::Post;
    req.body = b"data".to_vec();
    let resp = fetch(&req, &options()).unwrap();
    assert_eq!(resp.body, b"GET");
    assert!(server.seen()[1].body.is_empty());
}

#[test]
fn the_response_is_capped() {
    let server = TestServer::start(|_| Reply::ok(&vec![b'x'; 5000]));
    let mut req = get(format!("https://localhost:{}/", server.port));
    req.max_response = 1000;
    let resp = fetch(&req, &options()).unwrap();
    assert_eq!(resp.body.len(), 1000);
    assert!(resp.truncated);
}

#[test]
fn a_dead_port_is_an_error_with_no_url_in_it() {
    let err = fetch(
        &get("https://localhost:9/secretpath?k=v".into()),
        &options(),
    )
    .unwrap_err();
    let text = err.to_string();
    assert!(
        !text.contains("secretpath") && !text.contains("k=v"),
        "{text}"
    );
}

#[test]
fn proxy_variables_are_not_read() {
    let server = TestServer::start(|_| Reply::ok(b"direct"));
    // `set_var` is unsafe in edition 2024, so the variables are set on a child
    // (this test binary, running `proxy_child`): a client that read them would
    // go to the dead proxy below and fail.
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "proxy_child", "--nocapture"])
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("VAHTA_TEST_PORT", server.port.to_string())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn proxy_child() {
    let Ok(port) = std::env::var("VAHTA_TEST_PORT") else {
        return;
    };
    let resp = fetch(&get(format!("https://localhost:{port}/")), &options()).unwrap();
    assert_eq!(resp.body, b"direct");
}
