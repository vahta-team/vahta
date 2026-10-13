//! `vahta http`: one HTTPS request made by the daemon, with a secret put in a
//! header or a query value. This process sends templates and receives the
//! response with the values already taken out; it never holds a value.

use std::io::Write;

use vahta_ipc::protocol::{
    ClientReply, ClientRequest, RunOutput, b64_decode, b64_encode, read_frame,
};

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_FAILED, EXIT_USAGE, Env};

pub const USAGE: &str = "\
usage: vahta http --secret NAME [--secret NAME]... [-H 'Name: value {NAME}']...
                  [--query key={NAME}]... [-X METHOD] [-d TEXT | -d @FILE]
                  [--json] [--timeout SECS] [--max-bytes N] [--label TEXT] URL

Make one HTTPS request with a secret in it. The daemon makes the request, so
this process never holds a value, and the response comes back with every value
replaced by ***REDACTED(NAME)***.

  --secret NAME     a secret to use (repeatable); each must appear as {NAME} in
                    a header or --query value
  -H, --header H    a header, `Name: value`; {NAME} in the value is replaced
  --query K=V       a query parameter, appended to the URL and percent-encoded;
                    {NAME} in V is replaced
  -X METHOD         GET (default), HEAD, POST, PUT, PATCH, DELETE or OPTIONS;
                    POST when there is a body and no -X
  -d TEXT|@FILE     the body, sent as written (at most 512 KiB)
  --json            print {status, headers, body, ...} as JSON instead of the body
  --timeout SECS    give up after SECS seconds (default 30, at most 120)
  --max-bytes N     keep at most N bytes of the response (default 4 MiB, at most 8 MiB)
  --label TEXT      a description for the window, shown as coming from the agent

A value goes only where {NAME} stands in a header value or a query value: never
in the URL, never in a name, never in the body (servers echo bodies back).
The URL must be https. The secret must be bound to the URL's host: the person
approves a host list with `vahta bind NAME --net hosts:HOST`; a secret with no
host list is refused. Redirects are followed only on the same host.

With a session from `vahta unlock` that covers the names there is no window;
otherwise a window asks for the password for this one request. An each-use
secret always asks. Without a daemon build that has network support, this
command is refused.

Exit: 0 for a response below 400, 1 for 400 and above or a stopped redirect (the
response is still printed), 3 refused, 4 cancelled, 5 no daemon.
";

struct Parsed {
    names: Vec<String>,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    method: Option<String>,
    body: Option<Vec<u8>>,
    json: bool,
    timeout: Option<u32>,
    max_bytes: Option<u64>,
    label: Option<String>,
    url: String,
}

enum Args {
    Run(Box<Parsed>),
    Help,
    Error(String),
}

fn parse(args: &[String]) -> Args {
    let mut p = Parsed {
        names: Vec::new(),
        headers: Vec::new(),
        query: Vec::new(),
        method: None,
        body: None,
        json: false,
        timeout: None,
        max_bytes: None,
        label: None,
        url: String::new(),
    };
    let mut urls: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if a == "--" {
            urls.extend(args[i..].iter().cloned());
            break;
        }
        if !a.starts_with('-') || a == "-" {
            urls.push(a.to_string());
            continue;
        }
        let mut value = |what: &str| -> Result<String, String> {
            let v = args
                .get(i)
                .cloned()
                .ok_or_else(|| format!("{what} expects a value"))?;
            i += 1;
            Ok(v)
        };
        let result: Result<(), String> = match a {
            "-h" | "--help" => return Args::Help,
            "--secret" => value(a).map(|v| p.names.push(v)),
            "-H" | "--header" => value(a).and_then(|v| match v.split_once(':') {
                Some((n, val)) if !n.trim().is_empty() => {
                    p.headers
                        .push((n.trim().to_string(), val.trim().to_string()));
                    Ok(())
                }
                _ => Err("a header is `Name: value`".to_string()),
            }),
            "--query" => value(a).and_then(|v| match v.split_once('=') {
                Some((k, val)) if !k.is_empty() => {
                    p.query.push((k.to_string(), val.to_string()));
                    Ok(())
                }
                _ => Err("--query expects KEY=VALUE".to_string()),
            }),
            "-X" | "--request" => value(a).map(|v| p.method = Some(v.to_ascii_uppercase())),
            "-d" | "--data" => value(a).and_then(|v| {
                let bytes = match v.strip_prefix('@') {
                    Some(path) => std::fs::read(path)
                        .map_err(|e| format!("cannot read {path}: {}", e.kind()))?,
                    None => v.into_bytes(),
                };
                p.body = Some(bytes);
                Ok(())
            }),
            "--json" => {
                p.json = true;
                Ok(())
            }
            "--timeout" => value(a).and_then(|v| {
                v.parse::<u32>()
                    .ok()
                    .filter(|s| (1..=120).contains(s))
                    .map(|s| p.timeout = Some(s))
                    .ok_or_else(|| "--timeout is 1 to 120 seconds".to_string())
            }),
            "--max-bytes" => value(a).and_then(|v| {
                v.parse::<u64>()
                    .ok()
                    .filter(|n| *n >= 1)
                    .map(|n| p.max_bytes = Some(n))
                    .ok_or_else(|| "--max-bytes is a positive number".to_string())
            }),
            "--label" => value(a).map(|v| p.label = Some(v)),
            other => Err(format!("unrecognised option: {other}")),
        };
        if let Err(e) = result {
            return Args::Error(e);
        }
    }
    match urls.len() {
        1 => p.url = urls.remove(0),
        0 => return Args::Error("no URL given".to_string()),
        _ => return Args::Error("more than one URL given".to_string()),
    }
    if p.names.is_empty() {
        return Args::Error("name a secret with --secret NAME".to_string());
    }
    if p.body.as_ref().is_some_and(|b| b.len() > 512 * 1024) {
        return Args::Error("the body is too large (512 KiB at most)".to_string());
    }
    Args::Run(Box::new(p))
}

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let p = match parse(args) {
        Args::Help => {
            let _ = stdout.write_all(USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Args::Error(msg) => {
            let _ = write!(stderr, "vahta http: error: {msg}\n\n{USAGE}");
            return EXIT_USAGE;
        }
        Args::Run(p) => p,
    };
    let method = p
        .method
        .clone()
        .unwrap_or_else(|| if p.body.is_some() { "POST" } else { "GET" }.to_string());
    let request = ClientRequest::Http {
        cwd: env.cwd.to_string_lossy().into_owned(),
        method,
        url: p.url,
        names: p.names,
        headers: p.headers,
        query: p.query,
        body: p.body.as_deref().map(b64_encode),
        max_response: p.max_bytes,
        timeout_secs: p.timeout,
        label: p.label,
    };
    let mut conn = match daemon_cmd::connect(env, "http", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let (status, headers, truncated, stopped) = match conn.request(&request) {
        Ok(ClientReply::HttpResponse {
            status,
            headers,
            truncated,
            redirect_stopped,
        }) => (status, headers, truncated, redirect_stopped),
        Ok(other) => return daemon_cmd::report("http", &other, p.json, stdout, stderr),
        Err(e) => {
            let _ = writeln!(stderr, "vahta http: error: {e}");
            return EXIT_DAEMON;
        }
    };
    let mut body: Vec<u8> = Vec::new();
    loop {
        match read_frame::<RunOutput>(conn.stream()) {
            Ok(Some(RunOutput::Stdout { data })) => {
                if let Some(bytes) = b64_decode(&data) {
                    body.extend_from_slice(&bytes);
                }
            }
            Ok(Some(RunOutput::Exit { .. })) => break,
            Ok(Some(RunOutput::Stderr { .. })) => {}
            Ok(Some(RunOutput::Failed { message })) => {
                let _ = writeln!(stderr, "vahta http: error: {message}");
                return EXIT_FAILED;
            }
            Ok(None) | Err(_) => {
                let _ = writeln!(
                    stderr,
                    "vahta http: error: lost the connection to the daemon"
                );
                return EXIT_DAEMON;
            }
        }
    }
    if p.json {
        let doc = serde_json::json!({
            "status": status,
            "headers": headers,
            "body": String::from_utf8_lossy(&body),
            "truncated": truncated,
            "redirect_stopped": stopped,
        });
        let _ = writeln!(stdout, "{doc}");
    } else {
        let _ = stdout.write_all(&body);
        let _ = stdout.flush();
        if status >= 400 {
            let _ = writeln!(stderr, "vahta http: HTTP {status}");
        }
        if let Some(why) = &stopped {
            let _ = writeln!(stderr, "vahta http: HTTP {status}: {why}");
        }
        if truncated {
            let _ = writeln!(stderr, "vahta http: the response was cut at the size limit");
        }
    }
    if status >= 400 || stopped.is_some() {
        EXIT_FAILED
    } else {
        EXIT_CLEAN
    }
}
