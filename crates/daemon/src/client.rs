//! The client side: find the daemon, starting it if the caller allows, say
//! hello, and ask.
//!
//! Only the `vahta` command starts a daemon. The hook never does: a hook runs
//! on every tool call and must stay cheap and quiet.
//!
//! The handshake compares versions. A daemon of another version with no live
//! sessions is told to stop and a new one is started; with live sessions it is
//! left alone, because ending it would end them, and the caller is pointed at
//! `vahta daemon restart`.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::process::Command;
use std::time::{Duration, Instant};

use vahta_os::ipc::{Address, Stream};

use crate::paths::{PathError, Paths};
use crate::protocol::{
    ClientReply, ClientRequest, Hello, HelloKind, HelloReply, PROTOCOL, ProtocolError, read_frame,
    write_frame,
};

#[derive(Debug)]
pub enum ClientError {
    /// No daemon, and none could be started (or the caller did not want one).
    Unavailable(String),
    /// The daemon is another version and holds live sessions.
    LiveSessions {
        daemon_version: String,
        sessions: usize,
    },
    Protocol(ProtocolError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Unavailable(why) => write!(f, "the Vahta daemon is not available: {why}"),
            ClientError::LiveSessions {
                daemon_version,
                sessions,
            } => write!(
                f,
                "the running daemon is version {daemon_version} and holds {sessions} live session(s); \
                 run `vahta daemon restart` to replace it (that ends them)"
            ),
            ClientError::Protocol(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<ProtocolError> for ClientError {
    fn from(e: ProtocolError) -> Self {
        ClientError::Protocol(e)
    }
}

impl From<PathError> for ClientError {
    fn from(e: PathError) -> Self {
        ClientError::Unavailable(e.to_string())
    }
}

/// How to reach, and if allowed start, the daemon.
#[derive(Debug, Clone)]
pub struct Connector {
    pub paths: Paths,
    /// The version this client is. Compared with the daemon's.
    pub version: String,
    /// The command that runs a daemon, or `None` to never start one.
    pub start: Option<Vec<OsString>>,
}

/// A client connection after the hello.
#[derive(Debug)]
pub struct Connection {
    stream: Stream,
    pub daemon: HelloReply,
}

impl Connection {
    /// Send one request and read its reply.
    pub fn request(&mut self, request: &ClientRequest) -> Result<ClientReply, ClientError> {
        write_frame(&mut self.stream, request)?;
        read_frame(&mut self.stream)?.ok_or(ClientError::Protocol(ProtocolError::Truncated))
    }

    /// The raw stream, for a conversation that is more than request and reply.
    pub fn stream(&mut self) -> &mut Stream {
        &mut self.stream
    }
}

const START_WAIT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(40);

fn handshake(stream: &mut Stream, version: &str) -> Result<HelloReply, ClientError> {
    write_frame(
        stream,
        &Hello {
            protocol: PROTOCOL,
            version: version.to_string(),
            kind: HelloKind::Client,
        },
    )?;
    let reply: HelloReply =
        read_frame(stream)?.ok_or(ClientError::Protocol(ProtocolError::Truncated))?;
    Ok(reply)
}

fn is_not_running(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

impl Connector {
    fn address(&self) -> Result<Address, ClientError> {
        Ok(self.paths.address()?)
    }

    /// Connect to a daemon that is already running; `Ok(None)` when none is.
    /// Never starts one and never replaces one.
    pub fn connect_running(&self) -> Result<Option<Connection>, ClientError> {
        let address = self.address()?;
        match Stream::connect(&address) {
            Ok(mut stream) => {
                let daemon = handshake(&mut stream, &self.version)?;
                Ok(Some(Connection { stream, daemon }))
            }
            Err(e) if is_not_running(&e) => Ok(None),
            Err(e) => Err(ClientError::Unavailable(e.to_string())),
        }
    }

    /// Connect, starting a daemon if there is none and the caller allows it,
    /// and replacing one of another version if it holds no session.
    pub fn connect(&self) -> Result<Connection, ClientError> {
        if let Some(mut conn) = self.connect_running()? {
            let same = conn.daemon.ok && conn.daemon.version == self.version;
            if same {
                return Ok(conn);
            }
            if conn.daemon.sessions > 0 {
                return Err(ClientError::LiveSessions {
                    daemon_version: conn.daemon.version.clone(),
                    sessions: conn.daemon.sessions,
                });
            }
            // An older (or newer) daemon with nothing to lose: it goes, and a
            // fresh one comes up in its place.
            if self.start.is_none() {
                return Err(ClientError::Unavailable(format!(
                    "the running daemon is version {}",
                    conn.daemon.version
                )));
            }
            if conn.daemon.ok {
                let _ = conn.request(&ClientRequest::Stop {});
            }
            drop(conn);
            self.wait_until_gone()?;
        }
        let Some(start) = &self.start else {
            return Err(ClientError::Unavailable("it is not running".to_string()));
        };
        self.start_daemon(start)?;
        let deadline = Instant::now() + START_WAIT;
        loop {
            if let Some(conn) = self.connect_running()? {
                if conn.daemon.ok && conn.daemon.version == self.version {
                    return Ok(conn);
                }
                return Err(ClientError::Unavailable(format!(
                    "a daemon of version {} answered",
                    conn.daemon.version
                )));
            }
            if Instant::now() >= deadline {
                return Err(ClientError::Unavailable(
                    "it did not start within 5 seconds".to_string(),
                ));
            }
            std::thread::sleep(POLL);
        }
    }

    fn start_daemon(&self, command: &[OsString]) -> Result<(), ClientError> {
        let Some((program, args)) = command.split_first() else {
            return Err(ClientError::Unavailable(
                "no command to start it".to_string(),
            ));
        };
        // The daemon is told exactly the directories this client resolved, so
        // the two cannot disagree about where the socket is, whatever the
        // environment this process happens to carry.
        vahta_os::spawn_detached(
            Command::new(program)
                .args(args)
                .env("VAHTA_RUNTIME_DIR", &self.paths.runtime)
                .env("VAHTA_DATA_DIR", &self.paths.data)
                .env("VAHTA_CONFIG_DIR", &self.paths.config),
        )
        .map_err(|e| ClientError::Unavailable(format!("cannot start it: {e}")))
    }

    /// Wait for a daemon that has been told to stop to leave the socket.
    pub fn wait_until_gone(&self) -> Result<(), ClientError> {
        let address = self.address()?;
        let deadline = Instant::now() + START_WAIT;
        loop {
            match Stream::connect(&address) {
                Err(e) if is_not_running(&e) => return Ok(()),
                _ if Instant::now() >= deadline => {
                    return Err(ClientError::Unavailable(
                        "the old daemon did not stop within 5 seconds".to_string(),
                    ));
                }
                _ => std::thread::sleep(POLL),
            }
        }
    }
}
