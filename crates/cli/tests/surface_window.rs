//! Drives the real prompt window (`vahta _surface`) with a scripted standard
//! input and a stand-in for the daemon's end of the connection. The window
//! reads the keyboard only while a prompt waits on it: after a wait the daemon
//! ended (the phone answered, pairing finished) no reader may be left holding
//! the next line, and what was typed during the wait must not answer the next
//! prompt.
#![cfg(unix)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vahta_ipc::protocol::{
    Hello, HelloKind, HelloReply, PROTOCOL, Panel, Secret, SurfaceAnswer, SurfaceRequest,
    read_frame, write_frame,
};
use vahta_os::ipc::{Address, Listener, Stream};

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Window {
    dir: PathBuf,
    child: Child,
    keys: ChildStdin,
    conn: Stream,
    screen: Arc<Mutex<String>>,
    answers: Receiver<Option<SurfaceAnswer>>,
}

impl Window {
    fn start() -> Window {
        let dir = std::env::temp_dir().join(format!(
            "vahta-window-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let addr = Address::for_runtime_dir(&dir).unwrap();
        let listener = Listener::bind(&addr).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_vahta"))
            .arg("_surface")
            .env("HOME", &dir)
            .env("VAHTA_SURFACE_TOKEN", "ticket")
            .env("VAHTA_SURFACE_ADDR", addr.as_os_str())
            .env("VAHTA_TEST_SURFACE_PLAIN", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let keys = child.stdin.take().unwrap();
        let mut out = child.stdout.take().unwrap();
        let screen = Arc::new(Mutex::new(String::new()));
        let shown = Arc::clone(&screen);
        std::thread::spawn(move || {
            let mut chunk = [0u8; 1024];
            while let Ok(n) = out.read(&mut chunk) {
                if n == 0 {
                    return;
                }
                let text = String::from_utf8_lossy(&chunk[..n]).into_owned();
                shown.lock().unwrap().push_str(&text);
            }
        });
        let mut conn = listener.accept().unwrap();
        let hello: Hello = read_frame(&mut conn).unwrap().unwrap();
        assert_eq!(
            hello.kind,
            HelloKind::Surface {
                token: "ticket".into()
            }
        );
        write_frame(
            &mut conn,
            &HelloReply {
                ok: true,
                protocol: PROTOCOL,
                version: hello.version,
                pid: std::process::id(),
                sessions: 0,
                error: None,
            },
        )
        .unwrap();
        // The window's answers, read on a thread so a test can give up.
        let (tx, answers) = mpsc::channel();
        let mut reader = conn.try_clone().unwrap();
        std::thread::spawn(move || {
            while let Ok(Some(a)) = read_frame::<SurfaceAnswer>(&mut reader) {
                if tx.send(Some(a)).is_err() {
                    return;
                }
            }
            let _ = tx.send(None);
        });
        Window {
            dir,
            child,
            keys,
            conn,
            screen,
            answers,
        }
    }

    fn send(&mut self, request: &SurfaceRequest) {
        write_frame(&mut self.conn, request).unwrap();
    }

    fn type_keys(&mut self, text: &str) {
        self.keys.write_all(text.as_bytes()).unwrap();
        self.keys.flush().unwrap();
    }

    /// Waits until the window has printed `what` (since `from` bytes).
    fn wait_for(&self, what: &str, from: usize) {
        let until = Instant::now() + Duration::from_secs(20);
        while Instant::now() < until {
            if self.screen.lock().unwrap()[from..].contains(what) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "the window never showed {what:?}: {}",
            self.screen.lock().unwrap()
        );
    }

    fn mark(&self) -> usize {
        self.screen.lock().unwrap().len()
    }

    fn answer(&self) -> SurfaceAnswer {
        self.answers
            .recv_timeout(Duration::from_secs(20))
            .expect("the window gave no answer")
            .expect("the window closed")
    }

    /// A password prompt, answered with `typed` once the window shows it.
    fn ask_password(&mut self, typed: &str) -> SurfaceAnswer {
        let at = self.mark();
        self.send(&request_password());
        self.wait_for("Password: ", at);
        self.type_keys(typed);
        self.answer()
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn panel() -> Panel {
    Panel {
        title: "Test".into(),
        lines: vec![],
        warning: None,
        agent_note: None,
    }
}

fn request_password() -> SurfaceRequest {
    SurfaceRequest::Password {
        panel: panel(),
        prompt: "Password".into(),
        confirm: false,
    }
}

fn device_wait() -> SurfaceRequest {
    SurfaceRequest::DeviceWait {
        panel: panel(),
        device: "Pixel".into(),
        seconds: 120,
    }
}

fn pair() -> SurfaceRequest {
    SurfaceRequest::Pair {
        panel: panel(),
        qr: "##".into(),
        text: "code".into(),
        seconds: 120,
    }
}

fn is_secret(answer: &SurfaceAnswer, text: &str) -> bool {
    *answer
        == SurfaceAnswer::Secret {
            value: Secret::new(text.into()),
        }
}

#[test]
fn a_password_after_a_device_wait_the_phone_ended_is_read_whole() {
    let mut w = Window::start();
    w.send(&device_wait());
    w.wait_for("Press Enter to use the password instead", 0);
    w.send(&SurfaceRequest::DeviceWaitStop {});
    assert_eq!(w.answer(), SurfaceAnswer::Done {});
    // Nothing is still reading the keyboard: the whole line is the password.
    let answer = w.ask_password("correct horse\n");
    assert!(is_secret(&answer, "correct horse"), "{answer:?}");
}

#[test]
fn enter_during_a_device_wait_is_not_taken_as_an_empty_password() {
    let mut w = Window::start();
    w.send(&device_wait());
    w.wait_for("Press Enter to use the password instead", 0);
    // Enter, and the phone's answer right behind it: whichever the window sees
    // first, the Enter belongs to the wait.
    w.type_keys("\n");
    w.send(&SurfaceRequest::DeviceWaitStop {});
    let first = w.answer();
    assert!(
        matches!(
            first,
            SurfaceAnswer::Choice { index: 0 } | SurfaceAnswer::Done {}
        ),
        "{first:?}"
    );
    let answer = w.ask_password("correct horse\n");
    assert!(is_secret(&answer, "correct horse"), "{answer:?}");
}

#[test]
fn enter_chooses_the_password_and_the_next_prompt_reads_its_own_line() {
    let mut w = Window::start();
    w.send(&device_wait());
    w.wait_for("Press Enter to use the password instead", 0);
    w.type_keys("\n");
    assert_eq!(w.answer(), SurfaceAnswer::Choice { index: 0 });
    let answer = w.ask_password("correct horse\n");
    assert!(is_secret(&answer, "correct horse"), "{answer:?}");
}

#[test]
fn a_password_after_pairing_finished_is_read_whole() {
    let mut w = Window::start();
    w.send(&pair());
    w.wait_for("Press Enter to cancel", 0);
    w.send(&SurfaceRequest::PairStop {});
    assert_eq!(w.answer(), SurfaceAnswer::Done {});
    let answer = w.ask_password("correct horse\n");
    assert!(is_secret(&answer, "correct horse"), "{answer:?}");
}

#[test]
fn input_typed_while_pairing_ran_does_not_answer_the_next_prompt() {
    let mut w = Window::start();
    w.send(&pair());
    w.wait_for("Press Enter to cancel", 0);
    w.type_keys("\n");
    w.send(&SurfaceRequest::PairStop {});
    let first = w.answer();
    assert!(
        matches!(first, SurfaceAnswer::Cancel {} | SurfaceAnswer::Done {}),
        "{first:?}"
    );
    let answer = w.ask_password("correct horse\n");
    assert!(is_secret(&answer, "correct horse"), "{answer:?}");
}
