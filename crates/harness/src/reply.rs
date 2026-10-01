//! [`Decision`] to bytes: phrase the verdict the way the harness wants it.

use serde_json::Value;

use crate::manifest::{Kind, KindReplies, Manifest, Reply, Style};

/// What policy decided. Messages never carry a secret value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Refuse. `agent_message` goes to the model, `user_message` to the person.
    Deny { user_message: String, agent_message: String },
    /// Let it through, but say something.
    Notice { user_message: String, agent_message: String },
}

/// What the hook process emits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

fn fill(template: &str, user: &str, agent: &str) -> String {
    template
        .replace("{user_message}", user)
        .replace("{agent_message}", agent)
        .replace("{reason}", agent)
}

fn fill_value(v: &Value, user: &str, agent: &str) -> Value {
    match v {
        Value::String(s) => Value::String(fill(s, user, agent)),
        Value::Array(a) => Value::Array(a.iter().map(|x| fill_value(x, user, agent)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), fill_value(x, user, agent)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn emit(reply: &Reply, user: &str, agent: &str) -> Output {
    match reply.style {
        Style::Json => {
            let Some(body) = &reply.body else {
                return Output::default();
            };
            let mut stdout = serde_json::to_vec(&fill_value(body, user, agent)).unwrap_or_default();
            stdout.push(b'\n');
            Output { stdout, stderr: Vec::new(), exit_code: reply.exit_code }
        }
        Style::ExitCode => Output {
            stdout: Vec::new(),
            stderr: reply.stderr.as_deref().map(|s| fill(s, user, agent).into_bytes()).unwrap_or_default(),
            exit_code: reply.exit_code,
        },
        // Reserved: a plugin harness has no stdin protocol to answer on.
        Style::Plugin => Output::default(),
    }
}

impl Manifest {
    fn replies_for(&self, kind: Kind) -> Option<&KindReplies> {
        match kind {
            Kind::BeforeTool => self.replies.before_tool.as_ref(),
            Kind::BeforeRead => self.replies.before_read.as_ref(),
            Kind::Prompt => self.replies.prompt.as_ref(),
            Kind::AfterTool => self.replies.after_tool.as_ref(),
            Kind::SessionStart => self.replies.session_start.as_ref(),
        }
    }

    /// Phrase `decision` for an event of `kind`. A verdict the manifest has no
    /// reply for is silence with exit 0, which every harness reads as allow.
    pub fn render(&self, kind: Kind, decision: &Decision) -> Output {
        let Some(replies) = self.replies_for(kind) else {
            return Output::default();
        };
        let (reply, user, agent) = match decision {
            Decision::Allow => (replies.allow.as_ref(), "", ""),
            Decision::Deny { user_message, agent_message } => {
                (replies.deny.as_ref(), user_message.as_str(), agent_message.as_str())
            }
            Decision::Notice { user_message, agent_message } => {
                (replies.notice.as_ref(), user_message.as_str(), agent_message.as_str())
            }
        };
        reply.map(|r| emit(r, user, agent)).unwrap_or_default()
    }
}
