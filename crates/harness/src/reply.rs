//! [`Decision`] to bytes: phrase the verdict the way the harness wants it.

use serde_json::Value;

use crate::manifest::{Kind, KindReplies, Manifest, Reply, Style};

/// What policy decided. Messages never carry a secret value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Refuse. `agent_message` goes to the model, `user_message` to the person.
    Deny {
        user_message: String,
        agent_message: String,
    },
    /// Let it through, but say something.
    Notice {
        user_message: String,
        agent_message: String,
    },
    /// after_tool: let the result through with its secrets cut out. `output`
    /// is the rewritten result in the shape the tool gave it; `mcp` says it
    /// came from an MCP tool. `agent_message` tells the model what was cut and
    /// how to ask for it; `user_message` may be empty, and then the person is
    /// told nothing.
    Redact {
        output: Value,
        mcp: bool,
        agent_message: String,
        user_message: String,
    },
}

/// What the hook process emits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

/// What a template is filled with.
struct Fill<'a> {
    user: &'a str,
    agent: &'a str,
    /// A redact reply's rewritten output.
    output: Option<&'a Value>,
}

const PLACEHOLDERS: [&str; 5] = [
    "{user_message}",
    "{agent_message}",
    "{reason}",
    "{redacted_text}",
    "{redacted_output}",
];

impl Fill<'_> {
    /// The rewritten output as one string: itself if it is one, else its JSON.
    fn output_text(&self) -> String {
        match self.output {
            Some(Value::String(s)) => s.clone(),
            Some(other) => serde_json::to_string(other).unwrap_or_default(),
            None => String::new(),
        }
    }

    fn text(&self, template: &str) -> String {
        let mut out = template
            .replace("{user_message}", self.user)
            .replace("{agent_message}", self.agent)
            .replace("{reason}", self.agent);
        if out.contains("{redacted_text}") {
            out = out.replace("{redacted_text}", &self.output_text());
        }
        out
    }

    /// A filled leaf, or `None` for one to leave out: exactly one placeholder
    /// that filled to nothing.
    fn value(&self, v: &Value) -> Option<Value> {
        Some(match v {
            Value::String(s) if s == "{redacted_output}" => self.output?.clone(),
            Value::String(s) => {
                let filled = self.text(s);
                if filled.is_empty() && PLACEHOLDERS.contains(&s.as_str()) {
                    return None;
                }
                Value::String(filled)
            }
            Value::Array(a) => Value::Array(a.iter().filter_map(|x| self.value(x)).collect()),
            Value::Object(o) => Value::Object(
                o.iter()
                    .filter_map(|(k, x)| self.value(x).map(|x| (k.clone(), x)))
                    .collect(),
            ),
            other => other.clone(),
        })
    }
}

fn emit(reply: &Reply, fill: &Fill<'_>) -> Output {
    match reply.style {
        Style::Json => {
            let Some(body) = &reply.body else {
                return Output::default();
            };
            let filled = fill.value(body).unwrap_or(Value::Null);
            let mut stdout = serde_json::to_vec(&filled).unwrap_or_default();
            stdout.push(b'\n');
            Output {
                stdout,
                stderr: Vec::new(),
                exit_code: reply.exit_code,
            }
        }
        Style::ExitCode => Output {
            stdout: Vec::new(),
            stderr: reply
                .stderr
                .as_deref()
                .map(|s| fill.text(s).into_bytes())
                .unwrap_or_default(),
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

    fn redact_reply(&self, mcp: bool) -> Option<&Reply> {
        let replies = self.replies.after_tool.as_ref()?;
        if mcp {
            replies.redact_mcp.as_ref().or(replies.redact.as_ref())
        } else {
            replies.redact.as_ref()
        }
    }

    /// Whether this harness can rewrite a tool's result (an MCP tool's when
    /// `mcp`). Where it cannot, the hook says what it found instead.
    pub fn can_redact(&self, mcp: bool) -> bool {
        self.redact_reply(mcp).is_some()
    }

    /// Phrase `decision` for an event of `kind`. A verdict the manifest has no
    /// reply for is silence with exit 0, which every harness reads as allow.
    pub fn render(&self, kind: Kind, decision: &Decision) -> Output {
        let Some(replies) = self.replies_for(kind) else {
            return Output::default();
        };
        let (reply, fill) = match decision {
            Decision::Allow => (
                replies.allow.as_ref(),
                Fill {
                    user: "",
                    agent: "",
                    output: None,
                },
            ),
            Decision::Deny {
                user_message,
                agent_message,
            } => (
                replies.deny.as_ref(),
                Fill {
                    user: user_message,
                    agent: agent_message,
                    output: None,
                },
            ),
            Decision::Notice {
                user_message,
                agent_message,
            } => (
                replies.notice.as_ref(),
                Fill {
                    user: user_message,
                    agent: agent_message,
                    output: None,
                },
            ),
            Decision::Redact {
                output,
                mcp,
                agent_message,
                user_message,
            } => (
                if kind == Kind::AfterTool {
                    self.redact_reply(*mcp)
                } else {
                    None
                },
                Fill {
                    user: user_message,
                    agent: agent_message,
                    output: Some(output),
                },
            ),
        };
        reply.map(|r| emit(r, &fill)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn render(harness: &str, decision: &Decision) -> Value {
        let m = crate::manifest(harness).unwrap().unwrap();
        let out = m.render(Kind::AfterTool, decision);
        assert_eq!(out.exit_code, 0);
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn redact(output: Value, mcp: bool, user: &str) -> Decision {
        Decision::Redact {
            output,
            mcp,
            agent_message: "1 value was redacted".to_string(),
            user_message: user.to_string(),
        }
    }

    #[test]
    fn claude_rewrites_a_result_in_its_own_shape() {
        let shaped = json!({"stdout": "a ***REDACTED(K)*** b", "stderr": "", "interrupted": false});
        let doc = render("claude", &redact(shaped.clone(), false, ""));
        let hso = &doc["hookSpecificOutput"];
        assert_eq!(hso["hookEventName"], "PostToolUse");
        assert_eq!(hso["updatedToolOutput"], shaped);
        assert_eq!(hso["additionalContext"], "1 value was redacted");
        assert!(hso.get("updatedMCPToolOutput").is_none());
        // No message for the person: the key is left out, not sent empty.
        assert!(doc.get("systemMessage").is_none(), "{doc}");
        // With one, it is there.
        let doc = render("claude", &redact(json!("x"), false, "said"));
        assert_eq!(doc["systemMessage"], "said");
        assert_eq!(doc["hookSpecificOutput"]["updatedToolOutput"], "x");
    }

    #[test]
    fn claude_rewrites_an_mcp_result_as_a_string_or_an_object() {
        let doc = render(
            "claude",
            &redact(json!("plain ***REDACTED(K)***"), true, ""),
        );
        let hso = &doc["hookSpecificOutput"];
        assert_eq!(hso["updatedMCPToolOutput"], "plain ***REDACTED(K)***");
        assert!(hso.get("updatedToolOutput").is_none());
        let structured = json!({"content": [{"type": "text", "text": "***REDACTED(K)***"}]});
        let doc = render("claude", &redact(structured.clone(), true, ""));
        assert_eq!(
            doc["hookSpecificOutput"]["updatedMCPToolOutput"],
            structured
        );
    }

    #[test]
    fn cursor_rewrites_only_mcp_results() {
        let m = crate::manifest("cursor").unwrap().unwrap();
        assert!(m.can_redact(true));
        assert!(!m.can_redact(false));
        let doc = render(
            "cursor",
            &redact(json!({"text": "***REDACTED(K)***"}), true, ""),
        );
        assert_eq!(doc["updated_mcp_tool_output"]["text"], "***REDACTED(K)***");
        assert_eq!(doc["additional_context"], "1 value was redacted");
        // A non-MCP redact has no reply: silence, which the hook never sends.
        let out = m.render(Kind::AfterTool, &redact(json!("x"), false, ""));
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn codex_blocks_with_the_redacted_text_as_the_reason() {
        let m = crate::manifest("codex").unwrap().unwrap();
        assert!(m.can_redact(true) && m.can_redact(false));
        let doc = render("codex", &redact(json!("out ***REDACTED(K)***"), false, ""));
        assert_eq!(doc["decision"], "block");
        let reason = doc["reason"].as_str().unwrap();
        assert!(reason.starts_with("out ***REDACTED(K)***"), "{reason}");
        assert!(reason.contains("1 value was redacted"));
        assert!(doc.get("systemMessage").is_none());
        // Structured output is given as its JSON text.
        let doc = render("codex", &redact(json!({"stdout": "s"}), false, "u"));
        assert!(
            doc["reason"]
                .as_str()
                .unwrap()
                .starts_with(r#"{"stdout":"s"}"#)
        );
        assert_eq!(doc["systemMessage"], "u");
    }

    #[test]
    fn a_redact_is_never_rendered_for_another_kind() {
        let m = crate::manifest("claude").unwrap().unwrap();
        let out = m.render(Kind::BeforeTool, &redact(json!("x"), false, "u"));
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn the_existing_replies_are_unchanged() {
        let doc = render(
            "claude",
            &Decision::Notice {
                user_message: "u".into(),
                agent_message: "a".into(),
            },
        );
        assert_eq!(doc["systemMessage"], "u");
        assert_eq!(doc["hookSpecificOutput"]["additionalContext"], "a");
    }
}
