//! Payload to [`Event`]: read a harness's JSON the way its manifest says.

use vahta_json::Value;

use crate::manifest::{EventSpec, Group, Kind, Manifest, OneOrMany};

/// A harness payload, reduced to what policy needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub kind: Option<Kind>,
    /// The harness's tool name; empty when the payload names none.
    pub tool: String,
    pub group: Option<Group>,
    /// before_tool: the text to scan. prompt: the prompt. after_tool: the output.
    pub text: String,
    /// before_read: the file and, when the harness sends it, its content.
    /// before_tool: the file a write tool is about, when the harness names it.
    pub path: Option<String>,
    pub content: Option<String>,
    pub cwd: Option<String>,
    /// after_tool: the tool's output as the harness sent it, structure and
    /// all, so a rewrite can keep its shape (Claude wants the shape back).
    /// `None` when there is no output or it nests past [`OUTPUT_DEPTH`].
    pub output: Option<serde_json::Value>,
}

/// How deep an output is kept as a structure. A real tool result is a few
/// levels; past this, the output is still scanned as text but not rebuilt,
/// because a deep `serde_json::Value` is dropped recursively and a payload is
/// hostile input.
pub const OUTPUT_DEPTH: usize = 64;

/// A parsed payload value as a `serde_json::Value`, or `None` past `depth`.
/// An integer too big for 64 bits becomes a float, and a float JSON cannot
/// write (Python reads `NaN`) becomes its text: the rewrite need only be
/// faithful in its strings, which are what is redacted.
fn to_serde(v: &Value, depth: usize) -> Option<serde_json::Value> {
    use serde_json::Value as J;
    Some(match v {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Int(digits) => {
            if let Ok(n) = digits.parse::<i64>() {
                J::from(n)
            } else if let Ok(n) = digits.parse::<u64>() {
                J::from(n)
            } else {
                digits
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map_or_else(|| J::String(digits.clone()), J::Number)
            }
        }
        Value::Float(f) => {
            serde_json::Number::from_f64(*f).map_or_else(|| J::String(f.to_string()), J::Number)
        }
        Value::Str(s) => J::String(s.clone()),
        Value::Array(items) => {
            let depth = depth.checked_sub(1)?;
            J::Array(
                items
                    .iter()
                    .map(|x| to_serde(x, depth))
                    .collect::<Option<_>>()?,
            )
        }
        Value::Object(entries) => {
            let depth = depth.checked_sub(1)?;
            let mut map = serde_json::Map::new();
            for (k, x) in entries {
                map.insert(k.clone(), to_serde(x, depth)?);
            }
            J::Object(map)
        }
    })
}

/// Every string value, pre-order (Python's `collect_strings`). Iterative:
/// a payload is hostile input and may nest as deep as the parser allows.
fn collect_strings<'a>(root: &'a Value, out: &mut Vec<&'a str>) {
    let mut work = vec![root];
    while let Some(v) = work.pop() {
        match v {
            Value::Str(s) => out.push(s),
            Value::Array(items) => work.extend(items.iter().rev()),
            Value::Object(entries) => work.extend(entries.iter().rev().map(|(_, v)| v)),
            _ => {}
        }
    }
}

fn joined_strings(v: &Value) -> String {
    let mut all = Vec::new();
    collect_strings(v, &mut all);
    all.join("\n")
}

/// The member `key` of an object.
fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn is_null(v: &Value) -> bool {
    matches!(v, Value::Null)
}

/// The value at a dotted path, if every step exists.
fn at_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |cur, key| get(cur, key))
}

/// First alternative present and not null.
fn field<'a>(payload: &'a Value, paths: &Option<OneOrMany>) -> Option<&'a Value> {
    paths
        .as_ref()?
        .iter()
        .filter_map(|p| at_path(payload, p))
        .find(|v| !is_null(v))
}

fn text_field(payload: &Value, paths: &Option<OneOrMany>) -> Option<String> {
    match field(payload, paths)? {
        Value::Str(s) => Some(s.clone()),
        _ => None,
    }
}

/// Python's `str(x or "")` for a tool name: falsy values are "no name", any
/// other non-string is a name no manifest knows.
fn tool_name(payload: &Value, spec: &EventSpec) -> String {
    match field(payload, &spec.tool_name) {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Int(n)) if n == "0" => String::new(),
        Some(Value::Float(f)) if *f == 0.0 => String::new(),
        Some(Value::Array(a)) if a.is_empty() => String::new(),
        Some(Value::Object(o)) if o.is_empty() => String::new(),
        Some(other) => other.canonical(),
    }
}

fn strip(s: &str) -> &str {
    s.trim_matches(vahta_detect::primitives::is_python_space)
}

fn classify(m: &Manifest, payload: &Value, tool: &str) -> Option<Group> {
    let lower = tool.to_lowercase();
    let trimmed = strip(&lower);
    for g in &m.tool_groups {
        let by_name = g.tools.iter().any(|t| t.to_lowercase() == lower);
        let by_prefix = g.prefixes.iter().any(|p| {
            let p = p.to_lowercase();
            trimmed.starts_with(&p) && trimmed.len() > p.len()
        });
        let by_marker = g
            .marker_fields
            .iter()
            .any(|f| get(payload, f).is_some_and(|v| !is_null(v)));
        if by_name || by_prefix || by_marker {
            return Some(g.group);
        }
    }
    None
}

/// The text of a tool call. Known keys win in priority order, so a `command`
/// is scanned alone; MCP argument names belong to the server, so there every
/// string counts and no key can shadow a sibling.
fn call_text(tool_input: Option<&Value>, text_fields: &[String]) -> String {
    match tool_input {
        Some(v @ Value::Object(_)) => {
            for key in text_fields {
                if let Some(Value::Str(s)) = get(v, key)
                    && !strip(s).is_empty()
                {
                    return s.clone();
                }
            }
            joined_strings(v)
        }
        Some(Value::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

impl Manifest {
    /// Read `payload` as an event of `kind`. `None` means "nothing to judge":
    /// not an object, an event this manifest does not know, a tool outside the
    /// groups the kind covers. The caller allows.
    pub fn normalise(&self, kind: Kind, payload: &Value) -> Option<Event> {
        if !matches!(payload, Value::Object(_)) {
            return None;
        }
        let spec = self.event(kind)?;
        let mut ev = Event {
            kind: Some(kind),
            cwd: text_field(payload, &spec.cwd),
            ..Event::default()
        };
        match kind {
            Kind::BeforeTool => {
                ev.tool = tool_name(payload, spec);
                ev.group = if ev.tool.is_empty() {
                    self.unnamed_tool_group
                } else {
                    classify(self, payload, &ev.tool)
                };
                let group = self
                    .tool_groups
                    .iter()
                    .find(|g| Some(g.group) == ev.group)?;
                if !matches!(group.group, Group::Shell | Group::Write | Group::Mcp) {
                    return None;
                }
                // The file a write tool is about, where the harness names one;
                // the hook uses it to protect Vahta's own files.
                ev.path = text_field(payload, &spec.file_path);
                let input = field(payload, &spec.tool_input);
                ev.text = if group.group == Group::Mcp {
                    match input {
                        Some(v @ Value::Object(_)) => joined_strings(v),
                        _ => call_text(input, &[]),
                    }
                } else {
                    call_text(input, &group.text_fields)
                };
            }
            Kind::BeforeRead => {
                if spec.tool_name.is_some() {
                    ev.tool = tool_name(payload, spec);
                    ev.group = classify(self, payload, &ev.tool);
                    if ev.group != Some(Group::Read) {
                        return None;
                    }
                }
                ev.path = text_field(payload, &spec.file_path);
                ev.content = text_field(payload, &spec.content);
            }
            Kind::SessionStart => {}
            Kind::Prompt => ev.text = text_field(payload, &spec.prompt)?,
            Kind::AfterTool => {
                ev.tool = tool_name(payload, spec);
                // Which family: an MCP result is rewritten through its own
                // field in some harnesses.
                ev.group = classify(self, payload, &ev.tool);
                let output = field(payload, &spec.tool_output)?;
                ev.text = match output {
                    Value::Str(s) => s.clone(),
                    other => joined_strings(other),
                };
                ev.output = to_serde(output, OUTPUT_DEPTH);
            }
        }
        Some(ev)
    }
}
