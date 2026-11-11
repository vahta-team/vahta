//! Windows shells for the file guards: PowerShell cmdlets and their aliases,
//! `cmd` built-ins, .NET file calls, and the way Windows spells a path.
//!
//! The guards in `readguard` and `hookguard` know Unix programs. This adds the
//! rest, as data: [`CMDLETS`] says, for each cmdlet (and each alias and `cmd`
//! built-in of it), which parameters name a file, whether the file is read,
//! written or removed, which positional word is which, and which parameters
//! take a value that is not a file (`-Value`, `-Pattern`, `-Encoding`, ...).
//! Nothing here depends on the tool being called PowerShell: Codex on Windows
//! runs `pwsh` and calls the tool `Bash`, so the forms are recognised in any
//! shell command, on any OS.
//!
//! Names and `-Parameter` names are case-insensitive, and a parameter may be
//! abbreviated as far as PowerShell allows. `-Path:x` and `-Path x` both work.
//! `powershell -Command "..."`, `pwsh -c ...`, `cmd /c ...`, `sh -c ...` and
//! `Invoke-Expression` are followed into the command they run.
//!
//! Not covered (same as the Unix side): paths built from variables
//! (`$x = '.vah'; $x + 'ta'`), `-EncodedCommand`, `Get-Item` and other
//! metadata-only calls, `ls` (the Unix `ls` is not guarded either) and
//! objects made with `New-Object IO.FileStream`.

use std::path::PathBuf;

/// What a command does to a file it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// Its content is read (or listed).
    Read,
    /// It is created, overwritten or appended to.
    Write,
    /// It is deleted or moved away (so a directory above it is touched too).
    Remove,
}

/// A file a command names: the program that does it, the path as written, and
/// what is done to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Touch {
    pub prog: String,
    pub path: String,
    pub role: Role,
}

#[derive(Clone, Copy)]
enum Kind {
    Path(Role),
    /// Takes a value that is not a file.
    Value,
    /// Takes none.
    Switch,
}

#[derive(Clone, Copy)]
struct Param {
    name: &'static str,
    kind: Kind,
    /// The position of this parameter among the words that name no parameter.
    pos: Option<usize>,
    /// Words past the last position belong to this parameter too (`cmd` lets
    /// `type a b` and `del a b` take several files).
    rest: bool,
}

const fn path(name: &'static str, role: Role, pos: Option<usize>) -> Param {
    Param {
        name,
        kind: Kind::Path(role),
        pos,
        rest: false,
    }
}

const fn many(name: &'static str, role: Role, pos: usize) -> Param {
    Param {
        name,
        kind: Kind::Path(role),
        pos: Some(pos),
        rest: true,
    }
}

const fn value(name: &'static str, pos: Option<usize>) -> Param {
    Param {
        name,
        kind: Kind::Value,
        pos,
        rest: false,
    }
}

const fn switch(name: &'static str) -> Param {
    Param {
        name,
        kind: Kind::Switch,
        pos: None,
        rest: false,
    }
}

struct Cmdlet {
    /// Lower case: the cmdlet, its aliases, the `cmd` built-in.
    names: &'static [&'static str],
    params: &'static [Param],
}

use Role::{Read, Remove, Write};

/// Parameters every cmdlet has, and the usual switches: last in the search, so
/// a cmdlet's own parameter wins an abbreviation.
const COMMON: &[Param] = &[
    value("erroraction", None),
    value("ea", None),
    value("errorvariable", None),
    value("ev", None),
    value("warningaction", None),
    value("wa", None),
    value("warningvariable", None),
    value("wv", None),
    value("informationaction", None),
    value("ia", None),
    value("informationvariable", None),
    value("iv", None),
    value("outvariable", None),
    value("ov", None),
    value("outbuffer", None),
    value("ob", None),
    value("pipelinevariable", None),
    value("pv", None),
    switch("verbose"),
    switch("debug"),
    switch("whatif"),
    switch("confirm"),
    switch("force"),
    switch("recurse"),
    switch("raw"),
    switch("passthru"),
    switch("nonewline"),
    switch("append"),
    switch("noclobber"),
    switch("usetransaction"),
    switch("wait"),
];

/// The filter-and-credential parameters the file-system cmdlets share.
const FILTERS: [Param; 4] = [
    value("filter", None),
    value("include", None),
    value("exclude", None),
    value("credential", None),
];

macro_rules! params {
    ($($p:expr),* $(,)?) => {
        &[
            $($p,)*
            FILTERS[0], FILTERS[1], FILTERS[2], FILTERS[3],
        ]
    };
}

const CMDLETS: &[Cmdlet] = &[
    // --- reads ---
    Cmdlet {
        names: &["get-content", "gc", "cat", "type", "more"],
        params: params![
            many("path", Read, 0),
            path("literalpath", Read, None),
            path("pspath", Read, None),
            path("lp", Read, None),
            value("totalcount", None),
            value("head", None),
            value("first", None),
            value("tail", None),
            value("last", None),
            value("readcount", None),
            value("delimiter", None),
            value("encoding", None),
            value("stream", None),
        ],
    },
    Cmdlet {
        names: &["select-string", "sls"],
        params: params![
            value("pattern", Some(0)),
            many("path", Read, 1),
            path("literalpath", Read, None),
            path("lp", Read, None),
            value("encoding", None),
            value("context", None),
            value("culture", None),
            value("inputobject", None),
        ],
    },
    Cmdlet {
        names: &["findstr"],
        params: &[value("pattern", Some(0)), many("files", Read, 1)],
    },
    Cmdlet {
        names: &["get-childitem", "gci", "dir"],
        params: params![
            many("path", Read, 0),
            path("literalpath", Read, None),
            path("lp", Read, None),
            value("depth", None),
            value("attributes", None),
        ],
    },
    Cmdlet {
        names: &["import-csv", "import-clixml", "import-powershelldatafile"],
        params: &[
            path("path", Read, Some(0)),
            path("literalpath", Read, None),
            path("lp", Read, None),
            value("delimiter", None),
            value("header", None),
            value("encoding", None),
        ],
    },
    // --- copy, move, rename, remove ---
    Cmdlet {
        names: &["copy-item", "copy", "cp", "cpi"],
        params: params![
            path("path", Read, Some(0)),
            path("literalpath", Read, None),
            path("lp", Read, None),
            path("destination", Write, Some(1)),
            value("fromsession", None),
            value("tosession", None),
        ],
    },
    Cmdlet {
        names: &["move-item", "move", "mv", "mi"],
        params: params![
            path("path", Remove, Some(0)),
            path("literalpath", Remove, None),
            path("lp", Remove, None),
            path("destination", Write, Some(1)),
        ],
    },
    Cmdlet {
        names: &["rename-item", "rename", "ren", "rni"],
        params: &[
            path("path", Remove, Some(0)),
            path("literalpath", Remove, None),
            path("lp", Remove, None),
            value("newname", Some(1)),
            value("credential", None),
        ],
    },
    Cmdlet {
        names: &["remove-item", "ri", "rm", "del", "erase", "rd", "rmdir"],
        params: params![
            many("path", Remove, 0),
            path("literalpath", Remove, None),
            path("lp", Remove, None),
            value("stream", None),
        ],
    },
    Cmdlet {
        names: &["xcopy", "robocopy"],
        params: &[
            path("source", Read, Some(0)),
            path("target", Write, Some(1)),
        ],
    },
    // --- writes ---
    Cmdlet {
        names: &["set-content", "sc", "add-content", "ac"],
        params: params![
            path("path", Write, Some(0)),
            path("literalpath", Write, None),
            path("pspath", Write, None),
            path("lp", Write, None),
            value("value", Some(1)),
            value("encoding", None),
            value("stream", None),
        ],
    },
    Cmdlet {
        names: &["clear-content", "clc"],
        params: params![
            path("path", Write, Some(0)),
            path("literalpath", Write, None),
            path("lp", Write, None),
            value("stream", None),
        ],
    },
    Cmdlet {
        names: &["out-file"],
        params: &[
            path("filepath", Write, Some(0)),
            path("path", Write, None),
            path("literalpath", Write, None),
            path("lp", Write, None),
            value("encoding", Some(1)),
            value("width", Some(2)),
            value("inputobject", None),
        ],
    },
    Cmdlet {
        names: &["tee-object", "tee"],
        params: &[
            path("filepath", Write, Some(0)),
            path("path", Write, None),
            path("literalpath", Write, None),
            path("lp", Write, None),
            value("variable", None),
            value("inputobject", None),
        ],
    },
    Cmdlet {
        names: &["new-item", "ni"],
        params: params![
            path("path", Write, Some(0)),
            path("name", Write, None),
            value("itemtype", None),
            value("type", None),
            value("value", None),
        ],
    },
    Cmdlet {
        names: &["export-csv", "export-clixml"],
        params: &[
            path("path", Write, Some(0)),
            path("literalpath", Write, None),
            path("lp", Write, None),
            value("delimiter", None),
            value("encoding", None),
            value("inputobject", None),
        ],
    },
    Cmdlet {
        names: &["compress-archive"],
        params: &[
            many("path", Read, 0),
            path("literalpath", Read, None),
            path("lp", Read, None),
            path("destinationpath", Write, Some(1)),
            value("compressionlevel", None),
        ],
    },
    Cmdlet {
        names: &["expand-archive"],
        params: &[
            path("path", Read, Some(0)),
            path("literalpath", Read, None),
            path("lp", Read, None),
            path("destinationpath", Write, Some(1)),
        ],
    },
    Cmdlet {
        names: &["invoke-webrequest", "iwr", "invoke-restmethod", "irm"],
        params: &[
            value("uri", Some(0)),
            path("outfile", Write, None),
            path("infile", Read, None),
            value("method", None),
            value("body", None),
            value("headers", None),
            value("contenttype", None),
            value("useragent", None),
            value("credential", None),
            value("authentication", None),
            value("token", None),
            value("timeoutsec", None),
            value("maximumredirection", None),
            value("proxy", None),
        ],
    },
];

/// The program's name as it is matched: no directory (either slash), no
/// `.exe`, lower case.
pub(crate) fn prog_name(prog: &str) -> String {
    let base = prog.rsplit(['/', '\\']).next().unwrap_or(prog);
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// A word that names a parameter: `-Name` or `-Name:value`, not `--long`, not
/// `-5`. Returns the name (lower case) and the inline value.
fn parameter(word: &str) -> Option<(String, Option<String>)> {
    let rest = word.strip_prefix('-')?;
    if !rest.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    let (name, inline) = match rest.split_once(':') {
        Some((n, v)) => (n, Some(v.to_string())),
        None => (rest, None),
    };
    Some((name.to_ascii_lowercase(), inline))
}

/// `cmd`'s switches: `/y`, `/q`, `/s`, `/c:text`. Not `/etc/x`.
fn is_slash_switch(word: &str) -> bool {
    let Some(rest) = word.strip_prefix('/') else {
        return false;
    };
    let letters = rest
        .chars()
        .take_while(|c| c.is_ascii_alphabetic() || *c == '?')
        .count();
    (1..=2).contains(&letters) && matches!(rest.chars().nth(letters), None | Some(':'))
}

/// The parameter an abbreviation means: an exact name first, then the first
/// parameter (the cmdlet's own before the common ones) it starts.
fn resolve<'a>(cmdlet: &'a Cmdlet, name: &str) -> Option<&'a Param> {
    let pool = || cmdlet.params.iter().chain(COMMON.iter());
    pool()
        .find(|p| p.name == name)
        .or_else(|| pool().find(|p| p.name.starts_with(name)))
}

/// The files a command names, when its program is a cmdlet, an alias or a
/// `cmd` built-in of the table. `words` start with the program.
pub(crate) fn touches(words: &[String]) -> Vec<Touch> {
    let Some(prog) = words.first() else {
        return Vec::new();
    };
    let name = prog_name(prog);
    let Some(cmdlet) = CMDLETS.iter().find(|c| c.names.contains(&name.as_str())) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut emit = |param: &Param, text: &str| {
        if let Kind::Path(role) = param.kind {
            for part in text.split(',').filter(|p| !p.is_empty()) {
                out.push(Touch {
                    prog: name.clone(),
                    path: part.to_string(),
                    role,
                });
            }
        }
    };
    let args = &words[1..];
    let mut bound: Vec<&str> = Vec::new();
    let mut positional: Vec<&str> = Vec::new();
    let mut named: Vec<(&Param, String)> = Vec::new();
    let mut only_positional = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if only_positional {
            positional.push(a);
        } else if a == "--" {
            only_positional = true;
        } else if a.starts_with("--") || is_slash_switch(a) {
            // A long option of a Unix program, or a `cmd` switch.
        } else if let Some((pname, inline)) = parameter(a) {
            let Some(p) = resolve(cmdlet, &pname) else {
                continue; // a switch we do not know
            };
            if matches!(p.kind, Kind::Switch) {
                continue;
            }
            let given = match inline {
                Some(v) => v,
                None => match args.get(i) {
                    Some(next) if parameter(next).is_none() => {
                        i += 1;
                        next.clone()
                    }
                    _ => continue,
                },
            };
            bound.push(p.name);
            named.push((p, given));
        } else {
            positional.push(a);
        }
    }
    for (p, given) in &named {
        emit(p, given);
    }
    let mut slots: Vec<&Param> = cmdlet
        .params
        .iter()
        .filter(|p| p.pos.is_some() && !bound.contains(&p.name))
        .collect();
    slots.sort_by_key(|p| p.pos);
    for (k, word) in positional.iter().enumerate() {
        let slot = slots
            .get(k)
            .copied()
            .or_else(|| slots.last().copied().filter(|p| p.rest));
        if let Some(p) = slot {
            emit(p, word);
        }
    }
    out
}

/// The command line a shell, `cmd` or `Invoke-Expression` is given to run,
/// if `words` is one of them.
pub(crate) fn nested(words: &[String]) -> Option<String> {
    let name = prog_name(words.first()?);
    let args = &words[1..];
    let is_flag = |a: &str, full: &str| {
        a.strip_prefix('-')
            .is_some_and(|f| !f.is_empty() && full.starts_with(&f.to_ascii_lowercase()))
    };
    let tail = |from: usize| -> Option<String> {
        let rest = args.get(from..).filter(|r| !r.is_empty())?;
        if rest.len() == 1 {
            return Some(rest[0].clone());
        }
        // Words that held spaces go back in quotes.
        Some(
            rest.iter()
                .map(|w| {
                    if w.contains(char::is_whitespace) {
                        format!("\"{w}\"")
                    } else {
                        w.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        )
    };
    match name.as_str() {
        "powershell" | "pwsh" => {
            let at = args.iter().position(|a| is_flag(a, "command"))?;
            tail(at + 1)
        }
        "cmd" => {
            let at = args
                .iter()
                .position(|a| a.eq_ignore_ascii_case("/c") || a.eq_ignore_ascii_case("/k"))?;
            tail(at + 1)
        }
        "invoke-expression" | "iex" => tail(0),
        "sh" | "bash" | "zsh" | "dash" | "ksh" => {
            let at = args
                .iter()
                .position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))?;
            tail(at + 1).filter(|_| args.len() == at + 2)
        }
        _ => None,
    }
}

// --- .NET file calls -----------------------------------------------------------------------

/// `[IO.File]::Method(args)`: type, method, and what each argument is.
const DOTNET: &[(&str, &[&str], &[Role])] = &[
    (
        "io.file",
        &[
            "readalltext",
            "readallbytes",
            "readalllines",
            "readlines",
            "openread",
            "opentext",
            "readalltextasync",
            "readallbytesasync",
            "readalllinesasync",
        ],
        &[Read],
    ),
    (
        "io.file",
        &[
            "writealltext",
            "writeallbytes",
            "writealllines",
            "appendalltext",
            "appendalllines",
            "appendtext",
            "create",
            "createtext",
            "openwrite",
            "open",
            "writealltextasync",
            "writeallbytesasync",
        ],
        &[Write],
    ),
    ("io.file", &["delete"], &[Remove]),
    ("io.file", &["copy"], &[Read, Write]),
    ("io.file", &["move"], &[Remove, Write]),
    ("io.file", &["replace"], &[Remove, Write, Write]),
    (
        "io.directory",
        &[
            "getfiles",
            "enumeratefiles",
            "getdirectories",
            "enumeratedirectories",
            "getfilesystementries",
            "enumeratefilesystementries",
        ],
        &[Read],
    ),
    ("io.directory", &["delete"], &[Remove]),
    ("io.directory", &["move"], &[Remove, Write]),
    ("io.directory", &["createdirectory"], &[Write]),
    ("io.streamreader", &["new"], &[Read]),
    ("io.streamwriter", &["new"], &[Write]),
    ("io.filestream", &["new"], &[Write]),
];

/// The arguments of the call whose `(` is at the start of `text`, split at
/// the commas that are not inside quotes or brackets.
fn call_args(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut depth, mut quote) = (0usize, None::<char>);
    for c in text.chars().skip(1) {
        match (quote, c) {
            (Some(q), c) if c == q => {
                quote = None;
                cur.push(c);
            }
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                cur.push(c);
            }
            (None, '(' | '[' | '{') => {
                depth += 1;
                cur.push(c);
            }
            (None, ')' | ']' | '}') if depth > 0 => {
                depth -= 1;
                cur.push(c);
            }
            (None, ')') => {
                out.push(std::mem::take(&mut cur));
                return out;
            }
            (None, ',') if depth == 0 => out.push(std::mem::take(&mut cur)),
            (None, c) => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// An argument that is one string literal, without its quotes. Anything else
/// (a variable, a concatenation, a call) is not followed.
fn literal(arg: &str) -> Option<String> {
    let a = arg.trim().replace("\\\"", "\"");
    let a = a.trim();
    let q = a.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
    let inner = a.strip_prefix(q)?.strip_suffix(q)?;
    (!inner.contains(q)).then(|| inner.to_string())
}

/// The files `[IO.File]::...`, `[System.IO.Directory]::...` and the like name
/// in a command, wherever in it the call is (inside a nested `-Command`
/// string too).
pub(crate) fn dotnet(cmd: &str) -> Vec<Touch> {
    let lower = cmd.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = lower[from..].find("::") {
        let at = from + i;
        from = at + 2;
        let before = lower[..at].trim_end();
        let Some(inner) = before.strip_suffix(']') else {
            continue;
        };
        let Some(open) = inner.rfind('[') else {
            continue;
        };
        let ty = inner[open + 1..].trim();
        let ty = ty.strip_prefix("system.").unwrap_or(ty);
        let after = &lower[at + 2..];
        let method: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let paren = at + 2 + method.len();
        if !cmd[paren..].trim_start().starts_with('(') {
            continue;
        }
        let Some((_, _, roles)) = DOTNET
            .iter()
            .find(|(t, ms, _)| *t == ty && ms.contains(&method.as_str()))
        else {
            continue;
        };
        let start = paren + (cmd[paren..].len() - cmd[paren..].trim_start().len());
        for (arg, role) in call_args(&cmd[start..]).iter().zip(roles.iter()) {
            if let Some(path) = literal(arg) {
                out.push(Touch {
                    prog: format!("[{ty}]::{method}"),
                    path,
                    role: *role,
                });
            }
        }
    }
    out
}

// --- how Windows spells a path -------------------------------------------------------------

fn home() -> Option<PathBuf> {
    for var in ["HOME", "USERPROFILE"] {
        if let Some(h) = std::env::var_os(var).filter(|h| !h.is_empty()) {
            return Some(PathBuf::from(h));
        }
    }
    dirs::home_dir()
}

/// The value of a variable a path may start with: the process's, else the
/// platform's own answer for the usual ones.
fn variable(name: &str) -> Option<String> {
    let upper = name.to_ascii_uppercase();
    for n in [name, upper.as_str()] {
        if let Some(v) = std::env::var_os(n).filter(|v| !v.is_empty()) {
            return Some(v.to_string_lossy().into_owned());
        }
    }
    let dir = match upper.as_str() {
        "APPDATA" => dirs::data_dir(),
        "LOCALAPPDATA" => dirs::data_local_dir(),
        "USERPROFILE" | "HOME" => home(),
        _ => None,
    };
    dir.map(|d| d.to_string_lossy().into_owned())
}

/// A variable reference at the start of `s`: the name and how many bytes it
/// takes. `$env:NAME`, `${env:NAME}`, `$HOME`, `${HOME}`, `%NAME%`.
fn reference(s: &str) -> Option<(String, usize)> {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    if let Some(rest) = s.strip_prefix("${") {
        let end = rest.find('}')?;
        let inner = &rest[..end];
        let name = match inner.get(..4) {
            Some(p) if p.eq_ignore_ascii_case("env:") => &inner[4..],
            _ => inner,
        };
        return (!name.is_empty() && name.chars().all(is_name))
            .then(|| (name.to_string(), 2 + end + 1));
    }
    if let Some(rest) = s.strip_prefix('$') {
        if rest
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("env:"))
        {
            let name: String = rest[4..].chars().take_while(|c| is_name(*c)).collect();
            let used = 1 + 4 + name.len();
            return (!name.is_empty()).then_some((name, used));
        }
        let name: String = rest.chars().take_while(|c| is_name(*c)).collect();
        return name
            .eq_ignore_ascii_case("home")
            .then(|| (name.clone(), 1 + name.len()));
    }
    if let Some(rest) = s.strip_prefix('%') {
        let end = rest.find('%')?;
        let name = &rest[..end];
        return (!name.is_empty() && name.chars().all(is_name))
            .then(|| (name.to_string(), 1 + end + 1));
    }
    None
}

/// `given` with `~`, `$env:NAME`, `${env:NAME}`, `$HOME` and `%NAME%` replaced
/// by what they stand for. What cannot be resolved stays as written.
pub(crate) fn expand(given: &str) -> String {
    let mut out = String::with_capacity(given.len());
    let mut i = 0;
    if given.starts_with('~')
        && matches!(given[1..].chars().next(), None | Some('/') | Some('\\'))
        && let Some(h) = home()
    {
        out.push_str(&h.to_string_lossy());
        i = 1;
    }
    while i < given.len() {
        let rest = &given[i..];
        if rest.starts_with(['$', '%'])
            && let Some((name, used)) = reference(rest)
            && let Some(v) = variable(&name)
        {
            out.push_str(&v);
            i += used;
            continue;
        }
        let c = rest.chars().next().unwrap_or(' ');
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// The ways to read one path word: as written, with `\` as a separator, with
/// variables expanded, and both.
pub(crate) fn variants(given: &str) -> Vec<String> {
    let mut out = vec![given.to_string()];
    let expanded = expand(given);
    for v in [
        given.replace('\\', "/"),
        expanded.clone(),
        expanded.replace('\\', "/"),
    ] {
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    fn t(line: &str) -> Vec<(String, Role)> {
        touches(&w(line))
            .into_iter()
            .map(|t| (t.path, t.role))
            .collect()
    }

    fn one(path: &str, role: Role) -> Vec<(String, Role)> {
        vec![(path.to_string(), role)]
    }

    #[test]
    fn readers_by_name_alias_and_parameter() {
        assert_eq!(t("Get-Content x"), one("x", Read));
        assert_eq!(t("gc x"), one("x", Read));
        assert_eq!(t("TYPE x"), one("x", Read));
        assert_eq!(t("Get-Content -LiteralPath x"), one("x", Read));
        assert_eq!(t("get-content -lit x"), one("x", Read));
        assert_eq!(t("Get-Content -Path:x"), one("x", Read));
        assert_eq!(t("Get-Content -Tail 5 x"), one("x", Read));
        assert_eq!(t("Get-Content -Raw x"), one("x", Read));
        assert_eq!(t("Get-Content -ea Stop x"), one("x", Read));
        assert_eq!(t("Select-String -Path x -Pattern y"), one("x", Read));
        assert_eq!(t("Select-String y x"), one("x", Read));
        assert_eq!(t("sls -Pattern y x"), one("x", Read));
        assert_eq!(t("Get-ChildItem -Recurse x"), one("x", Read));
        assert_eq!(t("dir x"), one("x", Read));
        assert_eq!(
            t("Get-Content a,b"),
            [("a".into(), Read), ("b".into(), Read)]
        );
    }

    #[test]
    fn writers_copiers_and_removers() {
        assert_eq!(
            t("Copy-Item a b"),
            [("a".into(), Read), ("b".into(), Write)]
        );
        assert_eq!(
            t("copy -Path a -Destination b"),
            [("a".into(), Read), ("b".into(), Write)]
        );
        assert_eq!(
            t("Move-Item a b"),
            [("a".into(), Remove), ("b".into(), Write)]
        );
        assert_eq!(t("Remove-Item -Recurse -Force x"), one("x", Remove));
        assert_eq!(t("del /q /f x"), one("x", Remove));
        assert_eq!(t("Rename-Item x y"), one("x", Remove));
        assert_eq!(t("Set-Content x text"), one("x", Write));
        assert_eq!(t("Set-Content -Value text -Path x"), one("x", Write));
        assert_eq!(t("Add-Content x text"), one("x", Write));
        assert_eq!(t("Clear-Content x"), one("x", Write));
        assert_eq!(t("Out-File -FilePath x"), one("x", Write));
        assert_eq!(t("New-Item -Force x"), one("x", Write));
        assert_eq!(t("Invoke-WebRequest http://u -OutFile x"), one("x", Write));
        assert_eq!(t("iwr http://u -o x"), one("x", Write));
    }

    #[test]
    fn values_that_are_not_files_are_not_files() {
        assert_eq!(t("Set-Content notes.txt .vahta"), one("notes.txt", Write));
        assert_eq!(
            t("Select-String -Pattern .vahta README.md"),
            one("README.md", Read)
        );
        assert!(t("Write-Host Get-Content .vahta").is_empty());
        assert!(t("echo .vahta").is_empty());
    }

    #[test]
    fn nested_shells_give_their_command() {
        let n = |l: &str| nested(&w(l));
        assert_eq!(
            nested(&["powershell".into(), "-Command".into(), "gc x".into()]).as_deref(),
            Some("gc x")
        );
        assert_eq!(
            nested(&[
                "pwsh".into(),
                "-NoProfile".into(),
                "-c".into(),
                "gc x".into()
            ])
            .as_deref(),
            Some("gc x")
        );
        assert_eq!(n("cmd /c type x").as_deref(), Some("type x"));
        assert_eq!(n("cmd.exe /D /C del x").as_deref(), Some("del x"));
        assert_eq!(n("pwsh -File s.ps1"), None);
        assert_eq!(n("cmd /?"), None);
        assert_eq!(n("git commit"), None);
    }

    #[test]
    fn dotnet_calls_name_their_files() {
        let d = |c: &str| -> Vec<(String, Role)> {
            dotnet(c).into_iter().map(|t| (t.path, t.role)).collect()
        };
        assert_eq!(d("[IO.File]::ReadAllBytes('a b')"), one("a b", Read));
        assert_eq!(
            d("$t = [System.IO.File]::ReadAllText(\"C:\\x\\y\")"),
            one("C:\\x\\y", Read)
        );
        assert_eq!(
            d("[io.file]::copy('a','b')"),
            [("a".into(), Read), ("b".into(), Write)]
        );
        assert_eq!(
            d("[IO.File]::WriteAllText('f', 'text, with comma')"),
            one("f", Write)
        );
        assert_eq!(d("[IO.Directory]::Delete('d', $true)"), one("d", Remove));
        assert!(d("[IO.File]::ReadAllText($p)").is_empty());
        assert!(d("[IO.Path]::Combine('a','b')").is_empty());
        assert!(d("echo [x]::y").is_empty());
    }

    #[test]
    fn variables_and_home_are_expanded() {
        let home = home().unwrap().to_string_lossy().into_owned();
        assert_eq!(expand("~"), home);
        assert_eq!(expand("~/x"), format!("{home}/x"));
        assert_eq!(expand("~\\x"), format!("{home}\\x"));
        assert_eq!(expand("$HOME\\x"), format!("{home}\\x"));
        assert_eq!(expand("${HOME}/x"), format!("{home}/x"));
        assert_eq!(
            expand("$env:USERPROFILE\\x"),
            format!("{}\\x", variable("USERPROFILE").unwrap())
        );
        assert_eq!(expand("~x"), "~x");
        assert_eq!(expand("$nothing\\x"), "$nothing\\x");
        assert_eq!(expand("100%"), "100%");
        let appdata = variable("APPDATA").unwrap();
        for spelling in [
            "$env:APPDATA\\v",
            "$ENV:appdata\\v",
            "${env:APPDATA}\\v",
            "%APPDATA%\\v",
            "%appdata%\\v",
        ] {
            assert_eq!(expand(spelling), format!("{appdata}\\v"), "{spelling}");
        }
        let local = variable("LOCALAPPDATA").unwrap();
        assert_eq!(expand("%LOCALAPPDATA%\\v"), format!("{local}\\v"));
    }
}
