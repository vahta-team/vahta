"""Differential check for the `--deep` scan: Rust against the Python spec.

Three layers, each compared against the interpreter rather than a hand-written
expectation, because the whole point is to agree with Python where Python is odd:

1. **The JSON parser.** Rust's `vahta_scan::json` against `json.loads`, on a
   list of hazards (NaN, duplicate keys, lone surrogates, huge integers, deep
   nesting, whitespace Python does and does not allow, ...) and on many
   generated and *mutated* documents. Compared as a canonical re-serialisation
   (key order, code points, float bit patterns) or as the same failure class:
   `JSONDecodeError`, `RecursionError`, or `ValueError` (integer digit cap).
2. **One transcript.** `scan_py._findings_for_transcript` against the Rust one
   on generated JSONL files: secret-shaped values assembled at run time from
   pieces, JSON-in-strings, duplicate keys, lone surrogates inside values,
   odd line terminators, invalid UTF-8, BOM, NBSP padding, hostile nesting, and
   the progress callback's exact calls (and an exception it raises). Findings
   compared field for field; exceptions compared by class.
3. **The whole deep scan** over generated fake HOME trees, including symlinks
   and duplicates: `scan_deep`, `iter_agent_transcript_files` (in order) and
   `_deep_candidate_paths`, progress calls included. Never touches a real home.

    cargo build --release -p vahta-pyext-scan
    cp target/release/lib_scan_rs.so src/key_amnesia/_scan_rs.so
    .venv/bin/python benchmarks/diff_transcripts.py [--seed N] [--scale K]

Exits non-zero on any mismatch. Every credential-shaped value is generated,
never a literal in this file.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
import shutil
import struct
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

os.environ.pop("KEY_AMNESIA_DETECT_IMPL", None)  # the spec must be pure Python
os.environ.pop("KEY_AMNESIA_SCAN_IMPL", None)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from key_amnesia import scan_py  # noqa: E402

try:
    from key_amnesia import _scan_rs  # noqa: E402
except ImportError:
    print("key_amnesia._scan_rs is not installed; build it first (see the docstring)", file=sys.stderr)
    raise SystemExit(2)

SURROGATE_BASE = 0x10F800

# --------------------------------------------------------------------------
# Layer 1: JSON
# --------------------------------------------------------------------------


def canon_py(value) -> str:
    """The same canonical form `Value::canonical` writes. Iterative."""
    out: list[str] = []
    work: list = [("v", value)]

    def cstr(s: str) -> str:
        cps = []
        for c in s:
            o = ord(c)
            if 0xD800 <= o < 0xE000:
                o = SURROGATE_BASE + (o - 0xD800)
            cps.append(format(o, "x"))
        return "s" + ".".join(cps) + ";"

    while work:
        kind, item = work.pop()
        if kind == "raw":
            out.append(item)
            continue
        v = item
        if v is None:
            out.append("n")
        elif v is True:
            out.append("t")
        elif v is False:
            out.append("f")
        elif isinstance(v, int):
            out.append(f"i{v};")
        elif isinstance(v, float):
            if v != v:
                out.append("dnan;")
            else:
                out.append("d" + struct.pack(">d", v).hex() + ";")
        elif isinstance(v, str):
            out.append(cstr(v))
        elif isinstance(v, list):
            out.append("[")
            work.append(("raw", "]"))
            for x in reversed(v):
                work.append(("v", x))
        elif isinstance(v, dict):
            out.append("{" + "".join(cstr(k) for k in v) + "|")
            work.append(("raw", "}"))
            for x in reversed(list(v.values())):
                work.append(("v", x))
        else:  # pragma: no cover
            raise AssertionError(type(v))
    return "".join(out)


def py_json(text: str) -> str:
    try:
        return canon_py(json.loads(text))
    except json.JSONDecodeError:
        return "!invalid"
    except RecursionError:
        return "!recursion"
    except ValueError:
        return "!intlimit"


def rs_json(text: str) -> str:
    return _scan_rs._json_canonical(text)


JSON_HAZARDS = [
    # literals Python accepts
    "NaN", "Infinity", "-Infinity", "[NaN,Infinity,-Infinity]", '{"a":NaN}',
    # near misses
    "nan", "inf", "+Infinity", "-NaN", "Infinit", "NaNa", "[NaN NaN]", "nulll", "[nullx]", "truefalse",
    # syntax Python rejects
    "[1,]", '{"a":1,}', "[,1]", "{,}", "[1 2]", "{'a':1}", "['a']", "// c\n1", "/* c */1", '{"a" 1}',
    '{"a":}', "{1:2}", "[", "{", '"abc', "", "   ", "\n", "[]]", "{}}", '{"a":1}{', "1 2", "[1]x",
    # whitespace
    " \t\n\r1", "1 \t\n\r", "\x0b1", "1\x0c", "\xa01", "1\xa0", " 1", "﻿1", "﻿[]", "\x1f1",
    # numbers
    "0", "-0", "-0.0", "0.0", "00", "01", "-01", "1.", ".5", "1.e5", "1e", "1e+", "1E-2", "1e5.5",
    "-", "--1", "+1", "0x10", "1_000", "١٢٣", "1e999", "-1e999", "1e-999", "[1e999,-1e999]", "0e0", "-0e0",
    "123456789012345678901234567890", "1" * 4300, "1" * 4301, "-" + "1" * 4300, "-" + "1" * 4301,
    "[" + "1" * 4301 + ",x]", "[x," + "1" * 4301 + "]", "1" * 4301 + ".5", "1" * 5000 + "e1",
    '{"a":' + "9" * 5000 + "}", "[" + "9" * 4301 + "," + "9" * 4301 + "]",
    # strings
    r'"\ud800"', r'"\udc00"', r'"\udbff"', r'"\udfff"', r'"😀"', r'"😀"',
    r'"\ud800\ud800"', r'"\ud800😀"', r'"\udc00\ud800"', r'"\ud800A"', r'"\ud800\n"',
    r'"\ud800abc"', r'"\ud800\u12"', r'"\ud800\uzzzz"', r'"\ud800\u"', r'"😀\ude00"',
    r'"\ud83d😀"', r'"\ude00\ud83d"', r'"\ud800\\ud800"', r'"éé€"',
    r'"\u0000"', r'"\u001f"', '"\x00"', '"\x1f"', '"\n"', '"\t"', '"\x7f"', '"\x85  "',
    r'"\x41"', r'"\u12"', r'"\u12g4"', '"\\', r'"\a"', r'"\u"', r'"\/"', r'"\b\f\n\r\t\"\\"',
    '"é😀世界"', '"\U0010ffff"', '"\U0010f800"',
    # keys
    r'{"\ud800":1,"\udc00":2,"\ud800":3}', '{"a":1,"b":2,"a":3}', '{"a":{"x":1},"a":[2]}', '{"":1,"":2}',
    '{"a":1,"b":2,"c":3,"a":4,"c":5,"b":6}',
    "{" + ",".join(f'"k{i}":{i}' for i in range(60)) + ',"k3":"x","k59":"y","k0":"z"}',
    '{"a":1 "b":2}', '{"a":1,,"b":2}', '{"a" :1}', '{ "a" : 1 }', '{"a":[1,{"b":null}]}',
    # structure
    "[[]]", "[{}]", "{}", "[]", '{"a":{}}', "[[[[[[[[[[1]]]]]]]]]]",
]


def deep_cases() -> list[str]:
    cases = []
    for n in (10, 500, 990, 1100, 5000, 40000, 51000):
        cases.append("[" * n + "]" * n)
        cases.append('{"a":' * n + "1" + "}" * n)
        cases.append("[" * n)  # unterminated: invalid, unless past the limit
    for n in (60000, 100000, 1_000_000):
        cases.append("[" * n + "]" * n)
        cases.append("[" * n)  # unterminated but already too deep: RecursionError
        cases.append('{"a":' * n)
    return cases


ALPHABET = list('abcXYZ019 _-.:/,"\\\n\t') + ["é", "世", "😀", "\x7f", "\x85", " ", "\U0010f800"]


def rand_json(rng: random.Random, depth: int = 0):
    r = rng.random()
    if depth > 4 or r < 0.35:
        k = rng.randrange(9)
        if k == 0:
            return None
        if k == 1:
            return rng.random() < 0.5
        if k == 2:
            return rng.choice([0, -0, 1, -1, 10**rng.randrange(1, 60), -(10**rng.randrange(1, 60))])
        if k == 3:
            return rng.choice([0.0, -0.0, 1.5, 1e300, -2.5e-10, 1e999, float("nan"), float("-inf"), 123456.789e5])
        return rand_str(rng)
    if r < 0.7:
        return [rand_json(rng, depth + 1) for _ in range(rng.randrange(0, 5))]
    return {rand_key(rng): rand_json(rng, depth + 1) for _ in range(rng.randrange(0, 5))}


def rand_str(rng: random.Random) -> str:
    n = rng.randrange(0, 12)
    chars = []
    for _ in range(n):
        r = rng.random()
        if r < 0.08:
            chars.append(chr(rng.choice([0xD800, 0xDBFF, 0xDC00, 0xDFFF, rng.randrange(0xD800, 0xE000)])))
        elif r < 0.12:
            chars.append(chr(rng.randrange(0x20, 0x2FF)))
        else:
            chars.append(rng.choice(ALPHABET))
    return "".join(chars)


def rand_key(rng: random.Random) -> str:
    return rng.choice(["a", "b", "api_key", "token", "x", "k", "A"]) if rng.random() < 0.6 else rand_str(rng)


def dump_random(rng: random.Random, value) -> str:
    """json.dumps with the knobs that change the *text*: escapes, spacing."""
    text = json.dumps(
        value,
        ensure_ascii=rng.random() < 0.5 and True,
        separators=rng.choice([(",", ":"), (", ", ": "), (",", ": ")]),
        allow_nan=True,
    )
    return text


MUTATE_WITH = list('[]{}",:\\ \n\t-+.eEuU0123456789ndtrfNIa') + [
    r"\ud800", r"\udc00", r"😀", "\x00", "\xa0", "﻿", "NaN", "Infinity", "-Infinity", "1" * 4301,
]


def mutate(rng: random.Random, text: str) -> str:
    for _ in range(rng.randrange(1, 4)):
        if not text:
            return text
        i = rng.randrange(len(text) + 1)
        op = rng.randrange(3)
        if op == 0 and i < len(text):
            text = text[:i] + text[i + 1 :]
        elif op == 1:
            text = text[:i] + rng.choice(MUTATE_WITH) + text[i:]
        elif i < len(text):
            text = text[:i] + rng.choice(MUTATE_WITH) + text[i + 1 :]
    return text


def surrogate_free(text: str) -> bool:
    """Rust receives a `str`, which cannot carry a literal lone surrogate."""
    try:
        text.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def layer_json(rng: random.Random, scale: int) -> tuple[int, list[str]]:
    texts = list(JSON_HAZARDS) + deep_cases()
    for _ in range(3000 * scale):
        value = rand_json(rng)
        text = dump_random(rng, value)
        texts.append(text)
        texts.append(mutate(rng, text))
        texts.append(mutate(rng, mutate(rng, text)))
    failures: list[str] = []
    checked = 0
    for text in texts:
        if not surrogate_free(text):
            continue
        checked += 1
        want, got = py_json(text), rs_json(text)
        if want != got:
            failures.append(f"json {text[:80]!r}{'...' if len(text) > 80 else ''}\n   python: {want[:100]}\n   rust:   {got[:100]}")
            if len(failures) >= 20:
                break
    return checked, failures


# --------------------------------------------------------------------------
# Layer 2: transcripts
# --------------------------------------------------------------------------

ALNUM = string.ascii_letters + string.digits
UPPER_DIG = string.ascii_uppercase + string.digits
NAMES = ["API_KEY", "api_key", "token", "TOKEN", "secret", "SECRET_KEY", "password", "DB_PASSWORD", "passwd",
         "private_key", "access_token", "client-secret", "host", "name", "user"]
WORDS = ["Get", "Token", "From", "Cache", "load", "Config", "Value", "build", "Header", "parse", "Key", "Store"]


def pick_name(rng):
    return rng.choice(NAMES)


def prefixed_token(rng: random.Random) -> str:
    """A vendor-prefixed credential shape, assembled from pieces at run time."""
    pieces = [
        ("s" + "k", "-" + "ant" + "-", ALNUM + "_-", 30),
        ("s" + "k", "-", ALNUM, 30),
        ("AK" + "IA", "", UPPER_DIG, 16),
        ("gh" + "p", "_", ALNUM, 30),
        ("glp" + "at", "-", ALNUM, 25),
        ("n" + "pm", "_", ALNUM, 30),
        ("AI" + "za", "", ALNUM + "_-", 30),
    ]
    a, b, alphabet, n = rng.choice(pieces)
    return a + b + "".join(rng.choice(alphabet) for _ in range(n + rng.randrange(0, 5)))


def rand_value(rng: random.Random) -> str:
    k = rng.randrange(9)
    if k == 0:
        return "".join(rng.choice(ALNUM) for _ in range(rng.randrange(8, 40)))
    if k == 1:
        return "".join(rng.choice(string.hexdigits.lower()) for _ in range(rng.choice([16, 24, 32, 40])))
    if k == 2:
        h = "".join(rng.choice("0123456789abcdef") for _ in range(32))
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    if k == 3:
        return "".join(rng.choice(WORDS) for _ in range(rng.randrange(2, 5)))
    if k == 4:
        return "-".join(rng.choice(["correct", "horse", "battery", "staple", "mango", "river"]) for _ in range(3))
    if k == 5:
        return rng.choice(["changeme", "xxxxxxxx", "your-api-key-here", "${API_KEY}", "<token>", "null", "None", ""])
    if k == 6:
        return "".join(rng.choice(ALNUM + "+/=") for _ in range(rng.randrange(16, 60)))
    if k == 7:
        return rng.choice(["getToken()", "str", "os.environ['X']", "Dict[str, int]", "./path/to/file", "/etc/passwd"])
    return "".join(rng.choice(ALNUM) for _ in range(rng.randrange(1, 8)))


def with_surrogates(rng: random.Random, value: str) -> str:
    """Splice lone surrogates into a value, so entropy and classes are exercised."""
    out = list(value)
    for _ in range(rng.randrange(1, 4)):
        out.insert(rng.randrange(len(out) + 1), chr(rng.randrange(0xD800, 0xE000)))
    return "".join(out)


def assignment_text(rng: random.Random, name: str, value: str) -> str:
    form = rng.randrange(7)
    if form == 0:
        return f"{name}={value}"
    if form == 1:
        return f'"{name}": "{value}"'
    if form == 2:
        return f"export {name.upper()}='{value}'"
    if form == 3:
        return f"mysql --{name.lower().replace('_', '-')} {value} -u root"
    if form == 4:
        return f"Authorization: Bearer {value}"
    if form == 5:
        return f"note: {name} is {value}, ok"
    return f"{name}: {value}"


def text_blob(rng: random.Random) -> str:
    parts = []
    for _ in range(rng.randrange(1, 4)):
        r = rng.random()
        if r < 0.25:
            parts.append(rng.choice(["hello", "ran the tests", "ok", "see file.py line 3", "done", "ls -la"]))
        elif r < 0.45:
            parts.append("prefix " + prefixed_token(rng) + " suffix")
        else:
            v = rand_value(rng)
            if rng.random() < 0.25:
                v = with_surrogates(rng, v)
            parts.append(assignment_text(rng, pick_name(rng), v))
    return "\n".join(parts) if rng.random() < 0.3 else " ".join(parts)


def wrap(rng: random.Random, payload):
    s = rng.randrange(4)
    if s == 0:
        return {"type": "user", "message": {"role": "user", "content": payload}}
    if s == 1:
        return {"type": "assistant", "message": {"content": [{"type": "text", "text": payload}]}}
    if s == 2:
        return {"payload": {"type": "message", "content": [{"type": "input_text", "text": payload}]}}
    return {"type": "tool_result", "data": {"output": payload, "n": rng.randrange(100)}}


def json_line(rng: random.Random) -> str:
    k = rng.randrange(10)
    if k <= 2:
        return json.dumps(wrap(rng, text_blob(rng)))
    if k == 3:  # JSON in a string, one level
        inner = {"note": "x", pick_name(rng): rand_value(rng), "list": [text_blob(rng)]}
        return json.dumps(wrap(rng, json.dumps(inner)))
    if k == 4:  # two levels
        inner = {"deeper": json.dumps({pick_name(rng): rand_value(rng), "t": text_blob(rng)})}
        return json.dumps(wrap(rng, json.dumps(inner)))
    if k == 5:  # secret-named keys, no assignment text
        return json.dumps({"message": {"content": "hi", pick_name(rng): rand_value(rng),
                                       "args": [{pick_name(rng): rand_value(rng)}]}})
    if k == 6:  # duplicate keys, written raw
        a, b = rand_value(rng), rand_value(rng)
        n = pick_name(rng)
        return '{"%s":%s,"x":1,"%s":%s}' % (n, json.dumps(a), n, json.dumps(b))
    if k == 7:  # lone surrogates in a secret-keyed value
        v = with_surrogates(rng, rand_value(rng) or "abc12345")
        return json.dumps({pick_name(rng): v, "t": [with_surrogates(rng, text_blob(rng))]})
    if k == 8:  # a string that is only a container, or looks like one
        return json.dumps(rng.choice(["[]", "{}", " [1,2]", "{not json", "[" + text_blob(rng) + "]", "  {\"a\": 1} x"]))
    return json.dumps(rng.choice([1, 2.5, None, True, "plain string", [], {}, [1, [2, [3]]]]))


def hostile_line(rng: random.Random) -> str:
    k = rng.randrange(9)
    if k == 0:
        return "not json at all"
    if k == 1:
        return "{" + '"a":' * 3
    if k == 2:
        return rng.choice(["NaN", "[NaN]", '{"a":Infinity,"api_key":"%s"}' % rand_value(rng), "-Infinity"])
    if k == 3:
        return "[" * 1500 + "]" * 1500  # past the recursion limit
    if k == 4:
        return json.dumps({"a": "[" * 1500 + "]" * 1500})  # nested in a string
    if k == 5:
        return "[" + "9" * 4301 + "]"  # ValueError, not a decode error
    if k == 6:
        return json.dumps({"a": "[" + "9" * 4301 + "]"})
    if k == 7:
        return "[" * 900 + '"%s=%s"' % (pick_name(rng), rand_value(rng)) + "]" * 900  # deep but fine
    return "{'single': 'quotes'}"


JUNK_BYTES = [b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf0\x9f\x92", b"\xe2\x82", b"\x80"]
PAD = ["", "", "", " ", "\t", "\xa0", " ", "\x0b", "\x0c", "\x1c", "\x85", "　", "﻿"]
TERMS = [b"\n", b"\n", b"\n", b"\r\n", b"\r"]


def make_transcript(rng: random.Random, hazard_rate: float) -> bytes:
    lines: list[bytes] = []
    for _ in range(rng.randrange(1, 25)):
        r = rng.random()
        if r < 0.08:
            text = ""
        elif r < 0.08 + hazard_rate:
            text = hostile_line(rng)
        else:
            text = json_line(rng)
        text = rng.choice(PAD) + text + rng.choice(PAD)
        raw = text.encode("utf-8", errors="surrogatepass")
        if rng.random() < 0.06:
            at = rng.randrange(len(raw) + 1)
            raw = raw[:at] + rng.choice(JUNK_BYTES) + raw[at:]
        lines.append(raw)
    out = b""
    for line in lines:
        out += line + rng.choice(TERMS)
    if rng.random() < 0.2:
        out = out.rstrip(b"\r\n")  # no final newline
    return out


def outcome(fn):
    """('ok', findings-as-dicts) or ('raise', class name)."""
    try:
        return ("ok", [asdict(f) for f in fn()])
    except BaseException as e:  # noqa: BLE001 — comparing failure classes is the point
        return ("raise", type(e).__name__)


def run_transcript(path: Path, impl, progress=None):
    return impl._findings_for_transcript(path, scope="deep", progress=progress)


COVERAGE: dict[str, int] = {}


def tally(key: str) -> None:
    COVERAGE[key] = COVERAGE.get(key, 0) + 1


def layer_transcripts(rng: random.Random, scale: int) -> tuple[int, list[str]]:
    failures: list[str] = []
    checked = 0
    tmp = Path(tempfile.mkdtemp(prefix="diff-transcripts-"))
    for i in range(500 * scale):
        hazard = 0.0 if i % 3 else 0.25
        data = make_transcript(rng, hazard)
        path = tmp / f"case{i}.jsonl"
        path.write_bytes(data)
        calls_py: list = []
        calls_rs: list = []
        want = outcome(lambda: run_transcript(path, scan_py, lambda *a: calls_py.append(a)))
        got = outcome(lambda: run_transcript(path, _scan_rs, lambda *a: calls_rs.append(a)))
        checked += 1
        if want[0] == "raise":
            tally(f"transcripts raising {want[1]}")
        else:
            for f in want[1]:
                tally(f"transcript findings: {f['confidence']}")
            if not want[1]:
                tally("transcripts with no findings")
        if want != got or calls_py != calls_rs:
            failures.append(f"transcript {path.name} ({len(data)} bytes) kept at {path}\n   python: {str(want)[:300]}\n   rust:   {str(got)[:300]}")
            if len(failures) >= 10:
                return checked, failures
            continue
        path.unlink()

    # Cadence: a long file, blank lines included, and a callback that raises.
    n = scan_py._PROGRESS_LINE_EVERY * 3 + 17
    for kind in ("plain", "crlf", "cr-only", "blank-heavy"):
        body = {"plain": '{"t":"ok"}\n', "crlf": '{"t":"ok"}\r\n', "cr-only": '{"t":"ok"}\r', "blank-heavy": "\n"}[kind] * n
        path = tmp / f"long-{kind}.jsonl"
        path.write_text(body, encoding="utf-8", newline="")
        a: list = []
        b: list = []
        want = outcome(lambda: run_transcript(path, scan_py, lambda *x: a.append(x)))
        got = outcome(lambda: run_transcript(path, _scan_rs, lambda *x: b.append(x)))
        checked += 1
        if want != got or a != b:
            failures.append(f"progress cadence {kind}: python {a} rust {b}")

    path = tmp / "long-plain.jsonl"

    def boom_after(counter):
        def cb(*args):
            counter.append(args)
            if len(counter) == 2:
                raise KeyError("stop")
        return cb

    a, b = [], []
    want = outcome(lambda: run_transcript(path, scan_py, boom_after(a)))
    got = outcome(lambda: run_transcript(path, _scan_rs, boom_after(b)))
    checked += 1
    if want != got or a != b or want != ("raise", "KeyError"):
        failures.append(f"progress exception: python {want} {a}; rust {got} {b}")

    # A missing file and a directory.
    for label, make in (("missing", lambda: tmp / "nope.jsonl"), ("directory", lambda: tmp)):
        p = make()
        want, got = outcome(lambda: run_transcript(p, scan_py)), outcome(lambda: run_transcript(p, _scan_rs))
        checked += 1
        if want != got:
            failures.append(f"{label}: python {want} rust {got}")
    if not failures:
        shutil.rmtree(tmp, ignore_errors=True)
    return checked, failures


# --------------------------------------------------------------------------
# Layer 3: whole deep scans over fake HOME trees
# --------------------------------------------------------------------------


def build_home(rng: random.Random, root: Path, hazard: float = 0.1) -> Path:
    home = root / "home"
    home.mkdir()

    def put(rel: str, data: bytes | str):
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            p.write_text(data, encoding="utf-8")
        else:
            p.write_bytes(data)
        return p

    def tr() -> bytes:
        return make_transcript(rng, hazard)

    def maybe(p: float) -> bool:
        return rng.random() < p

    if maybe(0.7):
        put(".env", f"{pick_name(rng).upper()}={rand_value(rng) or 'abc12345'}\n")
    if maybe(0.4):
        put(".env.local", "# nothing\n")
    if maybe(0.5):
        put(".npmrc", "registry=https://example.invalid/\n")
    if maybe(0.5):
        put(".bash_history", "ls\n" + assignment_text(rng, pick_name(rng), rand_value(rng)) + "\n")
    if maybe(0.5):
        put(".gitconfig", "[user]\n name = x\n")
    for key in ("id_rsa", "id_ed25519"):
        if maybe(0.5):
            put(f".ssh/{key}", "PRIVATE\n")
    if maybe(0.5):
        put(".cursor/mcp.json", json.dumps({"mcpServers": {"a": {"command": "x"}}}))
    if maybe(0.4):
        put(".claude/mcp.json", json.dumps({"something": 1}))

    for i in range(rng.randrange(0, 5)):
        put(f".claude/projects/proj{rng.randrange(3)}/s{i}.jsonl", tr())
    for i in range(rng.randrange(0, 3)):
        put(f".claude/projects/p/{i}/sub/agent-{i}.jsonl", tr())
    for i in range(rng.randrange(0, 3)):
        put(f".codex/sessions/2026/0{i + 1}/01/rollout-{i}.jsonl", tr())
        if maybe(0.5):
            put(f".codex/sessions/2026/0{i + 1}/01/notrollout-{i}.jsonl", tr())
    if maybe(0.4):
        put(".codex/archived_sessions/rollout-old.jsonl", tr())
        put(".codex/archived_sessions/rollout-.jsonl", tr())
        put(".codex/archived_sessions/rollout.jsonl", tr())
    for i in range(rng.randrange(0, 3)):
        put(f".copilot/session-state/sess-{i}/events.jsonl", tr())
    if maybe(0.4):
        put(".copilot/session-state/loose-file.jsonl", tr())
    if maybe(0.5):
        put(".claude/projects/.hidden/h.jsonl", tr())
    if maybe(0.3):
        put(".claude/projects/dir.jsonl/inner.jsonl", tr())  # a directory named *.jsonl

    # Symlinks and duplicates.
    real = home / ".claude" / "projects"
    if real.is_dir() and maybe(0.7):
        target = put(".claude/projects/real/target.jsonl", tr())
        (real / "real" / "alias.jsonl").symlink_to(target)
        (real / "z-alias.jsonl").symlink_to(target)
    (home / ".claude" / "projects").mkdir(parents=True, exist_ok=True)
    if maybe(0.4):
        (home / ".claude" / "projects" / "broken.jsonl").symlink_to(home / "nowhere.jsonl")
    if maybe(0.4):
        elsewhere = root / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "ext.jsonl").write_bytes(tr())
        (home / ".claude" / "projects").mkdir(parents=True, exist_ok=True)
        (home / ".claude" / "projects" / "linkdir").symlink_to(elsewhere, target_is_directory=True)  # not followed by **
        (home / ".claude" / "projects" / "ext-link.jsonl").symlink_to(elsewhere / "ext.jsonl")
    if maybe(0.3) and (home / ".env").exists():
        (home / ".env.local").unlink(missing_ok=True)
        (home / ".env.local").symlink_to(home / ".env")  # candidate duplicate by resolved path
    if maybe(0.3):
        other = root / "other-home"
        other.mkdir()
        (home / ".copilot" / "session-state").mkdir(parents=True, exist_ok=True)
        d = other / "linked-session"
        d.mkdir()
        (d / "events.jsonl").write_bytes(tr())
        (home / ".copilot" / "session-state" / "via-link").symlink_to(d, target_is_directory=True)
    return home


def layer_deep(rng: random.Random, scale: int) -> tuple[int, list[str]]:
    failures: list[str] = []
    checked = 0
    for i in range(60 * scale):
        root = Path(tempfile.mkdtemp(prefix="diff-deep-"))
        home = build_home(rng, root)
        appdata = root / "appdata"
        env_cases = [None, str(appdata), ""]
        if rng.random() < 0.5:
            (appdata / "Claude").mkdir(parents=True)
            (appdata / "Claude" / "claude_desktop_config.json").write_text('{"mcpServers": {}}')
            (appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine").mkdir(parents=True)
            (appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt").write_text(
                assignment_text(rng, pick_name(rng), rand_value(rng)) + "\n")
        env = rng.choice(env_cases)
        old = os.environ.get("APPDATA")
        try:
            if env is None:
                os.environ.pop("APPDATA", None)
            else:
                os.environ["APPDATA"] = env

            order_py = [str(p) for p in scan_py.iter_agent_transcript_files(home)]
            order_rs = [str(p) for p in _scan_rs.iter_agent_transcript_files(home)]
            cand_py = sorted(str(p) for p in scan_py._deep_candidate_paths(home))
            cand_rs = sorted(str(p) for p in _scan_rs._deep_candidate_paths(home))

            pa: list = []
            pb: list = []
            want = outcome(lambda: scan_py.scan_deep(home, progress=lambda *a: pa.append(a)))
            got = outcome(lambda: _scan_rs.scan_deep(home, progress=lambda *a: pb.append(a)))
            want_np = outcome(lambda: scan_py.scan_deep(home))
            got_np = outcome(lambda: _scan_rs.scan_deep(home))
        finally:
            if old is None:
                os.environ.pop("APPDATA", None)
            else:
                os.environ["APPDATA"] = old
        checked += 1
        problems = []
        if order_py != order_rs:
            problems.append(f"transcript order\n     python {order_py}\n     rust   {order_rs}")
        if cand_py != cand_rs:
            problems.append("candidate paths differ")
        if want != got:
            problems.append(f"scan_deep\n     python {str(want)[:300]}\n     rust   {str(got)[:300]}")
        if want_np != got_np:
            problems.append("scan_deep without progress")
        if pa != pb:
            problems.append(f"progress calls\n     python {pa[:6]}\n     rust   {pb[:6]}")
        if problems:
            failures.append(f"deep tree {home} (kept): " + "; ".join(problems))
            if len(failures) >= 5:
                break
        else:
            shutil.rmtree(root, ignore_errors=True)
    return checked, failures


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=20260418)
    ap.add_argument("--scale", type=int, default=1, help="multiply the generated case counts")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    print(f"Python {sys.version.split()[0]}, seed {args.seed}, scale {args.scale}")
    total = 0
    bad: list[str] = []
    for label, layer in (("json", layer_json), ("transcripts", layer_transcripts), ("deep", layer_deep)):
        n, failures = layer(rng, args.scale)
        total += n
        print(f"  {label:12} {n:7} cases  {len(failures):3} mismatches")
        bad.extend(failures)
    for key in sorted(COVERAGE):
        print(f"    covered: {key}: {COVERAGE[key]}")
    # A harness that stops exercising a hazard is a harness that stopped
    # checking it: require each class of outcome to occur.
    for need in ("transcripts raising RecursionError", "transcripts raising ValueError",
                 "transcript findings: certain", "transcript findings: likely", "transcript findings: possible"):
        if COVERAGE.get(need, 0) == 0:
            bad.append(f"coverage: no case produced {need!r}")
    for f in bad[:30]:
        print("MISMATCH", f)
    print(f"{total} cases, {len(bad)} mismatches")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
