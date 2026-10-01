"""Differential check for the `--deep` scan: Rust against the Python spec.

Three layers, each compared against the interpreter rather than a hand-written
expectation, because the whole point is to agree with Python where Python is odd:

1. **The JSON parser.** Rust's `vahta_scan::json` against `json.loads`, on a
   list of hazards (NaN, duplicate keys, lone surrogates, huge integers, deep
   nesting, whitespace Python does and does not allow, ...) and on many
   generated and *mutated* documents. Compared as a canonical re-serialisation
   (key order, code points, float bit patterns) or as the same failure class:
   `JSONDecodeError`. Where `json.loads` raises `RecursionError` or `ValueError`
   (integer digit cap) Rust deliberately does not: it parses the document, and
   the expectation is an oracle that does not share the limit (the interpreter
   with the digit cap lifted, or the canonical form known by construction).
2. **One transcript.** `scan_py._findings_for_transcript` against the Rust one
   on generated JSONL files: secret-shaped values assembled at run time from
   pieces, JSON-in-strings, duplicate keys, lone surrogates inside values,
   odd line terminators, invalid UTF-8, BOM, NBSP padding, hostile nesting, and
   the progress callback's exact calls (and an exception it raises). Findings
   compared field for field; exceptions compared by class.
   **Where Python raises** (a line nested past its recursion limit, an integer
   over 4300 digits) Rust is deliberately different: it scans such a line
   instead of aborting. The expectation is then: Python on the same file with
   the hostile lines blanked out (line numbers kept) equals Rust on that file
   exactly; Rust on the original reports a superset of those line hits; and
   every hostile line that carries a planted secret is reported.
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
import re
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


def py_json_uncapped(text: str) -> str:
    """`py_json` with the integer digit cap lifted: the oracle where Rust has no cap."""
    old = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        return py_json(text)
    finally:
        sys.set_int_max_str_digits(old)


def rs_json(text: str) -> str:
    return _scan_rs._json_canonical(text)


def expected_json(text: str, known: dict[str, str]) -> str:
    """What Rust must return: Python's answer, except where Python gives up.

    Python's `ValueError` is checked against Python itself with the cap lifted.
    Its `RecursionError` has no oracle but construction: `known` maps those
    texts to their canonical form (or "!invalid").
    """
    want = py_json(text)
    if want == "!intlimit":
        want = py_json_uncapped(text)
    if want == "!recursion":
        if text not in known:
            raise AssertionError(f"no oracle for a text Python cannot parse: {text[:60]!r}")
        want = known[text]
    return want


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


def deep_cases() -> tuple[list[str], dict[str, str]]:
    """Deeply nested texts, and for each its canonical form known by construction."""
    cases: list[str] = []
    known: dict[str, str] = {}

    def add(text: str, canonical: str) -> None:
        cases.append(text)
        known[text] = canonical

    for n in (10, 500, 990, 1100, 5000, 40000, 51000, 60000, 100000, 1_000_000):
        add("[" * n + "]" * n, "[" * n + "]" * n)
        add('{"a":' * n + "1" + "}" * n, "{s61;|" * n + "i1;" + "}" * n)
        add("[" * n, "!invalid")  # unterminated
        add('{"a":' * n, "!invalid")
    return cases, known


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
    deep, known = deep_cases()
    texts = list(JSON_HAZARDS) + deep
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
        want, got = expected_json(text, known), rs_json(text)
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


def planted_secret(rng: random.Random) -> str:
    """Text that always reports as certain: a vendor-prefixed key, built at run time."""
    return "prefix " + "s" + "k" + "-" + "ant" + "-" + "".join(rng.choice(ALNUM + "_-") for _ in range(34)) + " suffix"


def hostile_line(rng: random.Random) -> tuple[str, bool]:
    """A line, and whether it carries a planted secret that must be reported.

    The nesting and big-integer kinds are the ones Python cannot scan: it raises
    and the whole scan aborts. Rust scans them, secret included.
    """
    k = rng.randrange(14)
    plant = rng.random() < 0.6
    core = json.dumps(planted_secret(rng)) if plant else "1"
    depth = rng.choice([1500, 3000, 5000, 20000, 60000])
    if k == 0:
        return "not json at all", False
    if k == 1:
        return "{" + '"a":' * 3, False
    if k == 2:
        return rng.choice(["NaN", "[NaN]", '{"a":Infinity,"api_key":"%s"}' % rand_value(rng), "-Infinity"]), False
    if k == 3:
        return "[" * depth + core + "]" * depth, plant  # past the recursion limit
    if k == 4:
        return '{"a":' * depth + core + "}" * depth, plant
    if k == 5:
        return json.dumps({"a": "[" * depth + core + "]" * depth}), plant  # nested in a string
    if k == 6:
        return "[" + "9" * 4301 + ", " + core + "]", plant  # ValueError, not a decode error
    if k == 7:
        return json.dumps({"a": "[" + "9" * 4301 + ", " + core + "]"}), plant
    if k == 8:
        return "[" * depth + json.dumps({pick_name(rng): "x"}) + "]" * depth, False  # deep, no secret
    if k == 9:
        return "[" + "9" * 4301 + "]", False
    if k == 10:
        # A secret-named key at the bottom, found by the key walk alone.
        return "[" * depth + '{"%s": %s}' % (rng.choice(["api_key", "token", "password"]), json.dumps(rand_value(rng) or "abc12345")) + "]" * depth, False
    if k == 11:
        return "[" * 900 + '"%s=%s"' % (pick_name(rng), rand_value(rng)) + "]" * 900, False  # deep but fine
    if k == 12:
        return "[x, " + "9" * 4301 + "]", False  # a syntax error first: skipped by both
    return "{'single': 'quotes'}", False


JUNK_BYTES = [b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf0\x9f\x92", b"\xe2\x82", b"\x80"]
PAD = ["", "", "", " ", "\t", "\xa0", " ", "\x0b", "\x0c", "\x1c", "\x85", "　", "﻿"]
TERMS = [b"\n", b"\n", b"\n", b"\r\n", b"\r"]


# Transcript bytes -> the 1-based lines that carry a planted secret in a line
# Python cannot scan. Keyed by content so it survives being written to a tree.
PLANTED: dict[bytes, list[int]] = {}


def make_transcript(rng: random.Random, hazard_rate: float) -> bytes:
    lines: list[bytes] = []
    planted: list[int] = []
    for _ in range(rng.randrange(1, 25)):
        r = rng.random()
        carries = False
        if r < 0.08:
            text = ""
        elif r < 0.08 + hazard_rate:
            text, carries = hostile_line(rng)
        else:
            text = json_line(rng)
        pad_a, pad_b = rng.choice(PAD), rng.choice(PAD)
        if "\ufeff" in pad_a + pad_b:
            carries = False  # a BOM is not whitespace to `str.strip`: the line is not JSON
        text = pad_a + text + pad_b
        raw = text.encode("utf-8", errors="surrogatepass")
        if rng.random() < 0.06:
            at = rng.randrange(len(raw) + 1)
            raw = raw[:at] + rng.choice(JUNK_BYTES) + raw[at:]
            carries = False
        lines.append(raw)
        if carries:
            planted.append(len(lines))
    out = b""
    for n, line in enumerate(lines):
        term = rng.choice(TERMS)
        if term == b"\r" and n + 1 < len(lines) and lines[n + 1] == b"":
            term = b"\n"  # a CR before an empty line could fuse with its LF and shift the numbering
        out += line + term
    if rng.random() < 0.2:
        out = out.rstrip(b"\r\n")  # no final newline
    if planted:
        PLANTED[out] = planted
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

_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def blank_hostile_lines(data: bytes, probe_dir: Path) -> tuple[bytes, list[int]]:
    """Blank every line Python's scan raises on, keeping the line numbers.

    Each non-blank line is scanned on its own, as a file, by the Python
    implementation; one that raises `RecursionError` or `ValueError` is the
    hostile kind. Any other exception is a harness bug and propagates.
    """
    text = data.decode("utf-8", errors="replace")
    parts = _LINE_BREAK.split(text)
    if parts and parts[-1] == "":
        parts.pop()
    probe = probe_dir / "probe.jsonl"
    hostile: list[int] = []
    for i, line in enumerate(parts):
        if not line.strip():
            continue
        probe.write_text(line + "\n", encoding="utf-8", newline="")
        try:
            scan_py._findings_for_transcript(probe, scope="deep")
        except (RecursionError, ValueError):
            hostile.append(i + 1)
            parts[i] = ""
    return ("\n".join(parts) + "\n").encode("utf-8"), hostile


def hit_map(findings, by_name: bool = False) -> dict[tuple, set[int]]:
    """(resolved path, confidence) -> hit lines, for the superset comparison.

    `by_name` keys on the file name alone, for comparing two copies of one file.
    """
    out: dict[tuple, set[int]] = {}
    for f in findings:
        d = f if isinstance(f, dict) else asdict(f)
        key = (Path(d["path"]).name if by_name else str(Path(d["path"]).resolve()), d["confidence"])
        out.setdefault(key, set()).update(d["hit_lines"])
    return out


def superset_problems(clean, original, by_name: bool = False) -> list[str]:
    """Problems if `original` fails to report everything `clean` does."""
    have, need = hit_map(original, by_name), hit_map(clean, by_name)
    out = []
    for key, lines in need.items():
        if not lines <= have.get(key, set()):
            out.append(f"{key[1]} lines {sorted(lines - have.get(key, set()))} of {Path(key[0]).name} lost")
    return out


def planted_problems(data: bytes, path: Path, original) -> list[str]:
    """Problems if a planted secret in `data` (written at `path`) is not reported."""
    lines = PLANTED.get(data)
    if not lines:
        return []
    tally("hostile lines with a planted secret checked")
    certain = hit_map(original).get((str(path.resolve()), "certain"), set())
    return [f"planted secret on line {n} of {path.name} not reported as certain" for n in lines if n not in certain]


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
        problems: list[str] = []
        if want[0] == "raise":
            tally(f"transcripts raising {want[1]}")
            if want[1] not in ("RecursionError", "ValueError"):
                problems.append(f"python raised {want[1]}, which is not a known hostile-input failure")
            else:
                clean_data, hostile = blank_hostile_lines(data, tmp)
                if not hostile:
                    problems.append("python raised but no single line reproduces it")
                (tmp / f"clean{i}").mkdir()
                clean = tmp / f"clean{i}" / path.name  # same name: findings are compared by it
                clean.write_bytes(clean_data)
                calls_clean_py: list = []
                calls_clean_rs: list = []
                want_clean = outcome(lambda: run_transcript(clean, scan_py, lambda *a: calls_clean_py.append(a)))
                got_clean = outcome(lambda: run_transcript(clean, _scan_rs, lambda *a: calls_clean_rs.append(a)))
                if want_clean[0] != "ok":
                    problems.append(f"python still raises with the hostile lines blanked: {want_clean}")
                if want_clean != got_clean or calls_clean_py != calls_clean_rs:
                    problems.append(f"clean file differs\n   python: {str(want_clean)[:300]}\n   rust:   {str(got_clean)[:300]}")
                if got[0] != "ok":
                    problems.append(f"rust raised on the original: {got}")
                else:
                    if calls_rs != calls_clean_rs:
                        problems.append("progress calls differ between original and clean")
                    if want_clean[0] == "ok":
                        problems += superset_problems(want_clean[1], got[1], by_name=True)
                    problems += planted_problems(data, path, got[1])
                clean.unlink()
                clean.parent.rmdir()
        else:
            for f in want[1]:
                tally(f"transcript findings: {f['confidence']}")
            if not want[1]:
                tally("transcripts with no findings")
            if want != got or calls_py != calls_rs:
                problems.append(f"python: {str(want)[:300]}\n   rust:   {str(got)[:300]}")
        if problems:
            failures.append(f"transcript {path.name} ({len(data)} bytes) kept at {path}\n   " + "\n   ".join(problems))
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


def deep_crash_problems(home: Path, root: Path, got, pb) -> list[str]:
    """Rust against a Python that aborted, on a fake HOME. Mutates `home`.

    Blanks the lines Python cannot scan (in place, in real files only, once
    each), then checks what `layer_transcripts` checks for one file, for the
    whole scan: the blanked tree agrees exactly between the two, and the
    original, scanned by Rust, reports a superset plus every planted secret.
    """
    shutil.copytree(home, root / "home-before-blanking", symlinks=True)  # for reproducing
    probe = root / "probe"
    probe.mkdir()
    problems: list[str] = []
    originals: dict[Path, bytes] = {}
    hostile_lines = 0
    for p in scan_py.iter_agent_transcript_files(home):
        rp = p.resolve()
        if rp in originals:
            continue
        data = originals[rp] = rp.read_bytes()
        clean, hostile = blank_hostile_lines(data, probe)
        if hostile:
            hostile_lines += len(hostile)
            rp.write_bytes(clean)
    if not hostile_lines:
        problems.append("python raised but no single line reproduces it")
    pa2: list = []
    pb2: list = []
    want_clean = outcome(lambda: scan_py.scan_deep(home, progress=lambda *a: pa2.append(a)))
    got_clean = outcome(lambda: _scan_rs.scan_deep(home, progress=lambda *a: pb2.append(a)))
    if want_clean[0] != "ok":
        problems.append(f"python still raises with the hostile lines blanked: {want_clean}")
    if want_clean != got_clean or pa2 != pb2:
        problems.append(f"blanked tree differs\n     python {str(want_clean)[:300]}\n     rust   {str(got_clean)[:300]}")
    if got[0] != "ok":
        problems.append(f"rust raised on the original: {got}")
        return problems
    if pb != pb2:
        problems.append("progress calls differ between the original and the blanked tree")
    if want_clean[0] == "ok":
        problems += superset_problems(want_clean[1], got[1])
    for rp, data in originals.items():
        problems += planted_problems(data, rp, got[1])
    return problems


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
            raised = want[0] == "raise"
            if raised:
                tally(f"deep scans raising {want[1]}")
                crash = deep_crash_problems(home, root, got, pb) if want[1] in ("RecursionError", "ValueError") else [
                    f"python raised {want[1]}, which is not a known hostile-input failure"]
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
        if raised:
            problems += crash
            if want_np[0] != "raise" or got_np != got:
                problems.append("scan_deep without progress differs from the one with")
        else:
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
                 "deep scans raising RecursionError", "deep scans raising ValueError",
                 "hostile lines with a planted secret checked",
                 "transcript findings: certain", "transcript findings: likely", "transcript findings: possible"):
        if COVERAGE.get(need, 0) == 0:
            bad.append(f"coverage: no case produced {need!r}")
    for f in bad[:30]:
        print("MISMATCH", f)
    print(f"{total} cases, {len(bad)} mismatches")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
