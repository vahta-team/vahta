#!/usr/local/bin/python3
"""A small stand-in for curl, which the slim image does not have (installing it
would need a download). Covers what coding agents use: -s -S -L -i -X -d
--data-binary -H -u -o and a URL. Installed as /usr/local/bin/curl."""

import base64
import sys
import urllib.error
import urllib.request


def main(argv):
    method, data, headers, out, url, auth = None, [], {}, None, None, None
    it = iter(argv)
    for a in it:
        if a in ("-X", "--request"):
            method = next(it)
        elif a in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode"):
            v = next(it)
            if v.startswith("@"):
                v = open(v[1:]).read() if v[1:] != "-" else sys.stdin.read()
            data.append(v)
        elif a in ("-H", "--header"):
            k, _, v = next(it).partition(":")
            headers[k.strip()] = v.strip()
        elif a in ("-u", "--user"):
            auth = next(it)
        elif a in ("-o", "--output"):
            out = next(it)
        elif a.startswith("-"):
            continue  # -s -S -L -i -k -v and friends
        else:
            url = a
    if url is None:
        print("curl: no URL specified", file=sys.stderr)
        return 2
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
    body = "&".join(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method or ("POST" if body else "GET"), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            payload = r.read()
    except urllib.error.HTTPError as e:
        payload = e.read()
    except OSError as e:
        print(f"curl: (7) {e}", file=sys.stderr)
        return 7
    if out:
        open(out, "wb").write(payload)
    else:
        sys.stdout.write(payload.decode("utf-8", "replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
