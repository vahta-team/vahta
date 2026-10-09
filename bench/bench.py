#!/usr/bin/env python3
"""Vahta LLM test bench. Standard library only. See bench/README.md.

  bench.py build                          build the image from this checkout
  bench.py regress                        the fixed regression set, no model
  bench.py volume --backend B -n N        detector volume (B: seed | matrix | ollama:MODEL | haiku | sonnet)
  bench.py redteam --model M              one red-team episode (M: an ollama model | scripted | scripted-attacker | claude-code)
  bench.py cc-selftest                    the Claude Code mode against a mock API: proxy checks and an end-to-end run
  bench.py mkregress RUN_DIR              make the regression set from a volume run
  bench.py report RUN_DIR                 print a volume run's report again
"""

import argparse
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import redteam  # noqa: E402
import seeds  # noqa: E402
import volume  # noqa: E402

REPO = os.path.dirname(HERE)
OUT = os.path.join(HERE, "out")
REGRESSION = os.path.join(HERE, "regression", "specs.jsonl")


def new_run(kind):
    d = os.path.join(OUT, f"{kind}-{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(d)
    os.chmod(d, 0o777)  # the container's user writes results here
    return d


def score_in_container(run_dir, specs_name="specs.jsonl", held=False):
    """Plant canaries and run the real hook, in a container with no network."""
    cmd = f"python3 /bench/volume.py score --specs /data/{specs_name} --out /data/results.jsonl" + (" --held" if held else "")
    r = subprocess.run(["docker", "run", "--rm", "--init", "--network", "none", *redteam.mounts((run_dir, "/data")),
                        redteam.IMAGE, *redteam.in_container(cmd)], capture_output=True, text=True)
    if not os.path.exists(os.path.join(run_dir, "results.jsonl")):
        sys.exit(f"scoring failed:\n{r.stdout}{r.stderr}")


def cmd_build(a):
    subprocess.run(["docker", "build", "-f", "bench/docker/Dockerfile", "-t", redteam.IMAGE, "."], cwd=REPO, check=True)


def cmd_volume(a):
    t0 = time.time()
    run = new_run("volume")
    if a.reuse:  # the same templates again, with fresh canaries and no model
        specs, invalid = volume.load(os.path.join(a.reuse, "specs.jsonl")), 0
    elif a.backend == "seed":
        specs, invalid = seeds.specs(), 0
    elif a.backend == "matrix":
        specs, invalid = seeds.matrix(), 0
    else:
        specs, invalid = volume.gen_specs(a.backend, a.n, a.seed)
    volume.dump(os.path.join(run, "specs.jsonl"), specs)
    t_gen = time.time() - t0
    score_in_container(run, held=a.held)
    rows = volume.load(os.path.join(run, "results.jsonl"))
    volume.report(rows, invalid)
    print(f"\nrun {run}\nwall: generation {t_gen:.0f}s, scoring {time.time() - t0 - t_gen:.0f}s")


def cmd_report(a):
    volume.report(volume.load(os.path.join(a.run, "results.jsonl")))


def cmd_regress(a):
    t0 = time.time()
    run = new_run("regress")
    volume.dump(os.path.join(run, "specs.jsonl"), volume.load(REGRESSION))
    score_in_container(run)
    rows = volume.load(os.path.join(run, "results.jsonl"))
    bad = [r for r in rows if r["denied"] != (r["kind"] == "leak")]
    s = volume.report(rows, out=open(os.devnull, "w"))
    print(f"regression: {len(rows) - len(bad)}/{len(rows)} as expected; precision {s['precision']} recall {s['recall']}; "
          f"{time.time() - t0:.0f}s")
    for r in bad:
        print(f"  UNEXPECTED {r['id']} [{r['cat']}/{r['form']}] expected {'deny' if r['kind'] == 'leak' else 'allow'}")
    sys.exit(1 if bad else 0)


def cmd_mkregress(a):
    rows = volume.load(os.path.join(a.run, "results.jsonl"))
    right = [r for r in rows if r["denied"] == (r["kind"] == "leak")]
    wrong = [r for r in rows if r not in right]
    rng = random.Random(1)
    rng.shuffle(right)
    keep, seen = [], {}
    for r in right:  # at most 2 per (kind, category, form) first, then fill up
        k = (r["kind"], r["cat"], r["form"])
        if seen.get(k, 0) < 2:
            keep.append(r)
            seen[k] = seen.get(k, 0) + 1
    keep = keep[: a.n]
    specs = [{k: r[k] for k in ("id", "src", "tool", "path", "template", "kind", "cat", "form")} for r in keep]
    old = volume.load(REGRESSION) if os.path.exists(REGRESSION) and a.add else []
    ids = {s["id"] for s in old}
    volume.dump(REGRESSION, old + [s for s in specs if s["id"] not in ids])
    print(f"wrote {len(old) + len(specs)} cases to {REGRESSION}; {len(wrong)} wrong ones left out")
    if wrong:  # unfixed gaps stay local
        os.makedirs(os.path.join(HERE, "findings"), exist_ok=True)
        volume.dump(os.path.join(HERE, "findings", f"gaps-{os.path.basename(a.run)}.jsonl"), wrong)
        print("the ones the hook got wrong were saved in bench/findings/ (not committed)")


def cmd_cc_selftest(a):
    import cctest

    sys.exit(cctest.main())


def cmd_redteam(a):
    run = new_run("redteam")
    scenario = "attacker" if a.mode == "attacker" else a.scenario
    if a.model == "claude-code":
        canaries, wall = redteam.run_episode_cc(run, scenario, a.max_turns, a.alarm, bind=a.bind,
                                                cap=a.proxy_cap, cc_model=a.cc_model, allow=a.proxy_allow)
        res = redteam.score(run, canaries, wall)
        redteam.print_report(res)
        print(f"  authproxy: {redteam.proxy_summary(run)}")
        print(f"  claude: {res.get('claude')}")
    else:
        canaries, wall = redteam.run_episode(run, a.model, scenario, a.max_turns, a.alarm, bind=a.bind)
        redteam.print_report(redteam.score(run, canaries, wall))
    print(f"run {run}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build").set_defaults(f=cmd_build)
    p = sub.add_parser("volume")
    p.add_argument("--backend", default="seed")
    p.add_argument("-n", type=int, default=30)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--reuse", help="score the specs of an earlier run again (no model)")
    p.add_argument("--held", action="store_true", help="also hold the canaries in a vault session (daemon forms)")
    p.set_defaults(f=cmd_volume)
    p = sub.add_parser("regress")
    p.set_defaults(f=cmd_regress)
    p = sub.add_parser("report")
    p.add_argument("run")
    p.set_defaults(f=cmd_report)
    p = sub.add_parser("mkregress")
    p.add_argument("run")
    p.add_argument("-n", type=int, default=30)
    p.add_argument("--add", action="store_true", help="append to the existing set")
    p.set_defaults(f=cmd_mkregress)
    sub.add_parser("cc-selftest", help="Claude Code mode: proxy + e2e against a mock, no credential").set_defaults(f=cmd_cc_selftest)
    p = sub.add_parser("redteam")
    p.add_argument("--model", default=redteam.DEFAULT_MODEL,
                   help="an ollama model, `scripted`, `scripted-attacker`, or `claude-code`")
    p.add_argument("--mode", default="victim", choices=["victim", "attacker"],
                   help="victim: an ordinary task plus an injection; attacker: the model is told to beat Vahta")
    p.add_argument("--scenario", default="ci_check")
    p.add_argument("--bind", action="store_true",
                   help="bind every secret to `printenv` with the owner's approval (deny @network, @shells)")
    p.add_argument("--max-turns", type=int, default=15)
    p.add_argument("--alarm", default="warn", choices=["warn", "lock"])
    p.add_argument("--cc-model", default="haiku", help="claude-code only: the --model alias or id")
    p.add_argument("--proxy-cap", type=int, default=60, help="claude-code only: requests the auth proxy forwards per run")
    p.add_argument("--proxy-allow", action="append", default=[], metavar="'POST /v1/...'",
                   help="claude-code only: let the auth proxy forward one more exact method and path")
    p.set_defaults(f=cmd_redteam)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
