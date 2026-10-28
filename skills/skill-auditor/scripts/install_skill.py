#!/usr/bin/env python3
"""install_skill.py - install an AUDITED skill, optionally with the risky parts removed.

    python -I install_skill.py prepare <src> <stage> --name N [--drop PATH ...] [--strip-invisible]
                                                     [--drop-frontmatter-key KEY ...]
    python -I install_skill.py plan    <stage> --scope global|project [--project DIR]
    python -I install_skill.py apply   <stage> --scope global|project [--project DIR] --token T [--replace]

prepare  copies <src> into a NEW stage folder, applying mechanical changes (never follows symlinks,
         skips .git). You may then edit files in the stage by hand (for example delete an
         injected line) and run plan again.
plan     scans the stage, shows what differs from the original and where it would be installed,
         and prints a token that is valid only for this exact content and this exact target.
apply    installs only if the token matches, no CRITICAL finding remains, and the target does
         not exist (or --replace, which MOVES the old copy to <skills>/.removed/, never deletes).

There is deliberately no "yes to everything" flag. The token proves the content did not change
after the plan was shown; the user's consent is asked in chat between plan and apply.
Standard library only. Exit codes: 0 ok, 3 CRITICAL remains, 4 refused or error.
"""
import argparse, difflib, hashlib, importlib.util, json, os, re, shutil, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("scan_skill", os.path.join(HERE, "scan_skill.py"))
scan_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_mod)
safe = scan_mod.safe
NAME_RX = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
INVISIBLE = [scan_mod.ZW, scan_mod.BIDI, scan_mod.TAGS]


class Refuse(Exception):
    pass


def tree_files(root):
    out = []
    for dp, dn, fn in os.walk(root, followlinks=False):
        dn[:] = sorted(d for d in dn if d not in (".git", "__pycache__") and not os.path.islink(os.path.join(dp, d)))
        for f in sorted(fn):
            full = os.path.join(dp, f)
            if not os.path.islink(full):
                out.append(os.path.relpath(full, root).replace("\\", "/"))
    return out


def tree_hash(root):
    h = hashlib.sha256()
    for rel in tree_files(root):
        with open(os.path.join(root, rel), "rb") as fh:
            h.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(fh.read()).digest())
    return h.hexdigest()


def is_text(path):
    with open(path, "rb") as fh:
        return b"\0" not in fh.read(4096)


def inside(root, rel):
    full = os.path.realpath(os.path.join(root, rel))
    return full == os.path.realpath(root) or full.startswith(os.path.realpath(root) + os.sep)


def drop_fm_key(text, key):
    m = re.match(r"(---\s*\n)(.*?)(\n---\s*(\n|$))", text, re.S)
    if not m:
        return text, 0
    kept, skipping, n = [], False, 0
    for ln in m.group(2).split("\n"):
        if re.match(r"^%s\s*:" % re.escape(key), ln):
            skipping, n = True, n + 1
            continue
        if skipping and ln[:1] in (" ", "\t"):
            continue
        skipping = False
        kept.append(ln)
    return m.group(1) + "\n".join(kept) + m.group(3) + text[m.end():], n


def meta_path(stage):
    return os.path.abspath(stage).rstrip("\\/") + ".meta.json"


def prepare(a):
    src, stage = os.path.abspath(a.src), os.path.abspath(a.stage)
    if not os.path.isdir(src):
        raise Refuse("source is not a folder")
    if os.path.exists(stage):
        raise Refuse("stage already exists; choose a new empty path")
    if not NAME_RX.fullmatch(a.name):
        raise Refuse("name must be lowercase letters, digits and hyphens (max 64)")
    drops = [d.replace("\\", "/").strip("/") for d in a.drop or []]
    for d in drops:
        if not inside(src, d) or not os.path.exists(os.path.join(src, d)):
            raise Refuse("--drop path not found inside the source: " + d)
    files = tree_files(src)
    opaque = [f for f in files if scan_mod.classify(os.path.join(src, f), 0, open(os.path.join(src, f), "rb").read(4096)) in ("binary", "archive")
              and not any(f == d or f.startswith(d + "/") for d in drops)]
    if opaque:
        raise Refuse("binary/archive files cannot be audited; add --drop for each: " + ", ".join(safe(o, 80) for o in opaque))
    changes = []
    for rel in files:
        if any(rel == d or rel.startswith(d + "/") for d in drops):
            changes.append("dropped " + rel)
            continue
        dst = os.path.join(stage, *rel.split("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        s = os.path.join(src, *rel.split("/"))
        if not is_text(s):
            shutil.copyfile(s, dst)
            continue
        text = open(s, "rb").read().decode("utf-8", errors="replace")
        orig = text
        if a.strip_invisible:
            for rx in INVISIBLE:
                text = rx.sub("", text)
            if text != orig:
                changes.append("stripped invisible characters in " + rel)
        if rel.lower().endswith("skill.md"):
            for k in a.drop_frontmatter_key or []:
                text, n = drop_fm_key(text, k)
                if n:
                    changes.append("removed frontmatter key '%s' in %s" % (k, rel))
        with open(dst, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    if not os.path.isdir(stage):
        raise Refuse("nothing left to install")
    with open(meta_path(stage), "w", encoding="utf-8") as fh:
        json.dump(dict(name=a.name, source=src, source_hash=tree_hash(src), changes=changes), fh, indent=1)
    print("Stage created: %s\nName: %s\nMechanical changes (%d):" % (stage, a.name, len(changes)))
    for c in changes:
        print("  - " + safe(c, 200))
    print("Next: edit the stage by hand if needed, then run plan.")


def target_for(a, name):
    if a.scope == "global":
        return os.path.join(os.path.expanduser("~"), ".claude", "skills", name)
    if not a.project or not os.path.isdir(os.path.expanduser(a.project)):
        raise Refuse("--project must be an existing folder for scope=project")
    return os.path.join(os.path.abspath(os.path.expanduser(a.project)), ".claude", "skills", name)


def load_meta(stage):
    try:
        with open(meta_path(stage), encoding="utf-8") as fh:
            return json.load(fh)
    except OSError:
        raise Refuse("no prepare metadata for this stage; run prepare first")


def stage_diff(meta, stage, limit=160):
    src = meta["source"]
    lines = []
    old, new = set(tree_files(src)), set(tree_files(stage))
    for rel in sorted(old - new):
        lines.append("REMOVED  " + rel)
    for rel in sorted(new - old):
        lines.append("ADDED    " + rel)
    for rel in sorted(old & new):
        a_, b_ = os.path.join(src, rel), os.path.join(stage, rel)
        if open(a_, "rb").read() == open(b_, "rb").read():
            continue
        lines.append("CHANGED  " + rel)
        if is_text(a_):
            ta = open(a_, "rb").read().decode("utf-8", "replace").splitlines()
            tb = open(b_, "rb").read().decode("utf-8", "replace").splitlines()
            lines += ["    " + safe(l, 160) for l in difflib.unified_diff(ta, tb, "original", "to-install", lineterm="", n=0) if not l.startswith(("---", "+++"))]
    return lines[:limit] + (["... (%d more diff lines)" % (len(lines) - limit)] if len(lines) > limit else [])


def token_for(stage, target):
    return hashlib.sha256((tree_hash(stage) + "|" + os.path.abspath(target).lower() + "|v1").encode()).hexdigest()[:16]


def verdict_of(path):
    res = scan_mod.scan(path)
    top = max([scan_mod.SEV[f["severity"]] for f in res["findings"]] or [0])
    return res, top


def plan(a):
    stage = os.path.abspath(a.stage)
    meta = load_meta(stage)
    target = target_for(a, meta["name"])
    res, top = verdict_of(stage)
    print("Install plan for '%s'\n  from stage: %s\n  to:         %s%s" % (meta["name"], stage, target, "   (ALREADY EXISTS: needs --replace)" if os.path.exists(target) else ""))
    print("  scope:      %s" % ("GLOBAL: every project on this machine" if a.scope == "global" else "this project only"))
    d = stage_diff(meta, stage)
    print("\nDifferences from the audited original (%d):" % len(d) if d else "\nNo differences from the audited original.")
    for l in d:
        print("  " + l)
    counts = {}
    for f in res["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("\nScan of what would be installed: %s" % (", ".join("%d %s" % (n, s) for s, n in sorted(counts.items(), key=lambda x: -scan_mod.SEV[x[0]])) or "no findings"))
    for f in res["findings"]:
        if scan_mod.SEV[f["severity"]] >= 3:
            print("  %s %s %s:%s %s" % (f["severity"], f["rule"], safe(f["file"], 80), f["line"], safe(f["message"], 120)))
    if top >= 4:
        print("\nREFUSED: CRITICAL findings remain. Remove or fix them in the stage and run plan again.")
        return 3
    print("\nToken (valid only for this exact content and target): " + token_for(stage, target))
    print("Show the user the differences and every HIGH finding, and get an explicit yes before apply.")
    return 0


def apply(a):
    stage = os.path.abspath(a.stage)
    meta = load_meta(stage)
    target = target_for(a, meta["name"])
    if a.token != token_for(stage, target):
        raise Refuse("token does not match: the stage changed or the target differs since plan")
    res, top = verdict_of(stage)
    if top >= 4:
        print("REFUSED: CRITICAL findings remain.")
        return 3
    if os.path.exists(target):
        if not a.replace:
            raise Refuse("target exists; use --replace to move the old copy to .removed/")
        removed = os.path.join(os.path.dirname(target), ".removed")
        os.makedirs(removed, exist_ok=True)
        moved = os.path.join(removed, "%s-%s" % (meta["name"], time.strftime("%Y%m%d-%H%M%S")))
        shutil.move(target, moved)
        print("Old copy moved to " + moved)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copytree(stage, target, ignore=shutil.ignore_patterns(".git", "__pycache__"), symlinks=False)
    if tree_hash(target) != tree_hash(stage):
        raise Refuse("installed files differ from the stage; remove %s and retry" % target)
    inst, itop = verdict_of(target)
    log = os.path.join(os.path.expanduser("~"), ".claude", "skill-auditor-log.jsonl")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(dict(time=time.strftime("%Y-%m-%dT%H:%M:%S"), name=meta["name"], scope=a.scope, target=target,
                                 source=meta["source"], source_hash=meta["source_hash"], installed_hash=tree_hash(target),
                                 changes=meta["changes"], max_severity=[k for k, v in scan_mod.SEV.items() if v == itop][0])) + "\n")
    print("Installed: %s\nHash verified identical to the audited stage; rescan max severity: %s\nLogged in %s\nStart a new session for the skill to appear." % (target, [k for k, v in scan_mod.SEV.items() if v == itop][0], log))
    return 0


def main():
    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception: pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare"); p.add_argument("src"); p.add_argument("stage"); p.add_argument("--name", required=True)
    p.add_argument("--drop", action="append"); p.add_argument("--strip-invisible", action="store_true"); p.add_argument("--drop-frontmatter-key", action="append")
    for n in ("plan", "apply"):
        p = sub.add_parser(n); p.add_argument("stage"); p.add_argument("--scope", required=True, choices=["global", "project"]); p.add_argument("--project")
        if n == "apply":
            p.add_argument("--token", required=True); p.add_argument("--replace", action="store_true")
    a = ap.parse_args()
    try:
        return {"prepare": lambda: prepare(a) or 0, "plan": lambda: plan(a), "apply": lambda: apply(a)}[a.cmd]()
    except Refuse as e:
        print("REFUSED: " + str(e), file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
