#!/usr/bin/env python3
"""App Store Connect API → Analytics Reports + Sales reports, as normalized CSVs.

Standard library only. ES256 JWT signing uses the `cryptography` package if installed,
otherwise the `openssl` CLI. Everything is read-only except `request`, which creates an
Analytics report request (needs an Admin key the first time a report type is requested).

Config (env vars win over <skill>/.env; see .env.example):
  ASC_KEY_ID            key ID from App Store Connect → Users and Access → Integrations
  ASC_ISSUER_ID         issuer ID (team keys). Leave empty + ASC_KEY_TYPE=individual for an individual key
  ASC_PRIVATE_KEY_PATH  path to AuthKey_<KEY_ID>.p8 (default: <skill>/secrets/ or ~/.appstoreconnect/private_keys/)
  ASC_APP_ID            default app Apple ID (numeric) for analytics commands
  ASC_VENDOR_NUMBER     vendor number, only for `sales`

Commands:
  asc_fetch.py check                                    # config, key file, token, list apps
  asc_fetch.py selftest                                 # JWT signing round-trip with a throwaway key (no network)
  asc_fetch.py apps
  asc_fetch.py requests [--app ID]                      # analytics report requests (ONGOING / ONE_TIME_SNAPSHOT)
  asc_fetch.py request  [--app ID] --access ongoing|snapshot   # WRITE: create a request (idempotent)
  asc_fetch.py reports  [--app ID] [--name downloads]   # report names/categories per request
  asc_fetch.py download [--app ID] --report "App Store Downloads" [--variant standard|detailed]
                        [--granularity DAILY] [--access ongoing|snapshot|any] [--start D --end D] --out DIR
  asc_fetch.py summarize --in DIR [--columns | --distinct COL]
                        [--filter "Territory=US"] [--filter "Download Type=First-time Download"]
                        [--start D --end D] [--group Date] [--pivot "Source Type"] [--sum Counts]
                        [--paid-shape METRIC] [--no-dedupe] [--out file.csv]
  asc_fetch.py sales    --start D --end D --out DIR [--vendor N] [--version 1_0]   # daily SALES SUMMARY .gz
  asc_fetch.py sales-summary --in DIR [--country US] [--start D --end D] [--paid-shape] [--out file.csv]
"""

import argparse
import base64
import csv
import datetime as dt
import glob
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "https://api.appstoreconnect.apple.com"
KNOWN_METRICS = {"counts", "unique counts", "purchases", "proceeds in usd", "sales in usd",
                 "paying users", "units", "unique devices", "sessions", "total session duration"}
NON_SUMMABLE = {"paying users", "unique counts", "unique devices"}


# ---------------------------------------------------------------- config

def load_config():
    cfg = {}
    env_path = os.path.join(SKILL_DIR, ".env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k in ("ASC_KEY_ID", "ASC_ISSUER_ID", "ASC_KEY_TYPE", "ASC_PRIVATE_KEY_PATH", "ASC_APP_ID",
              "ASC_VENDOR_NUMBER"):
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    return {k: v for k, v in cfg.items() if v}


def key_path(cfg):
    kid = cfg.get("ASC_KEY_ID", "")
    cands = []
    if cfg.get("ASC_PRIVATE_KEY_PATH"):
        p = os.path.expanduser(cfg["ASC_PRIVATE_KEY_PATH"])
        cands.append(p if os.path.isabs(p) else os.path.join(SKILL_DIR, p))
    cands += [os.path.join(SKILL_DIR, "secrets", f"AuthKey_{kid}.p8"),
              os.path.expanduser(f"~/.appstoreconnect/private_keys/AuthKey_{kid}.p8")]
    for p in cands:
        if os.path.isfile(p):
            return p
    return None


def require(cfg, *keys):
    miss = [k for k in keys if not cfg.get(k)]
    if miss:
        sys.exit(f"missing {', '.join(miss)} — set them in {os.path.join(SKILL_DIR, '.env')} "
                 f"(see .env.example / README.md 'Gather the credentials')")


# ---------------------------------------------------------------- JWT (ES256)

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def der_to_raw(der, size=32):
    """ECDSA DER signature → raw r||s (JWS ES256)."""
    if der[0] != 0x30:
        raise ValueError("not a DER ECDSA signature")
    i = 2 + (der[1] & 0x7F if der[1] & 0x80 else 0)
    out = b""
    for _ in range(2):
        if der[i] != 0x02:
            raise ValueError("bad DER integer")
        ln = der[i + 1]
        v = der[i + 2:i + 2 + ln].lstrip(b"\x00")
        out += v.rjust(size, b"\x00")
        i += 2 + ln
    return out


def raw_to_der(raw):
    def integer(b):
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


def sign_es256(pem_path, msg):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = serialization.load_pem_private_key(open(pem_path, "rb").read(), None)
        der = key.sign(msg, ec.ECDSA(hashes.SHA256()))
    except ImportError:
        r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", pem_path], input=msg,
                           capture_output=True)
        if r.returncode:
            sys.exit(f"openssl signing failed: {r.stderr.decode(errors='replace').strip()}")
        der = r.stdout
    return der_to_raw(der)


def make_jwt(cfg, pem_path, lifetime=1140):
    now = int(time.time())
    header = {"alg": "ES256", "kid": cfg["ASC_KEY_ID"], "typ": "JWT"}
    payload = {"iat": now, "exp": now + lifetime, "aud": "appstoreconnect-v1"}
    if cfg.get("ASC_KEY_TYPE", "").lower() == "individual" or not cfg.get("ASC_ISSUER_ID"):
        payload["sub"] = "user"
    else:
        payload["iss"] = cfg["ASC_ISSUER_ID"]
    signing_input = f"{b64url(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    return signing_input + "." + b64url(sign_es256(pem_path, signing_input.encode()))


# ---------------------------------------------------------------- HTTP

class ApiError(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body
        detail = body
        try:
            errs = json.loads(body).get("errors", [])
            detail = "; ".join(f"{e.get('code')}: {e.get('title')} — {e.get('detail')}" for e in errs) or body
        except (ValueError, AttributeError):
            pass
        super().__init__(f"HTTP {status}: {detail[:800]}")


class ASC:
    def __init__(self, cfg):
        require(cfg, "ASC_KEY_ID")
        if not cfg.get("ASC_ISSUER_ID") and cfg.get("ASC_KEY_TYPE", "").lower() != "individual":
            sys.exit("ASC_ISSUER_ID is empty — set it (team key) or set ASC_KEY_TYPE=individual")
        self.cfg = cfg
        self.pem = key_path(cfg)
        if not self.pem:
            sys.exit(f"private key AuthKey_{cfg['ASC_KEY_ID']}.p8 not found — put it in "
                     f"{os.path.join(SKILL_DIR, 'secrets')}/ or set ASC_PRIVATE_KEY_PATH")
        self._tok, self._exp = None, 0

    def token(self):
        if not self._tok or time.time() > self._exp - 60:
            self._tok, self._exp = make_jwt(self.cfg, self.pem), time.time() + 1140
        return self._tok

    def call(self, method, path, params=None, body=None, accept="application/json"):
        url = path if path.startswith("http") else BASE + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, safe="[],")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token()}", "Accept": accept,
            **({"Content-Type": "application/json"} if data else {})})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            err = ApiError(e.code, e.read().decode(errors="replace"))
            if e.code == 401:
                err.args = (err.args[0] + "\n  → check ASC_KEY_ID / ASC_ISSUER_ID match the .p8, "
                            "the key is not revoked, and the system clock is right",)
            if e.code == 403:
                err.args = (err.args[0] + "\n  → the key's role lacks access (creating a report "
                            "request needs Admin; reading needs Admin, Sales and Reports or Finance)",)
            raise err

    def get_all(self, path, params=None):
        out, url = [], path
        while url:
            _, raw = self.call("GET", url, params)
            doc = json.loads(raw)
            out += doc.get("data", [])
            url, params = doc.get("links", {}).get("next"), None
        return out


def app_id(args, cfg):
    a = getattr(args, "app", None) or cfg.get("ASC_APP_ID")
    if not a:
        sys.exit("no app — pass --app <Apple ID> or set ASC_APP_ID (find it with `asc_fetch.py apps`)")
    return a


# ---------------------------------------------------------------- commands: setup

def cmd_selftest(args):
    with tempfile.TemporaryDirectory() as d:
        k, pub = os.path.join(d, "AuthKey_TEST.p8"), os.path.join(d, "pub.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-out", k], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", k, "-pubout", "-out", pub], check=True, capture_output=True)
        tok = make_jwt({"ASC_KEY_ID": "TEST", "ASC_ISSUER_ID": "issuer"}, k)
        h, p, s = tok.split(".")
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        sig = os.path.join(d, "sig.der")
        open(sig, "wb").write(raw_to_der(raw))
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig],
                           input=f"{h}.{p}".encode(), capture_output=True)
        ok = r.returncode == 0 and len(raw) == 64
        print("JWT ES256 self-test:", "OK" if ok else f"FAILED {r.stdout} {r.stderr}")
        print("payload:", base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode())
        sys.exit(0 if ok else 1)


def cmd_check(args):
    cfg = load_config()
    env_path = os.path.join(SKILL_DIR, ".env")
    print(f".env: {'found' if os.path.exists(env_path) else 'MISSING'} ({env_path})")
    for k in ("ASC_KEY_ID", "ASC_ISSUER_ID", "ASC_KEY_TYPE", "ASC_APP_ID", "ASC_VENDOR_NUMBER"):
        v = cfg.get(k, "")
        shown = (v[:2] + "…" + v[-2:]) if k in ("ASC_ISSUER_ID",) and len(v) > 6 else v
        print(f"  {k:18} {shown or '(empty)'}")
    pem = key_path(cfg) if cfg.get("ASC_KEY_ID") else None
    print(f"  private key        {pem or 'NOT FOUND'}")
    if pem:
        mode = stat.S_IMODE(os.stat(pem).st_mode)
        if mode & 0o077:
            print(f"  WARNING: {pem} is readable by others (mode {oct(mode)}) — run: chmod 600 '{pem}'")
        if pem.startswith(os.path.join(SKILL_DIR, "")):
            tracked = subprocess.run(["git", "-C", SKILL_DIR, "ls-files", "--error-unmatch", pem],
                                     capture_output=True).returncode == 0
            if tracked:
                print("  WARNING: the .p8 is tracked by git — remove it: git rm --cached")
    api = ASC(cfg)
    apps = api.get_all("/v1/apps", {"limit": 200, "fields[apps]": "name,bundleId"})
    print(f"token OK — {len(apps)} app(s) visible:")
    for a in apps:
        at = a["attributes"]
        print(f"  {a['id']:>12}  {at.get('bundleId', ''):45} {at.get('name', '')}")
    if cfg.get("ASC_APP_ID") and cfg["ASC_APP_ID"] not in {a["id"] for a in apps}:
        print(f"WARNING: ASC_APP_ID {cfg['ASC_APP_ID']} is not among the visible apps")


def cmd_apps(args):
    api = ASC(load_config())
    for a in api.get_all("/v1/apps", {"limit": 200, "fields[apps]": "name,bundleId"}):
        at = a["attributes"]
        print(f"{a['id']:>12}  {at.get('bundleId', ''):45} {at.get('name', '')}")


# ---------------------------------------------------------------- commands: analytics

ACCESS = {"ongoing": "ONGOING", "snapshot": "ONE_TIME_SNAPSHOT"}


def list_requests(api, app):
    return api.get_all(f"/v1/apps/{app}/analyticsReportRequests", {"limit": 200})


def cmd_requests(args):
    cfg = load_config()
    api = ASC(cfg)
    reqs = list_requests(api, app_id(args, cfg))
    if not reqs:
        print("no analytics report requests yet — create one: asc_fetch.py request --access ongoing")
    for r in reqs:
        at = r["attributes"]
        flag = "  ← STOPPED due to inactivity: create a new ONGOING request" if at.get("stoppedDueToInactivity") else ""
        print(f"{r['id']}  {at.get('accessType'):18} stoppedDueToInactivity={at.get('stoppedDueToInactivity')}{flag}")


def cmd_request(args):
    cfg = load_config()
    api = ASC(cfg)
    app, access = app_id(args, cfg), ACCESS[args.access]
    for r in list_requests(api, app):
        at = r["attributes"]
        if at.get("accessType") == access and not at.get("stoppedDueToInactivity"):
            print(f"already exists: {r['id']} {access} — nothing to do")
            return
    body = {"data": {"type": "analyticsReportRequests", "attributes": {"accessType": access},
                     "relationships": {"app": {"data": {"type": "apps", "id": app}}}}}
    _, raw = api.call("POST", "/v1/analyticsReportRequests", body=body)
    r = json.loads(raw)["data"]
    print(f"created {r['id']} {access} for app {app}. First reports arrive in ~24–48 h "
          f"({'one snapshot per month' if access == 'ONE_TIME_SNAPSHOT' else 'then daily'}).")


def list_reports(api, app, access=None):
    out = []
    for r in list_requests(api, app):
        acc = r["attributes"].get("accessType")
        if access and acc != access:
            continue
        for rep in api.get_all(f"/v1/analyticsReportRequests/{r['id']}/reports", {"limit": 200}):
            out.append({"request": r["id"], "access": acc, "id": rep["id"],
                        "name": rep["attributes"].get("name", ""), "category": rep["attributes"].get("category", "")})
    return out


def cmd_reports(args):
    cfg = load_config()
    api = ASC(cfg)
    reps = list_reports(api, app_id(args, cfg), ACCESS.get(args.access))
    if args.name:
        reps = [r for r in reps if args.name.lower() in r["name"].lower()]
    for r in sorted(reps, key=lambda r: (r["access"], r["category"], r["name"])):
        print(f"{r['access']:18} {r['category']:22} {r['id']}  {r['name']}")
    if not reps:
        print("no reports (yet) — reports appear ~24–48 h after `request`")


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def pick_reports(reps, name, variant):
    cand = [r for r in reps if r["name"].lower() == name.lower()]
    if not cand:
        cand = [r for r in reps if name.lower() in r["name"].lower()]
        if variant:
            v = [r for r in cand if variant.lower() in r["name"].lower()]
            cand = v or cand
    names = sorted({r["name"] for r in cand})
    if len(names) > 1:
        sys.exit(f"--report {name!r} matches several reports: {names} — pass the exact name or --variant")
    if not cand:
        sys.exit(f"no report matching {name!r}; run `asc_fetch.py reports` to see names")
    return cand


def cmd_download(args):
    cfg = load_config()
    api = ASC(cfg)
    access = None if args.access == "any" else ACCESS[args.access]
    reps = pick_reports(list_reports(api, app_id(args, cfg), access), args.report, args.variant)
    got = skipped = 0
    for rep in reps:
        insts = api.get_all(f"/v1/analyticsReports/{rep['id']}/instances",
                            {"filter[granularity]": args.granularity, "limit": 200})
        for inst in insts:
            pd = inst["attributes"].get("processingDate", "")
            if (args.start and pd < args.start) or (args.end and pd > args.end):
                continue
            d = os.path.join(args.out, slug(rep["name"]), rep["access"].lower(), args.granularity.lower())
            os.makedirs(d, exist_ok=True)
            # segment URLs are valid for 5 minutes: list and download right away
            segs = api.get_all(f"/v1/analyticsReportInstances/{inst['id']}/segments", {"limit": 200})
            for n, seg in enumerate(segs):
                at = seg["attributes"]
                path = os.path.join(d, f"{pd}_{inst['id'][:8]}_{n:02d}.tsv.gz")
                if os.path.exists(path) and os.path.getsize(path) == at.get("sizeInBytes"):
                    skipped += 1
                    continue
                with urllib.request.urlopen(at["url"], timeout=300) as r:   # pre-signed, no JWT
                    blob = r.read()
                if at.get("sizeInBytes") is not None and len(blob) != at["sizeInBytes"]:
                    sys.exit(f"size mismatch for {path}: got {len(blob)}, expected {at['sizeInBytes']}")
                if at.get("checksum") and hashlib.md5(blob).hexdigest() != at["checksum"].lower():
                    print(f"WARNING: MD5 differs from Apple's checksum for {path}", file=sys.stderr)
                open(path, "wb").write(blob)
                got += 1
    print(f"{got} segment(s) downloaded, {skipped} already present → {args.out}")


# ---------------------------------------------------------------- reading TSVs

def read_tsv(path):
    raw = open(path, "rb").read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8-sig", errors="replace")
    rows = list(csv.reader(io.StringIO(text), delimiter="\t"))
    rows = [r for r in rows if any(c.strip() for c in r)]
    return ([h.strip() for h in rows[0]], rows[1:]) if rows else ([], [])


def input_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for ext in ("*.gz", "*.tsv", "*.txt"):
                files += glob.glob(os.path.join(p, "**", ext), recursive=True)
        else:
            files.append(p)
    # oldest processing date first, so later files (corrections) win on dedupe
    return sorted(set(files), key=lambda f: (os.path.basename(f), f))


def iso(s):
    s = s.strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y%m%d", "%Y/%m/%d"):
        try:
            return dt.datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            pass
    return s


def num(s):
    try:
        return float(str(s).replace(",", "").strip() or 0)
    except ValueError:
        return 0.0


def col(header, name):
    low = [h.lower() for h in header]
    if name.lower() not in low:
        sys.exit(f"column {name!r} not in report; columns: {header}")
    return low.index(name.lower())


def parse_filters(specs):
    out = []
    for s in specs or []:
        neg = "!=" in s
        k, v = s.split("!=" if neg else "=", 1)
        out.append((k.strip(), {x.strip().lower() for x in v.split("|")}, neg))
    return out


def cmd_summarize(args):
    files = input_files(args.inp)
    if not files:
        sys.exit("no report files found")
    header, _ = read_tsv(files[0])
    if args.columns:
        h, rows = read_tsv(files[-1])
        print(f"{len(files)} file(s); columns of {files[-1]}:")
        for i, c in enumerate(h):
            print(f"  {c:28} e.g. {rows[0][i] if rows and i < len(rows[0]) else ''}")
        return
    sums = [s.strip() for s in args.sum.split(",")] if args.sum else \
        [h for h in header if h.lower() in KNOWN_METRICS and h.lower() not in NON_SUMMABLE]
    if args.paid_shape:
        sums = [args.paid_shape]
    for s in sums:
        if s.lower() in NON_SUMMABLE:
            print(f"WARNING: {s!r} is not summable across rows — totals overstate it", file=sys.stderr)
    filters = parse_filters(args.filter)
    merged = {}      # dimension tuple → metric list; later files override (dedupe/corrections)
    hdr0 = None
    for f in files:
        h, rows = read_tsv(f)
        if not h:
            continue
        if hdr0 is None:
            hdr0 = h
        elif [x.lower() for x in h] != [x.lower() for x in hdr0]:
            print(f"WARNING: {f} has different columns — skipped", file=sys.stderr)
            continue
        midx = [col(h, s) for s in sums]
        metric_cols = {i for i, x in enumerate(h) if x.lower() in KNOWN_METRICS} | set(midx)
        didx = [i for i in range(len(h)) if i not in metric_cols]
        per_file = {}
        for r in rows:
            r = r + [""] * (len(h) - len(r))
            key = tuple(r[i].strip() for i in didx)
            acc = per_file.setdefault(key, [0.0] * len(midx))
            for j, i in enumerate(midx):
                acc[j] += num(r[i])
        if args.no_dedupe:
            for k, v in per_file.items():
                acc = merged.setdefault(k, [0.0] * len(midx))
                for j, x in enumerate(v):
                    acc[j] += x
        else:
            merged.update(per_file)
    h = hdr0
    metric_cols = {i for i, x in enumerate(h) if x.lower() in KNOWN_METRICS} | {col(h, s) for s in sums}
    dcols = [h[i] for i in range(len(h)) if i not in metric_cols]
    dpos = {c.lower(): n for n, c in enumerate(dcols)}

    def dim(key, name):
        if name.lower() not in dpos:
            sys.exit(f"column {name!r} not a dimension; dimensions: {dcols}")
        return key[dpos[name.lower()]]

    date_col = args.date_col
    if args.distinct:
        counts = {}
        for key, v in merged.items():
            counts[dim(key, args.distinct)] = counts.get(dim(key, args.distinct), 0) + (v[0] if v else 0)
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"{v:12.0f}  {k}")
        return
    group = [g.strip() for g in args.group.split(",")] if args.group else []
    if args.paid_shape:
        group, args.pivot = [date_col], None
    out = {}
    pivots = set()
    for key, v in merged.items():
        if any((dim(key, c).lower() in vals) == neg for c, vals, neg in filters):
            continue
        if args.start or args.end:
            d = iso(dim(key, date_col))
            if (args.start and d < args.start) or (args.end and d > args.end):
                continue
        g = tuple(iso(dim(key, c)) if c.lower() == date_col.lower() else dim(key, c) for c in group)
        if args.pivot:
            pv = dim(key, args.pivot) or "(blank)"
            pivots.add(pv)
            acc = out.setdefault(g, {})
            acc[pv] = acc.get(pv, 0.0) + v[0]
        else:
            acc = out.setdefault(g, [0.0] * len(sums))
            for j, x in enumerate(v):
                acc[j] += x
    fh = open(args.out, "w", newline="") if args.out else sys.stdout
    w = csv.writer(fh)
    if args.paid_shape:
        w.writerow(["date", "total_paid", "direct", "trial_conversions", "intro_offers"])
        for g in sorted(out):
            w.writerow([g[0], f"{out[g][0]:g}", f"{out[g][0]:g}", 0, 0])
    elif args.pivot:
        pv = sorted(pivots)
        w.writerow(group + pv + ["total"])
        for g in sorted(out):
            vals = [out[g].get(p, 0.0) for p in pv]
            w.writerow(list(g) + [f"{x:g}" for x in vals] + [f"{sum(vals):g}"])
    else:
        w.writerow(group + sums)
        for g in sorted(out):
            w.writerow(list(g) + [f"{x:.2f}".rstrip("0").rstrip(".") for x in out[g]])
    if args.out:
        fh.close()
        print(f"{len(out)} row(s) → {args.out}  (files: {len(files)}, dedupe: {not args.no_dedupe})")


# ---------------------------------------------------------------- commands: sales

def daterange(a, b):
    d, e = dt.date.fromisoformat(a), dt.date.fromisoformat(b)
    while d <= e:
        yield d.isoformat()
        d += dt.timedelta(1)


def cmd_sales(args):
    cfg = load_config()
    vendor = args.vendor or cfg.get("ASC_VENDOR_NUMBER")
    if not vendor:
        sys.exit("no vendor number — pass --vendor or set ASC_VENDOR_NUMBER (README: 'Vendor number')")
    api = ASC(cfg)
    d = os.path.join(args.out, "sales-summary-daily")
    os.makedirs(d, exist_ok=True)
    versions = [args.version] + [v for v in ("1_0", "1_1", "1_3") if v != args.version]
    got = none = skipped = 0
    for day in daterange(args.start, args.end):
        path = os.path.join(d, f"{day}.txt.gz")
        if os.path.exists(path):
            skipped += 1
            continue
        for v in list(versions):
            params = {"filter[frequency]": "DAILY", "filter[reportType]": "SALES",
                      "filter[reportSubType]": "SUMMARY", "filter[vendorNumber]": vendor,
                      "filter[reportDate]": day, "filter[version]": v}
            try:
                _, blob = api.call("GET", "/v1/salesReports", params, accept="application/a-gzip")
                open(path, "wb").write(blob)
                got += 1
                versions = [v] + [x for x in versions if x != v]
                break
            except ApiError as e:
                if e.status == 404:
                    none += 1
                    break
                if e.status == 400 and "version" in e.body.lower() and v != versions[-1]:
                    continue
                raise
    print(f"{got} day(s) downloaded, {none} with no sales/not yet available, {skipped} already present → {d}"
          f"  (Sales days are Pacific Time)")


def product_kind(pti):
    p = pti.strip().upper()
    if p.startswith(("IA", "FI")):
        return "iap"
    if p[:1] == "1" or p in ("F1",):
        return "app"
    if p[:1] == "3" or p == "F3":
        return "redownload"
    if p[:1] == "7" or p == "F7":
        return "update"
    return "other"


def cmd_sales_summary(args):
    files = input_files(args.inp)
    out = {}
    for f in files:
        h, rows = read_tsv(f)
        if not h:
            continue
        ci = {k: col(h, k) for k in ("Product Type Identifier", "Units", "Developer Proceeds",
                                    "Country Code", "Currency of Proceeds", "Begin Date")}
        for r in rows:
            r = r + [""] * (len(h) - len(r))
            country = r[ci["Country Code"]].strip()
            if args.country and country.upper() != args.country.upper():
                continue
            day = iso(r[ci["Begin Date"]])
            if (args.start and day < args.start) or (args.end and day > args.end):
                continue
            units, kind = num(r[ci["Units"]]), product_kind(r[ci["Product Type Identifier"]])
            key = (day, country if not args.country else args.country.upper(), r[ci["Currency of Proceeds"]].strip())
            a = out.setdefault(key, {"app": 0, "redownload": 0, "update": 0, "iap": 0, "iap_refunds": 0,
                                     "other": 0, "proceeds": 0.0})
            if kind == "iap" and units < 0:
                a["iap_refunds"] += -units
            a[kind] += units
            a["proceeds"] += units * num(r[ci["Developer Proceeds"]])   # Developer Proceeds is per unit
    fh = open(args.out, "w", newline="") if args.out else sys.stdout
    w = csv.writer(fh)
    if args.paid_shape:
        daily = {}
        for (day, _, _), a in out.items():
            daily[day] = daily.get(day, 0) + a["iap"]
        w.writerow(["date", "total_paid", "direct", "trial_conversions", "intro_offers"])
        for day in sorted(daily):
            w.writerow([day, f"{daily[day]:g}", f"{daily[day]:g}", 0, 0])
    else:
        w.writerow(["date", "country", "currency", "app_units", "redownloads", "updates",
                    "iap_units_net", "iap_refund_units", "proceeds"])
        for k in sorted(out):
            a = out[k]
            w.writerow(list(k) + [f"{a['app']:g}", f"{a['redownload']:g}", f"{a['update']:g}",
                                  f"{a['iap']:g}", f"{a['iap_refunds']:g}", f"{a['proceeds']:.2f}"])
    if args.out:
        fh.close()
        print(f"{len(out)} row(s) → {args.out}")


# ---------------------------------------------------------------- CLI

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("selftest")
    sub.add_parser("apps")
    s = sub.add_parser("requests"); s.add_argument("--app")
    s = sub.add_parser("request"); s.add_argument("--app"); s.add_argument("--access", required=True, choices=ACCESS)
    s = sub.add_parser("reports"); s.add_argument("--app"); s.add_argument("--name")
    s.add_argument("--access", choices=list(ACCESS) + ["any"], default="any")
    s = sub.add_parser("download"); s.add_argument("--app"); s.add_argument("--report", required=True)
    s.add_argument("--variant", default="standard", help="standard | detailed (substring of the report name)")
    s.add_argument("--granularity", default="DAILY", choices=["DAILY", "WEEKLY", "MONTHLY"])
    s.add_argument("--access", default="ongoing", choices=list(ACCESS) + ["any"])
    s.add_argument("--start", help="processingDate ≥ (YYYY-MM-DD)"); s.add_argument("--end")
    s.add_argument("--out", required=True)
    s = sub.add_parser("summarize"); s.add_argument("--in", dest="inp", nargs="+", required=True)
    s.add_argument("--columns", action="store_true", help="print columns + a sample row")
    s.add_argument("--distinct", help="value totals of one column (first --sum metric)")
    s.add_argument("--filter", action="append", help='"Col=val1|val2" or "Col!=val"; case-insensitive')
    s.add_argument("--start"); s.add_argument("--end"); s.add_argument("--date-col", default="Date")
    s.add_argument("--group", help="comma-separated columns, e.g. Date,Source Type")
    s.add_argument("--pivot", help="spread one column's values into columns (first --sum metric)")
    s.add_argument("--sum", help="comma-separated metric columns (default: summable metrics present)")
    s.add_argument("--paid-shape", metavar="METRIC",
                   help="write date,total_paid,… (period_compare.py --rc) from METRIC per Date")
    s.add_argument("--no-dedupe", action="store_true", help="sum overlapping instances instead of last-wins")
    s.add_argument("--out")
    s = sub.add_parser("sales"); s.add_argument("--vendor"); s.add_argument("--start", required=True)
    s.add_argument("--end", required=True); s.add_argument("--out", required=True)
    s.add_argument("--version", default="1_0")
    s = sub.add_parser("sales-summary"); s.add_argument("--in", dest="inp", nargs="+", required=True)
    s.add_argument("--country"); s.add_argument("--start"); s.add_argument("--end")
    s.add_argument("--paid-shape", action="store_true", help="date,total_paid,… from net IAP units")
    s.add_argument("--out")
    args = p.parse_args()
    try:
        {"check": cmd_check, "selftest": cmd_selftest, "apps": cmd_apps, "requests": cmd_requests,
         "request": cmd_request, "reports": cmd_reports, "download": cmd_download,
         "summarize": cmd_summarize, "sales": cmd_sales, "sales-summary": cmd_sales_summary}[args.cmd](args)
    except ApiError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
