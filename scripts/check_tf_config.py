#!/usr/bin/env python3
"""Static pre-plan gate on the Terraform configuration (Guardian M2).

The plan role runs on every push to main and can read secrets (state, Lambda env vars). The
allowlisted hashicorp/aws provider (and the S3 backend) accept settings that send requests, and
whatever is in them, somewhere else: endpoints {}, custom_ca_bundle, http(s)_proxy,
shared_config_files (credential_process = run a program), assume_role, skip_* checks... An
aliased provider whose endpoint URL carries a secret would leak it during plan.

  check_tf_config.py --root REPO --tf-dir DIR [--profile NAME]

Checks the root module in DIR and every LOCAL module it calls (recursively):
  - provider blocks: only "aws", "archive", "random"; aws may set only ALLOWED_AWS_PROVIDER_ATTRS
    (+ blocks default_tags, ignore_tags); archive/random only `alias`
  - terraform blocks: only required_version, required_providers, backend; no cloud {}
  - backend: only "s3" (ALLOWED_S3_BACKEND_ATTRS) or "local" (path)
  - profile (provider and backend): a literal equal to --profile, or a var.<name> reference (the
    sandbox holds only that one profile, so any other name simply fails)
  - module sources: local paths only ("./", "../"); registry/git modules are not scanned, refused
  - data/resource types of Terraform's built-in provider other than terraform_data, in
    particular data "terraform_remote_state" (its `config` map is a backend config: endpoints,
    proxies, ... and it reads other state): refused
  - .tf.json files get the same checks
Allowlists, not denylists: anything new the provider grows is refused until reviewed here.
Terraform can't set environment variables from HCL, and the sandbox starts from env -i, so
AWS_* / TF_* overrides can't come from the configuration.

Exit 0 ok, 1 refused (one ::error:: line per finding), 2 unreadable/unparseable (fail closed).
"""
import argparse
import json
import os
import re
import sys

ALLOWED_PROVIDERS = {"aws", "archive", "random"}
ALLOWED_AWS_PROVIDER_ATTRS = {"alias", "region", "profile", "allowed_account_ids", "forbidden_account_ids",
                              "max_retries", "retry_mode"}
ALLOWED_AWS_PROVIDER_BLOCKS = {"default_tags": {"tags"}, "ignore_tags": {"keys", "key_prefixes"}}
ALLOWED_S3_BACKEND_ATTRS = {"bucket", "key", "region", "encrypt", "use_lockfile", "profile", "kms_key_id",
                            "dynamodb_table", "workspace_key_prefix"}
ALLOWED_TERRAFORM_ITEMS = {"required_version", "required_providers", "backend"}


class ParseError(ValueError):
    pass


# --- HCL lexer / parser (structure only) ------------------------------------------------------

TOKEN_RE = re.compile(r"""
    (?P<ws>[ \t\r]+)
  | (?P<nl>\n)
  | (?P<comment>\#[^\n]*|//[^\n]*|/\*.*?\*/)
  | (?P<heredoc><<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\n)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_-]*)
  | (?P<number>[0-9][0-9.eE+-]*)
  | (?P<punct>[{}\[\]()=,:.?!<>*/%+&|-])
""", re.VERBOSE | re.DOTALL)


def _read_string(text, i):
    """text[i] == '"'. Returns (literal or None if it interpolates, end index)."""
    j = i + 1
    out, interp = [], False
    while True:
        if j >= len(text):
            raise ParseError("unterminated string")
        c = text[j]
        if c == "\\":
            out.append(text[j:j + 2])
            j += 2
            continue
        if c == '"':
            return (None if interp else "".join(out)), j + 1
        if c == "\n":
            raise ParseError("newline in string")
        if text.startswith("$${", j) or text.startswith("%%{", j):
            out.append(text[j + 1:j + 3])
            j += 3
            continue
        if text.startswith("${", j) or text.startswith("%{", j):
            interp = True
            j = _skip_template(text, j + 2)
            continue
        out.append(c)
        j += 1


def _skip_template(text, j):
    depth = 1
    while depth:
        if j >= len(text):
            raise ParseError("unterminated interpolation")
        c = text[j]
        if c == '"':
            _, j = _read_string(text, j)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        j += 1
    return j


def lex(text):
    toks, i = [], 0
    while i < len(text):
        if text[i] == '"':
            lit, j = _read_string(text, i)
            toks.append(("string", lit))
            i = j
            continue
        m = TOKEN_RE.match(text, i)
        if not m:
            raise ParseError(f"unexpected character {text[i]!r}")
        kind = m.lastgroup
        if kind == "heredoc":
            tag = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)", m.group(0)).group(1)
            end = re.compile(r"^[ \t]*" + re.escape(tag) + r"[ \t]*$", re.MULTILINE)
            e = end.search(text, m.end())
            if not e:
                raise ParseError("unterminated heredoc")
            toks.append(("string", None))
            i = e.end()
            continue
        if kind == "comment":
            toks.extend([("nl", "\n")] * m.group(0).count("\n"))
        elif kind not in ("ws",):
            toks.append((kind, m.group(0)))
        i = m.end()
    return toks


class Node:
    def __init__(self, kind, name, labels=(), body=None, value=None):
        self.kind, self.name, self.labels, self.body, self.value = kind, name, list(labels), body or [], value


def parse(toks):
    pos = 0

    def skip_nl(p):
        while p < len(toks) and toks[p][0] == "nl":
            p += 1
        return p

    def parse_expr(p):
        """Skip an expression until a newline at bracket depth 0. Returns (tokens, p)."""
        depth, start = 0, p
        while p < len(toks):
            k, v = toks[p]
            if k == "nl" and depth == 0:
                break
            if k == "punct" and v in "{[(":
                depth += 1
            elif k == "punct" and v in "}])":
                if depth == 0:
                    break
                depth -= 1
            p += 1
        if depth:
            raise ParseError("unbalanced expression")
        return toks[start:p], p

    def parse_body(p, closing):
        items = []
        while True:
            p = skip_nl(p)
            if p >= len(toks):
                if closing:
                    raise ParseError("unexpected end of file")
                return items, p
            k, v = toks[p]
            if closing and k == "punct" and v == "}":
                return items, p + 1
            if k != "ident":
                raise ParseError(f"expected an attribute or block name, got {v!r}")
            name = v
            p += 1
            if p < len(toks) and toks[p] == ("punct", "="):
                expr, p = parse_expr(p + 1)
                items.append(Node("attr", name, value=expr))
                continue
            labels = []
            while p < len(toks) and toks[p][0] in ("string", "ident"):
                labels.append(toks[p][1])
                p += 1
            if p >= len(toks) or toks[p] != ("punct", "{"):
                raise ParseError(f"expected '{{' after block {name}")
            body, p = parse_body(p + 1, True)
            items.append(Node("block", name, labels, body))
    items, _ = parse_body(pos, False)
    return items


def literal(expr):
    """The string value of an expression that is one plain string literal, else None."""
    if len(expr) == 1 and expr[0][0] == "string" and expr[0][1] is not None:
        return expr[0][1]
    return None


def is_var_ref(expr):
    return (len(expr) == 3 and expr[0] == ("ident", "var") and expr[1] == ("punct", ".")
            and expr[2][0] == "ident")


# --- JSON syntax ------------------------------------------------------------------------------

def _json_value_expr(v):
    if isinstance(v, str):
        if "${" in v or "%{" in v:
            if re.fullmatch(r"\$\{var\.[A-Za-z_][A-Za-z0-9_-]*\}", v):
                return [("ident", "var"), ("punct", "."), ("ident", v[6:-1])]
            return [("string", None)]
        return [("string", v)]
    return [("other", json.dumps(v))]


def _json_body(obj, where):
    if not isinstance(obj, dict):
        raise ParseError(f"{where}: expected an object")
    items = []
    for k, v in obj.items():
        if isinstance(v, dict) and k in ("default_tags", "ignore_tags", "required_providers", "backend",
                                          "cloud", "provider_meta", "endpoints", "assume_role",
                                          "assume_role_with_web_identity"):
            items.append(_json_block(k, v, where))
        elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v) and k not in ("allowed_account_ids",):
            for x in v:
                items.append(Node("block", k, [], _json_body(x, f"{where}.{k}")))
        else:
            items.append(Node("attr", k, value=_json_value_expr(v)))
    return items


def _json_block(name, v, where):
    if name == "backend":
        (btype, bbody), = v.items() if len(v) == 1 else (_ for _ in ()).throw(ParseError("backend"))
        return Node("block", "backend", [btype], _json_body(bbody, f"{where}.backend"))
    return Node("block", name, [], _json_body(v, f"{where}.{name}"))


def parse_json(text, where):
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ParseError("not an object")
    items = []
    for top, val in doc.items():
        entries = val if isinstance(val, list) else [val]
        for entry in entries:
            if top == "provider":
                for pname, pval in entry.items():
                    for pv in (pval if isinstance(pval, list) else [pval]):
                        items.append(Node("block", "provider", [pname], _json_body(pv, f"provider.{pname}")))
            elif top == "terraform":
                items.append(Node("block", "terraform", [], _json_body(entry, "terraform")))
            elif top == "module":
                for mname, mval in entry.items():
                    items.append(Node("block", "module", [mname], _json_body(mval, f"module.{mname}")))
            elif top in ("data", "resource"):
                if not isinstance(entry, dict):
                    raise ParseError(f"{top}: expected an object")
                for rtype, named in entry.items():
                    if not isinstance(named, dict):
                        raise ParseError(f"{top}.{rtype}: expected an object")
                    for rname, rval in named.items():
                        for rv in (rval if isinstance(rval, list) else [rval]):
                            items.append(Node("block", top, [rtype, rname], []))
            else:
                items.append(Node("block", top, [], []))
    return items


# --- checks -------------------------------------------------------------------------------------

def check_profile(node, profile, where, problems):
    lit = literal(node.value)
    if lit is not None:
        if profile is not None and lit != profile:
            problems.append(f"{where}: profile {lit!r} is not the pipeline's profile {profile!r}")
    elif not is_var_ref(node.value):
        problems.append(f"{where}: profile must be a literal or a var.<name> reference")


def check_items(items, where, profile, problems, module_sources):
    for n in items:
        if n.kind != "block":
            continue
        loc = f"{where}: {n.name}{''.join(' ' + json.dumps(str(x)) for x in n.labels)}"
        if n.name == "provider":
            pname = str(n.labels[0]) if n.labels else "?"
            if pname not in ALLOWED_PROVIDERS:
                problems.append(f"{loc}: provider not allowed")
                continue
            allowed = ALLOWED_AWS_PROVIDER_ATTRS if pname == "aws" else {"alias"}
            blocks = ALLOWED_AWS_PROVIDER_BLOCKS if pname == "aws" else {}
            for item in n.body:
                if item.kind == "attr":
                    if item.name not in allowed:
                        problems.append(f"{loc}: setting {item.name!r} is not allowed in CI")
                    elif item.name == "profile":
                        check_profile(item, profile, loc, problems)
                elif item.name in blocks:
                    for sub in item.body:
                        if sub.kind != "attr" or sub.name not in blocks[item.name]:
                            problems.append(f"{loc}: {item.name}.{sub.name} is not allowed in CI")
                else:
                    problems.append(f"{loc}: block {item.name!r} is not allowed in CI")
        elif n.name == "terraform":
            for item in n.body:
                if item.name not in ALLOWED_TERRAFORM_ITEMS:
                    problems.append(f"{loc}: {item.name!r} is not allowed in CI")
                elif item.name == "backend":
                    btype = str(item.labels[0]) if item.labels else "?"
                    if btype == "s3":
                        allowed_b = ALLOWED_S3_BACKEND_ATTRS
                    elif btype == "local":
                        allowed_b = {"path"}
                    else:
                        problems.append(f"{loc}: backend {btype!r} is not allowed in CI")
                        continue
                    for b in item.body:
                        if b.kind != "attr" or b.name not in allowed_b:
                            problems.append(f"{loc}: backend {btype} setting {b.name!r} is not allowed in CI")
                        elif b.name == "profile":
                            check_profile(b, profile, f"{loc} backend", problems)
        elif n.name in ("data", "resource"):
            rtype = str(n.labels[0]) if n.labels else "?"
            # Terraform's built-in provider: terraform_remote_state takes a backend `config` map
            # (endpoints, proxies, ...) and reads other state; no project uses it. Only
            # terraform_data is allowed from the built-in provider.
            if rtype == "terraform_remote_state" or (rtype.startswith("terraform_") and rtype != "terraform_data"):
                problems.append(f"{loc}: built-in {n.name} {rtype!r} is not allowed in CI")
        elif n.name == "module":
            src = next((i for i in n.body if i.kind == "attr" and i.name == "source"), None)
            lit = literal(src.value) if src else None
            if lit is None or not (lit.startswith("./") or lit.startswith("../")):
                problems.append(f"{loc}: module source must be a local path (./ or ../), got {lit!r}")
            else:
                module_sources.append(lit)


def check_module_dir(root, mod_dir, profile, problems, seen):
    real = os.path.realpath(mod_dir)
    if real in seen:
        return
    seen.add(real)
    if not (real + os.sep).startswith(os.path.realpath(root) + os.sep):
        problems.append(f"{os.path.relpath(mod_dir, root)}: module outside the repository")
        return
    files = sorted(f for f in os.listdir(real) if f.endswith(".tf") or f.endswith(".tf.json"))
    sources = []
    for f in files:
        path = os.path.join(real, f)
        rel = os.path.relpath(path, os.path.realpath(root))
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        try:
            items = parse_json(text, rel) if f.endswith(".tf.json") else parse(lex(text))
        except (ParseError, ValueError) as e:
            raise ParseError(f"{rel}: {e}")
        check_items(items, rel, profile, problems, sources)
    for s in sources:
        check_module_dir(root, os.path.join(real, s), profile, problems, seen)


def check(root, tf_dir, profile=None):
    problems = []
    check_module_dir(root, os.path.join(root, tf_dir), profile, problems, set())
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--tf-dir", required=True)
    ap.add_argument("--profile")
    args = ap.parse_args(argv)
    try:
        problems = check(args.root, args.tf_dir, args.profile or None)
    except (OSError, ParseError, UnicodeDecodeError) as e:
        print(f"::error::cannot check the Terraform configuration (refusing): {e}"[:400], file=sys.stderr)
        return 2
    for p in problems:
        print(f"::error::{p}", file=sys.stderr)
    if problems:
        return 1
    print("terraform configuration ok: providers, backend and module sources within the CI allowlist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
