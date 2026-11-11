# command-reviewer

Hermes executes shell commands and scripts on your behalf. A script written
earlier can be run later without anyone reading it, and a command that looks
harmless can do something harmful. Nothing between "the agent decided to run
this" and "it ran" checks whether the code is actually malicious.

**command-reviewer closes that gap.** A plugin hook reviews every
`terminal` and `execute_code` call before it runs: commands get checked by
deterministic rules and an LLM reviewer, and scripts get their _contents_
read and judged, not just their filenames. Malicious code is blocked.
Anything uncertain goes to you for approve/deny — and your decision is
remembered, bound to the exact bytes of the script, so you only judge a
command once.

## Setup

Requires Hermes Agent v0.23+ (Docker terminal backend recommended).

1. Put `plugin.yaml` and `__init__.py` in `~/.hermes/plugins/command-reviewer/`
2. Validate and enable:
   ```bash
   hermes plugins doctor ~/.hermes/plugins/command-reviewer --ci
   hermes plugins enable command-reviewer
   ```
3. It starts in **shadow mode** — logs every decision, blocks nothing:
   ```bash
   tail -20 ~/.hermes/plugin-data/command-reviewer/decisions.jsonl
   ```
4. When you trust it, flip to enforce (live, no restart):
   ```bash
   hermes config set plugins.entries.command-reviewer.settings.mode enforce
   ```

Model reviews use the `command_reviewer` auxiliary task, which follows your
main model (one small LLM call per reviewed command). Pin a cheaper model in
Desktop Settings → Models if you like.

## Testing

A standalone harness is included: `python3 test_reviewer.py` (no
dependencies, exits nonzero on failure). It covers every decision layer —
including the zero-LLM fast path: per-script verdict caching by content
hash, the per-command verdict cache for identical reruns, the
config-allowlist pre-check, and the deny-glob pass-through — plus a timing
test proving the fork-bomb rule matches a 12KB adversarial single-line
input in under 100ms.

## License

MIT — see [LICENSE](LICENSE).
