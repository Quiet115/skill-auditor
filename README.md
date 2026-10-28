# skill-auditor

A Claude skill that audits other Claude skills and plugins **before you install them**: is it safe, is it worth it, what does it cost in tokens, and does it actually work. It can also search for candidate skills and audit them first.

A skill is instructions plus code that run with your permissions and sit in the model's context. Installing one is a trust decision. Most installers (`npx skills add ...`) run remote code before you have looked at anything; this skill puts the audit first.

Spanish version: [README.es.md](README.es.md).

## What it does

| Question | How |
|---|---|
| Is it safe? | `scan_skill.py` triages the whole folder: hidden or encoded code, remote execution, secrets plus network, prompt-injection wording, invisible Unicode, hooks, MCP servers, edits to agent config. Then the model reads the skill in full. |
| Is it worth it? | A 0-5 rubric compares the skill with what Claude already does and with your installed skills. |
| What does it cost? | Three token estimates: always-on (name + description, paid every session), on-trigger (the SKILL.md body), on-demand (references). Flags over-broad descriptions and cost amplifiers. |
| Does it work? | Optional with/without test on realistic tasks (reuses `skill-creator`'s eval tooling). It states the token cost first and asks. |
| Where do I find one? | `references/discovery.md`: registry pages, `gh search`, optional pinned `npx skills find`. Search only, never install. |

Output is a scorecard (Security / Benefit / Cost / Works) ending in *install / install with changes / don't install*. It installs only after an explicit yes, by copying the audited files itself, never through a third-party installer.

## Benign or malicious? How a finding is judged

The scanner does **not** decide this. A hit is a lead. Every report lists, for each rule that fired, what it means and when it is usually benign or suspicious, and asks six questions: code or prose? read or write? does it chain with something else? does it match the skill's stated purpose? is the target fixed and documented? is the user told first? Anything you cannot answer from the files stays a finding. Full table: [findings-guide.md](skills/skill-auditor/references/findings-guide.md) (or `python scan_skill.py --explain`).

Example: a path to `~/.claude/skills/...` mentioned in a doc is a *mention* (benign); a script that *writes* to `settings.json` and also has network access is the serious case.

## Range of use

- Input: a folder with one or more skills (`SKILL.md`) or a plugin. Text files are read; binaries, archives, PDFs and `.git` are only reported.
- It never runs, imports or installs what it scans.
- It does not prove a skill safe, judge intent, see content fetched at run time, or sandbox-run anything. "No findings" means "no known pattern matched".
- Needs Python 3.8+ (developed and tested on 3.14, Windows 11), no third-party packages. Token counts are estimates (about 3.5 characters per token, +-25%).
- Documentation that quotes risky patterns will match. A security skill flags itself; the scanner has no ignore directive on purpose.
- Not yet done: the with/without benchmark and the trigger-accuracy test of the skill itself.

## Install

```bash
git clone https://github.com/Quiet115/skill-auditor
cp -r skill-auditor/skills/skill-auditor ~/.claude/skills/    # all projects
# or: <your-project>/.claude/skills/ for one project
```

Read it first, which is the point of the project. Then ask Claude: *"audita esta skill: <path or URL>"* / *"is this skill safe to install?"*

Use the scanner directly:

```bash
python -I skills/skill-auditor/scripts/scan_skill.py <folder> --md report.md --json report.json
```

Exit code: 0 nothing at MEDIUM or above, 1 MEDIUM, 2 HIGH, 3 CRITICAL, 4 error. On PowerShell use `$HOME`, not `~`.

## Tests

```bash
python -I -m unittest discover -s tests
```

Builds a malicious fixture, a clean one and a few edge cases in a temp folder and checks detection, false-positive guards, that the target is never executed, and that reports are inert ASCII.

## Examples

- [Audit of vercel-labs/find-skills](examples/audit-find-skills.es.md) (Spanish)
- [Self-audit](examples/audit-skill-auditor-itself.es.md) (Spanish), with the expected self-hits explained

## License

MIT. Provided as is, with no warranty: it reduces risk, it does not remove it.
