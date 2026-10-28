# Finding candidate skills

Goal: shortlist 1-3 candidates worth auditing. Discovery is read-only; nothing from a
candidate is executed or installed here. `vercel-labs/find-skills` was audited (verdict:
install with changes) and its search idea is folded in below without its install step.

## Sources, in order
1. Skills already available: `ListSkills` / `SearchSkills` (claude.ai skills) and the installed list in the system prompt. If one already covers the need, say so and stop.
2. Registry and official repos: skills.sh (leaderboard and search pages, read with `WebFetch`), `anthropics/skills`, the user's installed plugin marketplaces.
3. GitHub: `gh search repos "<need> claude skill" --sort stars`, or `WebSearch` for `"<need>" claude skill SKILL.md github`.
4. Optional, only if Node is installed and the user agrees: `npx --yes skills@1.7.4 find <query>` (search only; version pinned after checking npm metadata, no install scripts, deps `tar`+`yaml`). Check `Get-Command node` first: it was absent on this machine, so steps 2-3 are the default here.

Popularity (installs, stars, leaderboard rank) is a lead, not safety evidence. Never run `npx skills add`, `-g -y`, `/plugin install` or any installer before the audit passes: they execute remote code and write to the user's config. After a PASS, install only on the user's explicit yes, preferably by copying the audited folder at the recorded commit.

## Pre-filter before spending an audit (no downloads yet)
- Does the README say concretely what it does? Vague claims ("supercharge your workflow") lower priority.
- Repo age, last commit, open issues about security or token use, number of contributors. A new single-author repo is fine but gets Seguridad -1 until read.
- Name impersonation: lookalikes of well-known skills or vendors.
- Size: count files and total bytes from the repo tree (`gh api repos/<o>/<r>/git/trees/HEAD?recursive=1`) before fetching.

## Fetching into quarantine
- Make a fresh empty folder under the scratchpad (for example `<scratch>/quarantine/<name>`), one per candidate.
- Fetch only the skill's own folder: `gh api -H "Accept: application/vnd.github.raw" "repos/<o>/<r>/contents/<path>?ref=<sha>"` per file, or `git clone --depth 1` with hooks disabled (`git -c core.hooksPath=NUL clone ...` on Windows, `/dev/null` elsewhere). Do not `cd` into it and run anything.
- Record the commit SHA so the audit refers to an exact version. Installing later means installing that SHA, not "latest".
- Run any Python that must parse the files with `python -I` and pass the folder as an argument.

## Output
For each candidate: name, source URL + commit, one-line purpose, why it made the shortlist, and the audit result (use the report format in SKILL.md). If none is worth installing, say that plainly; "no skill needed" is a valid result.
