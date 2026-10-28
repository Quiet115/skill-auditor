# Does it actually work? (opt-in empirical test)

Reading a skill proves little; the question is whether Claude does better WITH it. This test spends tokens, so tell the user the estimate and ask before running. Skip it for trivial skills or when the verdict is already NO INSTALAR on security.

## Cost estimate to state up front
`runs = tasks x 2` (with and without the skill). Each run is roughly the task's normal cost plus the skill's on-trigger tokens. With 3 tasks that is 6 subagent runs; say so in tokens-ish terms ("about 6 small sessions") and let the user cut it down to 1-2 tasks.

## Method
Reuse the `skill-creator` machinery rather than inventing one: it already defines test-case folders, the with-skill vs baseline layout, `timing.json`, grading and a benchmark viewer. Load that skill and follow its "Running and evaluating test cases" section, with the candidate in place of the skill under development.

Safety first: the candidate is still untrusted while being tested.
- Audit passed at least at "no unexplained CRITICAL/HIGH" before any run.
- Run in a throwaway working folder with dummy data, never in the user's real project or with real credentials in the environment.
- If the skill has hooks, MCP servers or network scripts, do not run it at all; test a copy with those removed and say so.
- Read each script's code before it executes; on Windows watch for PowerShell/cmd differences.

## Choosing tasks
2-3 realistic tasks the user would actually give, one of them an edge case, plus one near-miss that should NOT trigger the skill (to check the description is not over-broad). Write assertions that are objectively checkable (file exists, numbers match, flag raised), not "looks good".

## What to record
| Measure | How |
|---|---|
| Quality | assertion pass rate, with vs without |
| Cost | `total_tokens` and duration from each run's notification |
| Triggering | did it fire on the target tasks, and stay quiet on the near-miss |
| Side effects | files written outside the outputs folder, network calls, config changes |

## Reading the result
- Pass rate no better than baseline: Beneficio drops to 1-2 regardless of how good the skill looks.
- Better quality but several times the tokens: say so; the user decides whether it is worth it.
- Passes only because of an assertion any run satisfies: note it as non-discriminating and do not count it.
- One run per cell is noisy. Say "indicative" unless the same result repeats.

Set `Funciona` in the rubric from this evidence: 5 clear win, 3 works but no clear win, 1 not tested.
