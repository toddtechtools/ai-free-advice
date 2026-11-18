---
name: verification-loop
description: Evidence-based verification workflow for Go, Python, shell, Node.js, RPMs, and release bundles, producing a fail-closed PASS/HOLD/FAIL/SKIP ledger. Use after a completed feature, fix, refactor, component, or task, before a PR or release, and when asked to verify, certify, gate, check everything, or assess readiness to ship.
---

# Verification Loop

Run the applicable checks, inspect evidence, resolve blockers, and repeat against
the final candidate. Treat this as an instruction workflow; no bundled runner is
required. Use an existing runner only after confirming that it implements these
rules. Never claim that an absent script ran or that this skill installs tools.

## Status and decision rules

- **PASS**: the applicable check ran to completion and met its acceptance criteria.
- **FAIL**: the check ran and failed, timed out, crashed, or lost required evidence.
- **HOLD**: the check could not run because a tool, permission, prerequisite, or
  required configuration is missing, or a required check remains unexecuted. Record
  the specific blocker, or "not executed; reason unestablished". Never treat HOLD as PASS.
- **SKIP**: demonstrably outside the agreed candidate scope. Record the reason.
  A missing tool, missing tests, or missing configuration is not proof of irrelevance.

Keep raw outcomes immutable. Store waivers separately; do not relabel a failed or
unexecuted check as PASS. For an automated gate, return 0 only for a complete,
current ledger with zero FAIL and zero HOLD. Return nonzero on blockers, incomplete
execution, or ledger-writing failure, including when exceptions are accepted.

Use `READY` only when every required check passes and manual review is complete.
Use `NOT READY` otherwise. If the release authority explicitly accepts valid
waivers covering every remaining blocker, report `EXCEPTION ACCEPTED` separately;
keep the automated gate nonzero. Never call this a clean verification pass.

## Bundled helper

Run `bash <skill-directory>/scripts/verify.sh <project-dir>`; resolve the skill
location in the current AI environment instead of hard-coding a Claude/Codex home.
The Bash entry point requires Python 3.9+ on a Linux host with `/proc` and
child-subreaper support, and uses the adjacent
`verify.py` supervisor. The default evidence directory is printed in the output;
`--out /absolute/path/ledger.json` selects a new ledger outside the candidate.
Use `--timeout 300 --budget 3600 --grace 10` to set finite limits. Run
`--prepare-node` only on an isolated candidate where `npm ci` is authorized.

Treat the helper ledger as partial workflow evidence. It deliberately records
`workflow.completeness` HOLD: it cannot decide project scope, manual review,
waiver authority, or two-pass completion. It also holds Python environments,
Node/Go workspace integration, and release coverage for project-specific checks.
Complete those checks with the same supervision/logging contract and produce a
separate final ledger linking the original helper ledger and closure evidence.
Never overwrite original outcomes. The final ledger may close an unexecuted HOLD
with new evidence; retain its history. A FAIL requires remediation and fresh
passes. Do not remove helper HOLDs without performing the identified work.
The helper does not install system tools or automatically approve waivers.

## 1. Establish scope and prerequisites

1. Read project instructions and identify the candidate, required checks, and
   acceptance criteria. Record requirements before running; do not drop a check
   after it fails. Include project-specific integration, migration, packaging,
   security, or runtime checks needed to substantiate the intended release.
2. Record repository commit, dirty state, changed/untracked files, and submodule
   revisions, or an equivalent file manifest if no Git repository exists. Record
   OS/architecture, UTC time, tool versions, relevant non-secret environment,
   dependency lockfile hashes, and the verification plan.
3. Enumerate first-party modules and packages recursively, including nested
   `go.mod`, `go.work` members, Node workspaces, Python projects, shell scripts,
   RPM specs, and release checksum manifests. Exclude dependency caches, generated
   output, and vendored code only with recorded reasons. Do not follow symlinks
   outside scope. Flag inaccessible or unresolved required scope as HOLD.
4. Use an isolated candidate workspace for dependency preparation, builds, and
   tests where possible. Respect the user's host and repository rules. Do not
   install system tools, change security settings, or upgrade dependencies merely
   to clear the gate. Record missing prerequisites as HOLD; resolve them only
   through the authorized process.
5. Create a unique evidence directory outside scanned source paths. Never overwrite
   earlier attempts. Plan one result for every required check and scope unit.

## 2. Execute bounded checks and capture evidence

Apply a finite timeout to **every external command**, including discovery,
version probes, dependency preparation, scans, and test retries. Default to 300
seconds per check with a 10-second termination grace. Set longer finite limits
before execution when the workload warrants them; record the reason and value.
Set a finite total run budget; on exhaustion, finalize the ledger with remaining
required checks as HOLD and report NOT READY.

On GNU timeout hosts, execute commands as argument arrays equivalent to:

```bash
timeout --signal=TERM --kill-after=10s 300s command arg1 arg2
```

Use a supervisor that terminates the command's process group and descendants;
verify cleanup on timeout. If bounded execution cannot be enforced, record HOLD
without starting the command. Treat timeout (including timeout-related status
124/137), forced termination, or a supervisor error after launch as FAIL. Do not
pipe through `tail`, mask failures with `|| true`, or infer success from a shell
pipeline's final command. Preserve the actual command status.

For each attempt, record:

- Stable check ID, scope path, exact command/arguments, working directory,
  tool version, timeout, UTC start/end, duration, and exit code (null if not run).
- Status, concise reason, and attempt number.
- Full stdout/stderr in a separate log with a relative path and SHA256 digest;
  retain the last 25 lines in the ledger.
- A bounded diagnostic excerpt with line numbers matching, case-insensitively,
  `FAIL|Error|panic|warning|Traceback|fatal`, and the matched/truncated line counts.
  State when no matches exist; the excerpt is a locator, not a guarantee that it
  contains the cause. Inspect full logs when needed. Never infer status from grep.

Keep secrets out of commands and logs. Use redacted reports from secret scanners;
if unexpected secrets appear, restrict the original log and distribute a redacted
copy, recording that transformation. Do not silently truncate or discard evidence.
Continue independent checks after failure; mark dependent checks HOLD with the
blocking check ID. On interruption, preserve partial evidence and report NOT READY.

## 3. Select applicable gates

Use project commands and supported tool versions. Run each command through the
bounded execution and evidence rules above. Record absent required tools as HOLD.

| Detected scope | Required checks |
|---|---|
| Each first-party Go module | `go mod verify`, `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `staticcheck ./...`, `govulncheck ./...` from that module; also verify declared workspace integration |
| Each Python project or first-party Python source scope | `ruff check`, `pyright`, and the project's pytest/test command in its declared environment; use explicit scope/configuration and locked dependencies where declared |
| First-party shell scripts | `shellcheck` for every applicable script, respecting its declared dialect |
| Each Node package/workspace | Locked dependency preparation at the owning lockfile root, then declared build, lint, and non-watch test scripts covering each package |
| RPM specs | `rpmlint` with the project policy/configuration |
| Release checksum manifests | Validate manifest paths, then run `sha256sum -c` from the manifest's intended base directory; verify release checksums twice in separate passes |
| Git repository | Secret scan with the installed gitleaks version's supported command; cover the candidate's tracked, untracked, and staged content and the relevant commit range, documenting coverage |

Additional rules:

- **Go**: record `go version`, `CGO_ENABLED`, `GOOS`, `GOARCH`, and compiler
  availability. If race instrumentation is unsupported or its CGO/compiler
  prerequisite is unavailable, record race-check HOLD. An ordinary test pass
  does not substitute for race coverage. A launched check's failure remains FAIL.
- **Python**: do not verify against arbitrary global packages. Establish the
  declared environment first. If dependency reproducibility cannot be established,
  record HOLD. Missing required tests or type-check configuration requires a
  documented project decision; do not silently SKIP.
- **Node**: use `npm ci` with the committed npm lockfile, or the repository's
  declared package manager and frozen-lock equivalent. Do not mix managers or
  regenerate locks to make verification pass. Prepare once per owning dependency
  root, then use its workspace commands. Missing locks/tools/network prerequisites
  produce HOLD; an executed install failing produces FAIL and dependent scripts
  HOLD. Existing `node_modules` alone is insufficient evidence. Do not install in
  a live runtime directory. Confirm script existence and meaning: no-op scripts,
  watch mode, and test commands that accept zero tests cannot prove coverage.
  Missing build/lint/test scripts are SKIP only with an applicability reason;
  missing required coverage is HOLD.
- **Checksums**: reject absolute paths, parent traversal, escaping symlinks,
  duplicates, missing files, and incomplete required release coverage before
  checking hashes. Use portable basenames for flat release bundles. A checksum
  pass establishes byte integrity, not authenticity or functional correctness.
- **Coverage**: detection is a starting point, not the definition of completeness.
  Unit tests do not prove deployment, tenant isolation, migrations, performance,
  or production readiness. Explicitly identify checks not executed and the claims
  they leave unverified. Do not invent required tests for trivial reversible edits.

## 4. Handle failures, flakes, and waivers

For a reproducible code defect, reproduce it, add a meaningful regression test
before the fix, fix the cause, and rerun affected checks followed by the full
required gate. Use `tdd-workflow` if available; otherwise follow this sequence
directly. Do not add tests that merely mirror implementation. For tooling,
configuration, or documentation defects, correct the cause and use an appropriate
check rather than forcing a code test.

Rerun a failing test at most once diagnostically, without source, dependency,
configuration, or environment changes; record both attempts and seeds. Rerun
only if the test is safe to repeat. Do not retry timeouts, race findings, or
security findings to clear them. Fail-then-pass is **FAIL (flaky)**, not PASS.
Fail-then-fail remains FAIL. Keep the original failure and investigate or obtain
an explicit exception. After remediation, require two fresh complete passes;
a retry alone cannot clear the original failure.

Keep waivers in tracked `waivers.toml` at the project root. Use one record per
exact check and scope; disallow wildcard or blanket waivers. Require:

```toml
[[waiver]]
id = "W-001"
check = "go.race"
scope = "services/example"
reason = "Document the specific limitation and risk."
date = "2026-10-20T10:00:00Z"
expires = "2026-10-27T10:00:00Z"
approved_by = "Named release authority"
approval_ref = "Durable approval record"
candidate = "Exact commit or immutable candidate manifest hash"
owner = "Named remediation owner"
remediation = "Tracked issue or concrete corrective action"
```

Validate UTC timestamps with `date <= now < expires` and `expires > date`.
Validate approval, candidate, check, and scope. Treat expired, malformed,
unapproved, or mismatched waivers as invalid; keep the original FAIL/HOLD
blocking. Never create approval on the authority's behalf. An expired waiver
leaves a missing-prerequisite result HOLD and a failed check FAIL. Surface all
waivers in the report, including invalid ones. Project policy may prohibit
waiving particular checks; honor that restriction.

## 5. Review the final candidate twice

Perform a second, separate review after the fixes; rebuild the assessment from
the final artifacts and raw evidence. Do not treat the first summary as proof.
An independent reviewer is useful when available, but is not required to run
this skill. If only self-review occurred, state that plainly.

Review `git diff --stat`, staged and unstaged diffs, relevant untracked files,
and every changed file for unintended changes, missing error handling, edge
cases, and scope omissions. Keep this manual judgment; tool success cannot
replace it. For security-relevant changes, use `security-review` if available;
otherwise examine the changed trust boundaries and capture applicable evidence.
Record the reviewer, candidate identity, reviewed scope, and findings.

After any source, configuration, lockfile, or scope change, invalidate affected
results and rerun the complete required gate on the final candidate. A tool's
expected generated build output does not by itself invalidate source identity;
unexpected source changes do. Compare pre/post candidate manifests. Require two
fresh complete gate passes for code/release work, with separate logs and manual
re-check. Record any weaker verification explicitly as NOT READY for that claim.

## 6. Report and close

Write a structured ledger (for example JSON) and this human-readable summary.
List every FAIL, HOLD, SKIP, flaky outcome, waiver, and unexecuted requirement.
Retain all attempt logs alongside the ledger. Verify result counts and expected
check coverage before deciding; an empty or incomplete ledger cannot pass.

```text
VERIFICATION LEDGER <project> <candidate identity> <UTC timestamp>
Scope: <modules/packages/release and exclusions>
Tools: <versions>  Evidence: <directory>
PASS n   FAIL n   HOLD n   SKIP n
<every non-PASS result: check/scope, reason, command, log, tail, diagnostics>
Waivers: <valid/invalid, IDs, approvals, expiry, covered results>
Diff review: <reviewer, scope, findings>
Pass 1: <ledger>   Pass 2: <ledger>
Decision: READY | NOT READY
Exception: NONE | ACCEPTED <authority and approval reference>
Limitations: <claims not established>
```

Use this loop after each completed component or task, not only at release time.
Use focused checks while editing; run the complete required gate at completion.
Never claim deployment or field certification from local checks alone.
