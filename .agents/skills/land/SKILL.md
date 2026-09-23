---
name: land
description: >-
  Land explicitly requested changes in the mkrdnk/jam repository onto master.
  Invoke only after the user has requested landing, such as with Land Changes
  or /land; do not invoke for review, preparation, passing checks, or skill
  installation alone.
metadata:
  delta-action: land
---

# Land jam changes

Land the changes requested in the current conversation. Loading this skill
means the user has already authorized the landing operation. Do not ask again
whether to commit, push, or land, and do not answer `/land` by waiting for
another explicit request. Stop only for a genuine blocker, unresolved scope,
failed verification, or a conflict as required below.

This workflow applies only to the `mkrdnk/jam` repository. Its publication
remote is `origin`, its destination branch is `master`, and landing is a
non-forced fast-forward push. The `local` remote is the user's primary checkout
backlink, not a publication destination.

## Safety and scope

1. Confirm the repository root, `origin` URL, current branch, HEAD, worktree
   state, and the exact changes attributable to this conversation. Fetch
   `origin/master` before comparing history.
2. Inspect every changed file and every commit in `origin/master..HEAD`.
   Exclude unrelated work. If unrelated uncommitted changes cannot be isolated
   safely, stop and ask the user rather than stashing, overwriting, or including
   them.
3. Verify the destination branch and any visible remote rules at execution
   time. Never infer permission to bypass a newly configured rule. If direct
   push is rejected, do not force it or redirect the push to `local`.
4. Record the original branch and commit. Before rewriting unpublished work,
   create a uniquely named local safety branch. Keep it on failure; remove only
   the branch created by this run after the final remote commit is verified.
5. Never rewrite a shared or published branch. If already-published commits
   need regrouping to satisfy this workflow, stop and ask. It is acceptable to
   rebuild unpublished conversation work on a fresh local branch based on
   `origin/master`.

## Prepare coherent commits

Each commit must contain one coherent logical change. Keep implementation and
its directly related tests in the same commit. Do not make a separate
"add tests" commit when those tests exist solely to verify an implementation
commit. Separate independent JWT, Redis, documentation, dependency, or other
concerns when each can stand and be reviewed on its own.

If all uncommitted changes are confirmed to be in scope, capture them on the
safety branch before restructuring. Use non-interactive Git operations only;
never open an editor or interactive rebase. After incorporating the latest
`origin/master`, rebuild unpublished commits with explicit path or patch
staging. Inspect the staged diff before every commit.

Commit subjects must match:

```text
TAG <Title>
```

Use exactly one of these tags:

- `[+]` for new functionality or a new project capability.
- `[-]` for removal.
- `[*]` for a functional logic change or bug fix.
- `[~]` for non-functional changes such as documentation, lint-only changes,
  or repository maintenance.
- `[^]` for a version pin or version bump.

Use an imperative, specific title after the tag. Commit bodies are optional.
When context is not obvious, use only the applicable prefixes:

```text
N: <note>
R: <reason for the change>
FB: <how the problem was fixed>
```

Do not add a body merely to repeat the subject. Validate all subjects in
`origin/master..HEAD` against `^\[(\+|-|\*|~|\^)\] .+`, and inspect every
non-empty body line for the `N:`, `R:`, or `FB:` convention. Do not introduce a
merge commit: the destination update must remain a fast-forward.

## Incorporate master

Rebase or rebuild the unpublished landing branch on the fetched
`origin/master` before verification. If any conflict occurs, do not resolve it,
even when the resolution appears obvious. Preserve the conflicted state,
report the conflicting paths, report that the changes have not landed, and ask
the user how to proceed. Continue only after the user has decided how the
conflict should be handled.

After integration, review the complete diff and commit list again. Check the
project contribution checklist: direct and facade tests, sync/async symmetry,
public imports and `__all__`, configuration and serialized-format
compatibility, optional dependency isolation, user-facing documentation, and
absence of credentials, generated release artifacts, or unrelated changes.
Substantial API or architecture changes require the issue-first agreement
described in `CONTRIBUTING.md:3-7`; stop if that applicable requirement is not
already satisfied.

## Required local verification

Run all of these commands against the exact final commit sequence:

```bash
uv run ruff check src/
uv run ruff format --check src/
uv run pyrefly check
```

Sources: `CONTRIBUTING.md:232-252` defines these exact commands;
`pyproject.toml:115-150` defines the Ruff and Pyrefly configuration.

Then run:

```bash
uv run pytest -x
uv build
```

Sources: `CONTRIBUTING.md:280-287` requires the full suite and distribution
build before submission; `.github/workflows/run-tests.yml:31-37` confirms the
CI test invocation; `pyproject.toml:88-94` defines the package build backend.

If any file under `docs/` changed, also run from `docs/`:

```bash
npm ci
npm run build
```

Sources: `CONTRIBUTING.md:289-301` requires these documentation checks;
`docs/package.json:6-10` defines `build`; `.github/workflows/deploy-docs.yml:
43-56` confirms the Node version, install command, working directory, and build
command.

All required commands must exit successfully. A prior run against another SHA
does not count. If a check fails, diagnose and fix only an in-scope issue,
rebuild affected commits if necessary, and rerun the complete required set.
Stop and report a blocker when the failure is unrelated or unsafe to repair.
Do not treat a pending, missing, partial, or unverifiable check as success.

Compare the worktree state before and after verification. Do not commit
generated build output or an incidental `uv.lock` change. Remove only output
created by this run, never pre-existing or unrelated files.

## Publish

1. Fetch `origin/master` again after local verification.
2. If it moved, incorporate the new tip and rerun the complete required local
   verification. Apply the conflict rule above without exception.
3. Confirm `origin/master` is an ancestor of HEAD, all commits and files are in
   scope, and the push is fast-forward.
4. Dry-run the exact update, then publish without force:

   ```bash
   git push --dry-run origin HEAD:master
   git push origin HEAD:master
   ```

   Sources: `pyproject.toml:57-61` identifies the GitHub repository and
   `master` links; `.github/workflows/run-tests.yml:3-10` identifies `master`
   as the push-tested destination. Runtime remote inspection remains
   authoritative for the `origin` transport.

5. If the push is rejected or the remote tip changed, fetch and reassess. Never
   use `--force`, `--force-with-lease`, or a deletion. Do not report success.
6. Verify with the remote, not just the local tracking ref, that
   `refs/heads/master` equals the exact landed HEAD SHA.

## Verify GitHub Actions

The push to `master` starts the `Run test` workflow defined in
`.github/workflows/run-tests.yml:1-37`. Query GitHub Actions for the exact
landed SHA and wait for that run to complete. The public GitHub API may be used
read-only when no authenticated hosting CLI is available.

Verify all of the following:

- the workflow path is `.github/workflows/run-tests.yml`;
- the event is the `master` push for the exact landed SHA;
- the workflow conclusion is `success`;
- every matrix job completed successfully for Linux and macOS across Python
  3.10, 3.11, 3.12, 3.13, and 3.14.

Pending, failed, canceled, missing, rate-limited, or otherwise unverifiable CI
is not landing success. If CI fails after the direct push, do not rewrite or
revert `master` automatically. Report clearly that the commit is already on
`master` but CI failed, with the commit and run links.

## Report the outcome

When running in a subthread and `report_subthread_status` is available, report
the final landing result to the parent. Otherwise report it directly in the
current conversation. Use `status: "success"` only after both the remote SHA
and successful CI run are verified. Use `status: "failure"` for a blocker,
conflict, rejected push, failed check, failed CI, or unverifiable outcome.
Failure is not terminal: continue safe recovery when the user supplies the
needed decision, then report the updated verified outcome.

Keep the status title to a few sentence-case words and the description to one
short line. Link the short SHA to
`https://github.com/mkrdnk/jam/commit/<full-sha>` and link the exact Actions run.
Do not invent a URL.

Examples:

- Success: title `Landed on master`; description
  `[abc1234](<commit-url>) · [CI passed](<run-url>).`
- Checks failed before push: title `Blocked by checks`; description
  `[Tests failed](<available-run-or-context-url>). Not landed.`
- Push rejected: title `Push blocked`; description
  `[abc1234](<commit-url-if-published>) passed local checks; push access required.`
- Conflict: title `Merge conflicts`; description
  `[abc1234](<commit-url-if-published>) conflicts with master. Not landed.`
- CI failed after push: title `Landed with failing CI`; description
  `[abc1234](<commit-url>) is on master; [CI failed](<run-url>).`

After verified success, state the landed short SHA, destination, and CI result.
Remove only the temporary safety branch created by this run and leave the
user's other branches and worktrees unchanged.
