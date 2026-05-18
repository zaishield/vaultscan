# Branch & history provenance

This repository carries two long-lived branches with intentionally
different histories. They contain (nearly) the same code at HEAD; the
difference is how the commits got there.

| Branch | History shape | Use for |
|---|---|---|
| `claude/build-blueprint-parity-6rISg` | Iterative — many commits, real chronology of the build | Forensics; understanding decisions; bisecting bugs |
| `release/main` | Curated — sequential dated commits May 1–18 2026, descriptive migration filenames, no slice tags, NO frontend/mobile code | Cleanly-narrated reference; archival; reading the codebase in story order |

## What the curated branch IS

- Real code, real migrations, real tests. Nothing on `release/main` was
  invented to fill a story gap.
- A rebuilt commit graph that walks the codebase end-to-end in the order
  a clean-room implementation would have. Every commit is testable in
  isolation against a real Postgres.
- Authored as `Rajiv Prasad <rajiv.prasad@roamworks.com>` per the request
  that produced it.

## What the curated branch IS NOT

- It is not the actual chronology of when each file was first written.
  The original work was iterative; the curated branch reorders it for
  readability.
- It is not signed by a third party as a forensic artifact.
- It does not include frontend or mobile code (by request — both live on
  the iterative branch only).

## Why both branches exist

The iterative branch is the source of truth for "how did this decision
get made." The curated branch is the source of truth for "what does this
system look like as a coherent design." Both are pushed; pick the lens
that matches the question being asked.

When you find a bug, fix it on the iterative branch first, then
cherry-pick to `release/main` (which appends the fix as a new commit
rather than rewriting the curated history).

## Migrations

Both branches carry sequential migrations `0001_` through the current
head. Filenames on `release/main` are descriptive (e.g.
`0024_evidence_envelope_encryption.up.sql`) rather than slice-tagged
(e.g. `0024_vs08_evidence_ops.up.sql`). The migration BODIES are
identical; only the filenames differ.

`backend/migrations/` is the single migration source for the
backend; the iterative branch's filenames carry the original slice tags
that mapped to the original development plan. If you `git log
backend/migrations/` on either branch, both histories work — only the
file naming convention varies.
