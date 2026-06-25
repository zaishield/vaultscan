# RYK StudioOS — The Build Bible
### *Powered by RYK Studio*

**Status:** Canonical specification. This document is the single source of truth for building RYK StudioOS. Where this document and any other artifact (chat message, verbal direction, old draft) disagree, this document wins until it is explicitly amended. Amendments are made by editing this file, not by working around it.

**Origin:** Derived from "The Platform Gap Report" (RYK Studio, June 2026). That report identified 10 production-layer gaps no AI generation platform has closed. This document is the buildable answer to Gap Opportunity #1: RYK StudioOS, the Agency-Grade AI Production Operating System.

**What this is not:** This is not a new image/video/audio generation model. RYK StudioOS never trains or hosts a foundation generation model except where Section 9 explicitly says otherwise (Arabic text rendering). It is the orchestration, memory, and accountability layer that sits above third-party generation APIs (Higgsfield, Runway, ElevenLabs, Suno, Adobe Firefly, etc.) and turns them into a system a creative director can run real client production through.

**How to read this document:** Sections 0–10 define *what* the product is (principles + modules). Section 11 defines the *cross-cutting engineering concerns* that every module must obey (security, tenancy, resilience, billing, compliance, ops). Section 12 is the binding tech stack. Section 13 defines what "Production-Ready," "Enterprise-Ready," and "GA" actually mean as hard checklists. Section 14 is the phase-by-phase implementation plan that drives toward those gates. Sections 15–16 are the decision log and glossary.

---

## 0. Non-Negotiable Principles

These principles override feature-level decisions anywhere in this document. If a future feature request conflicts with one of these, the principle wins.

1. **The Brief is the only source of truth.** Every artifact in the system — script, storyboard, generation job, asset, approval, invoice line — must trace back to a Brief record via foreign key. Nothing is allowed to exist as an orphan upload.
2. **Every generated asset is provenance-tracked.** No asset enters the system without a Provenance Record (model, prompt, params, cost, timestamp, operator). This is not optional and not deferred to "later phases" — it ships in Phase 1.
3. **The platform orchestrates models; it does not become one.** Don't build a competing image/video generator. The one sanctioned exception is the Arabic Visual Engine (Section 9), and only as a fine-tune of an open-weight base model, not a foundation model from scratch.
4. **Build for one real studio first.** Every feature in Phases 1–3 must be validated against actual RYK Studio client campaigns before being considered "done." A feature nobody used internally does not graduate to external SaaS.
5. **Open source for infrastructure, proprietary for generation.** Every piece of platform infrastructure (orchestration, database, auth, storage, workflow engine) must be open-source and self-hostable. Every piece of generation capability (the actual pixels/audio/video) is bought from the best available provider, proprietary or not. Do not violate this split in either direction — don't build your own LLM inference stack, and don't outsource the brand-memory database to a SaaS vendor.
6. **Data sovereignty is a first-class deployment property, not a feature flag bolted on later.** The system must be deployable entirely within a chosen region (including on-prem / Gulf-region cloud) from Phase 1 onward, even if Phase 1 doesn't need it yet.
7. **No client-visible feature ships without an audit trail.** Approvals, revisions, sign-offs — anything a client touches must be logged with timestamp, actor, and immutable record. This is the legal spine of Gap #5 and #10 and is not negotiable for scope-cutting.
8. **Every paid external call is idempotent and cost-capped.** No code path may charge a provider twice for the same logical request, and no campaign may exceed its authorized spend ceiling without an explicit human override. Money leaks are treated as Sev-1 defects, not accounting cleanup. *(Added — closes the runaway-credit loophole.)*
9. **Multi-tenant isolation is designed in Phase 1, even when there is one tenant.** Every domain row carries a `tenant_id` from the very first migration. Retrofitting tenancy later is forbidden — it is the single most expensive mistake this kind of platform can make. *(Added — closes the "tenancy deferred to Phase 4" loophole.)*

---

## 1. System Overview

```
                    ┌─────────────────────────────────────────┐
                    │              BRIEF ENGINE                │
                    │  (the one living document of record)     │
                    └───────────────────┬───────────────────────┘
                                        │ seeds
        ┌──────────────┬───────────────┼───────────────┬──────────────┐
        ▼              ▼               ▼               ▼              ▼
  ┌──────────┐  ┌──────────────┐ ┌───────────┐  ┌─────────────┐ ┌────────────┐
  │ BRAND DNA│  │ MULTI-MODEL  │ │ CAMPAIGN  │  │   BUDGET    │ │  EMOTION    │
  │  STORE   │  │ ORCHESTRATOR │ │VERSIONING │  │  PLANNER    │ │ TRANSLATOR  │
  └────┬─────┘  └──────┬───────┘ └─────┬─────┘  └──────┬──────┘ └─────┬──────┘
       │               │               │               │              │
       └───────────────┴───────┬───────┴───────────────┴──────────────┘
                                ▼
                    ┌───────────────────────┐
                    │   GENERATION JOBS      │  (Temporal workflows)
                    │   + PROVENANCE LEDGER  │
                    └───────────┬───────────┘
                                ▼
                    ┌───────────────────────┐
                    │     CLIENT PORTAL      │
                    │ (review/approve/sign)  │
                    └───────────┬───────────┘
                                ▼
                    ┌───────────────────────┐
                    │   IP DOCUMENTATION     │
                    │   (RYK CLEARANCE)      │
                    └───────────────────────┘

  ── cross-cutting (Section 11), present under every module ──
  Tenancy · RBAC · Secrets · Provider Resilience · Cost Governance ·
  Credit Ledger · Audit Log · Observability · Backup/DR · Compliance
```

Eight modules, sitting on the shared entity layer (Section 1.5) and governed by the cross-cutting concerns (Section 11). Each module is specified with: purpose, data model, required behaviors, explicit non-goals, and the gap(s) it closes.

---

## 1.5. Shared Core Entities (referenced everywhere — define once)

These entities are referenced by multiple modules. They are defined here so no module invents its own version. **Every one of these tables carries `tenant_id NOT NULL` (Principle 9) and `created_at / updated_at`.**

```
Tenant
 ├─ id, name, type (internal_studio | external_agency | enterprise | government)
 ├─ data_region (e.g. "uae-central", "eu-west") — pins where this tenant's data lives (Principle 6)
 ├─ plan (FK → Plan), status (active|suspended|trial)
 └─ feature_flags (jsonb — per-tenant capability gating)

User
 ├─ id, tenant_id, email, name
 ├─ role (FK → Role; see RBAC matrix 11.1)
 ├─ auth_provider_subject (external IdP subject id)
 └─ status (active|invited|disabled), last_login_at

Client            (the brand/customer a tenant produces work for — NOT a platform login)
 ├─ id, tenant_id, name, industry
 └─ primary_market[], notes

Asset             (the central output object — referenced by jobs, portal, provenance)
 ├─ id, tenant_id, brief_id, generation_job_id (nullable for uploads)
 ├─ kind (image|video|audio_vo|audio_music|audio_sfx|document)
 ├─ storage_uri (MinIO/S3 object key), checksum_sha256, byte_size, mime_type
 ├─ version_no, supersedes_asset_id (nullable — version chain)
 ├─ status (generating|ready|failed|archived|deleted)
 ├─ derived_from_asset_id (nullable — for versioning/upscale lineage)
 └─ retention_class (FK → RetentionPolicy; see 11.6)

AuditEvent        (append-only, hash-chained — see 11.12)
 ├─ id, tenant_id, actor_user_id (nullable for system), actor_type (user|system|client_guest)
 ├─ action, target_type, target_id, occurred_at
 ├─ payload (jsonb — before/after where relevant)
 └─ prev_hash, this_hash (sha256 chain for tamper-evidence)
```

**Invariants:**
- `Asset.brief_id` is `NOT NULL` for every generated asset (Principle 1). Manual uploads must still be attached to a Brief.
- An `Asset` is never hard-deleted while referenced by an `Approval`, `ProvenanceRecord`, or `RightsRecord` — deletion sets `status=deleted` and triggers the retention workflow (11.6), preserving the legal record.
- No row in any domain table may be written without a `tenant_id`. Enforced via Postgres Row-Level Security (RLS) policies, not just application code.

---

## 2. Module: Brief Engine

**Closes:** Gap #1 (Production Pipeline), Gap #7 (Campaign Versioning, partially)

**Purpose:** The brief is not a document attached to a project. The brief IS the project. Every other module reads from and writes back to the Brief record.

### Data model

```
Brief
 ├─ id, tenant_id, client_id, title, status (draft|active|in_review|approved|archived)
 ├─ objective (free text — the actual creative ask)
 ├─ emotional_direction_id (FK → EmotionDirection, nullable until Emotion Translator runs)
 ├─ brand_dna_id (FK → BrandDNA)
 ├─ market_targets[] (e.g. ["UAE","KSA","Egypt"])
 ├─ format_targets[] (e.g. ["16:9","9:16","1:1"])
 ├─ dialect_targets[] (e.g. ["Gulf Arabic","Egyptian Arabic","English"])
 ├─ calendar_context (nullable FK → CulturalCalendarEvent, e.g. Ramadan)
 ├─ budget_tier (FK → BudgetEstimate), spend_ceiling_usd (hard cap, Principle 8)
 ├─ created_by, created_at, updated_at
 └─ revision_history[] (append-only log of every field change, actor, timestamp)
```

### Required behaviors

- A Brief cannot be deleted, only archived. Revision history is append-only — never overwritten.
- Changing any field on an active Brief that has already spawned generation jobs creates a new **Brief Revision** and prompts the user: "this affects N downstream jobs — re-run them?" Never silently invalidates work in progress.
- The Brief view shows a live tree of everything it has spawned: scripts, storyboards, generation jobs, assets, approvals — this tree is the literal UI manifestation of Principle 1.
- A Brief carries a `spend_ceiling_usd`. The Orchestrator refuses to start jobs that would exceed it without an explicit override event recorded in the audit log (Principle 8).

### Explicit non-goals

- The Brief Engine is not a generic project management tool (no Gantt charts, no time tracking). Resist scope creep toward becoming a Jira clone.

---

## 3. Module: Brand DNA Store

**Closes:** Gap #3 (Brand DNA)

**Purpose:** Store not just brand assets (logo, colors, fonts) but brand *behavior*: how a brand should feel across campaigns, encoded as reusable, structured presets — not prose nobody re-reads.

### Data model

```
BrandDNA
 ├─ id, tenant_id, client_id, brand_name
 ├─ visual_grammar (structured: lighting_style, color_temperature, composition_rules, environment_type)
 ├─ emotional_register (structured tags: e.g. "cold/clean/confident" for Head & Shoulders)
 ├─ locked_model_presets[] (per generation model: which model, which params are pinned, which are open)
 ├─ character_library[] (FK → TalentConfig — recurring characters/talent with consistency seeds, e.g. Soul ID references)
 ├─ market_variants[] (per-market overrides, e.g. Always Egypt vs Always Jordan femininity representation rules)
 ├─ prohibited_elements[] (things this brand must never show — explicit deny-list, not just style guide prose)
 └─ campaign_history[] (FK → Brief[], so the system literally remembers every past campaign for this brand)
```

### Required behaviors

- Every Brief MUST reference exactly one BrandDNA record before any generation job can be created. This is enforced at the database level (NOT NULL FK), not just a UI suggestion.
- `locked_model_presets` are versioned. When a brand's visual identity is "locked" for a campaign, every generation job for that campaign reads the locked preset, not ad-hoc prompts.
- New campaigns for an existing brand pre-populate from the BrandDNA, not from a blank brief. The system must demonstrably get *easier* to brief the 5th time for a given brand than the 1st.
- `prohibited_elements` and `market_variants` are consumed by the Content Safety enforcement layer (11.8) as hard pre-generation guardrails, not advisory notes.

### Explicit non-goals

- Not a DAM (Digital Asset Management) system. Don't build a generic file browser here — that's the asset layer under Generation Jobs.

---

## 4. Module: Multi-Model Orchestrator

**Closes:** the "Wrapper Trap" warning, Gap #1, Gap #6 (Audio-Visual Unity)

**Purpose:** Route each generation task to the right model for the right reason (quality, cost, capability), execute it durably, and treat audio and visual generation as one governed brief rather than four disconnected tool calls.

### Architecture decision

Use **Temporal** (open source, self-hosted) as the workflow engine. Each generation pipeline (e.g. "3-scene brand film, UAE + KSA, 16:9 + 9:16, English + Gulf Arabic VO") is modeled as a single Temporal Workflow with parallel branches per market/format/dialect combination. This is the concrete mechanism for Gap #7 (Campaign Versioning) — the "master campaign" is the workflow definition; the 16+ derivative versions are parallel workflow executions sharing the same Brief and BrandDNA inputs.

```
GenerationJob (Temporal Workflow instance)
 ├─ id, tenant_id, brief_id, brand_dna_id
 ├─ idempotency_key (deterministic hash of {brief_rev, task, params} — Principle 8)
 ├─ task_type (script | storyboard | video | image | vo | music | sfx)
 ├─ assigned_model (e.g. "higgsfield:kling-v2", "elevenlabs:vo-arabic-gulf")
 ├─ routing_reason (why this model was chosen — quality/cost/capability — logged, not implicit)
 ├─ params (full request payload sent to provider, stored verbatim)
 ├─ status (queued|running|succeeded|failed|needs_review|cancelled)
 ├─ cost_estimate_usd, cost_actual_usd (reconciled against Budget Planner + Credit Ledger)
 ├─ provider_request_id (returned by provider — for webhook correlation, 11.3)
 ├─ output_asset_id (FK → Asset, once complete)
 └─ retry_count, last_error, circuit_state
```

### Required behaviors

- **Provider adapters are isolated.** Each provider (Higgsfield, Runway, ElevenLabs, Suno, Adobe Firefly, Midjourney-manual) gets its own adapter module implementing a shared `GenerationProvider` interface (`submit()`, `poll()`, `cancel()`, `estimateCost()`, `handleWebhook()`). New providers are added by writing one adapter, never by touching orchestration logic.
- **Idempotency is mandatory (Principle 8).** Every `submit()` carries an `idempotency_key`. On Temporal retry, the adapter must not re-charge the provider — it re-checks by `provider_request_id` first. Adapters for providers that don't support idempotency keys natively must implement a local dedupe guard.
- **Provider resilience is built in, not bolted on.** Adapters run behind circuit breakers and honor per-provider rate limits and fallback routing (see 11.3). A down provider degrades gracefully (queue + alert), it does not crash a campaign.
- **Sonic identity is a BrandDNA field, not an afterthought.** Audio generation jobs (VO, music, SFX) read `BrandDNA.emotional_register` the same way visual jobs read `visual_grammar`. A campaign's music brief and video brief are derived from the same emotional direction, submitted as sibling branches of the same Temporal workflow, not sequential disconnected tool calls.
- **Every job failure is visible, not silently retried into oblivion.** Temporal gives durable retry semantics — use them, but surface failed/needs_review jobs prominently in the Brief tree view.
- **Routing is rules-based first, ML-assisted later.** Phase 1–3 routing logic is explicit if/else rules per task type and quality tier (defined in Budget Planner, Section 6). Do not build a "smart router ML model" before the rules-based version has been used on real campaigns.

### Explicit non-goals

- Do not attempt to normalize all providers into one unified prompt schema. Visual, audio, and video models have genuinely different parameter spaces — the adapter layer translates from a common internal brief representation into each provider's native schema, but does not pretend they're interchangeable.

---

## 5. Module: Campaign Versioning Engine

**Closes:** Gap #7

**Purpose:** One master generation produces N derivative versions (market × format × dialect × calendar variant) without re-briefing from scratch.

### Data model

```
VersioningMatrix
 ├─ id, tenant_id, brief_id
 ├─ axes: markets[], formats[], dialects[], calendar_variants[]
 ├─ derivation_rules[] (per-axis overrides — e.g. "KSA variant: swap VO model, apply stricter prohibited_elements")
 └─ generated_combinations[] (FK → GenerationJob[], one per resolved combination)
```

### Required behaviors

- Given a Brief with `market_targets=[UAE,KSA]`, `format_targets=[16:9,9:16]`, `dialect_targets=[Gulf,Egyptian]`, the system computes the full cartesian product (8 combinations here) and spawns one GenerationJob branch per combination automatically — the user defines axes once, not 8 times.
- `derivation_rules` allow per-axis overrides without forking the brief (e.g., "for KSA, always use the stricter prohibited_elements list from BrandDNA.market_variants").
- The matrix view shows all derivative versions against the master in a single grid — this is the literal UI fix for "no platform has versioning intelligence."
- The full matrix's combined `cost_estimate` is checked against `Brief.spend_ceiling_usd` before any branch starts (Principle 8). A 16-version matrix that blows the budget is caught before generation, not after.

---

## 6. Module: Budget Planner

**Closes:** Gap #8

**Purpose:** Forecast generation cost before generation happens, and reconcile actual spend after.

### Data model

```
BudgetEstimate
 ├─ id, tenant_id, brief_id
 ├─ scope_inputs (number of scenes, formats, markets, dialects, quality tier)
 ├─ per_task_estimates[] (task_type, recommended_model, estimated_credits, estimated_usd)
 ├─ total_estimate_usd
 └─ actual_spend_usd (rolled up from GenerationJob.cost_actual_usd via the Credit Ledger, 11.5)

ProviderCostTable        (the maintained source of truth for pricing)
 ├─ provider, model, unit (per_second|per_image|per_1k_chars|per_credit)
 ├─ unit_cost_usd, effective_from, effective_to
 └─ changelog_note, updated_by    (Higgsfield reprices often — this needs an owner, not a hardcode)
```

### Required behaviors

- Estimate is generated BEFORE the first generation job is submitted, from the `ProviderCostTable`. The table is versioned with effective dates and a changelog — never a hardcoded constant buried in code.
- Variance between `total_estimate_usd` and `actual_spend_usd` is surfaced per campaign — this is the studio's real financial control mechanism, not a nice-to-have dashboard.
- The estimate feeds `Brief.spend_ceiling_usd` as a default the user can raise/lower; the ceiling, not the estimate, is what the Orchestrator enforces (Principle 8).

---

## 7. Module: Emotional Direction Translator

**Closes:** Gap #9

**Purpose:** Convert a human emotional brief into model-ready prompt architecture across image, video, and audio simultaneously.

### Data model

```
EmotionDirection
 ├─ id, tenant_id, brief_id
 ├─ raw_input (free text — "the feeling of calling your mother for the first time from a different country")
 ├─ resolved_parameters (structured output: lighting, pacing, color grade, music tempo/key, VO tone, camera movement)
 ├─ translator_model (which LLM performed the translation, e.g. Claude)
 └─ human_reviewed (boolean — Principle: emotional intelligence requires human oversight, never fully automated)
```

### Required behaviors

- This module calls an LLM (via LiteLLM gateway, Section 12) to translate `raw_input` into `resolved_parameters`, but `resolved_parameters` is **always presented to a human creative director for edit/approval before being passed to the Orchestrator.** `human_reviewed=false` blocks generation job creation. This is non-negotiable per the source report's own caveat that this "can't be purely automated."
- Approved `resolved_parameters` are saved as reusable Direction Templates, attached to BrandDNA for reuse on future campaigns.
- Phase placement: per the source report, this ships as a feature inside RYK StudioOS, not a standalone product. Do not let it grow a separate UI shell.

---

## 8. Module: Client Portal

**Closes:** Gap #2

**Purpose:** Replace WhatsApp/Drive/WeTransfer with a single client-facing surface for review, structured feedback, and legally meaningful approval.

### Data model

```
ReviewLink
 ├─ id, tenant_id, brief_id, asset_ids[], expires_at, access_token (signed, scoped, revocable)
 ├─ allowed_actions (view|comment|approve)
 └─ created_by

Feedback
 ├─ id, tenant_id, review_link_id, asset_id, comment_text, timestamp_marker (for video — frame/timecode)
 ├─ author_name (client-side, no login required), created_at
 └─ resolved (boolean)

Approval
 ├─ id, tenant_id, review_link_id, asset_id, approver_name, approver_email
 ├─ signature_record_id (FK → Documenso envelope)
 ├─ approved_at, ip_address
 └─ status (pending|approved|rejected|revision_requested)
```

### Required behaviors

- Review links are shareable without requiring the client to create an account (frictionless access, token-based). Tokens are signed, scoped to specific assets, time-boxed via `expires_at`, and individually revocable.
- Feedback is structured (attached to a specific asset, optionally a specific timecode/frame) — not freeform chat, directly fixing "can you make it more premium?" ambiguity by forcing comment-to-asset attachment as a UX pattern (the UX should still allow free text, but it must be anchored to a specific asset/version).
- Approval is a real e-signature event via **Documenso** (self-hosted, open source), producing a legally meaningful, timestamped, IP-logged record — not a "Looks good!" WhatsApp message. This satisfies Principle 7.
- All revisions are versioned (via `Asset.version_no` / `supersedes_asset_id`); the client always sees a version history, never just "the latest file."
- Every guest action writes an `AuditEvent` with `actor_type=client_guest` (Principle 7 + 11.12).

---

## 9. Module: MENA Cultural Intelligence Layer (codename RYK MARJAN, integrated as a module)

**Closes:** Gap #4, contributes to Gap #10

**Purpose:** Per the source report, this is the most defensible, least-contested-by-incumbents capability. Build it as a module inside RYK StudioOS first (per Build Phase P3), with the option to spin out as a standalone product later if validated.

### Sub-components

1. **Cultural Calendar Service** — a maintained dataset (Hijri calendar conversion, Ramadan dates, UAE/KSA National Days, regional observances) exposed as a service that BrandDNA and Brief records can subscribe to (`calendar_context` field, Section 2). Source this from an open Hijri calendar library (e.g. `hijri-converter` or equivalent open dataset) — do not hand-roll calendar math.
2. **Cultural Visual Library** — structured presets per market (UAE, KSA, Egypt, Levant) covering dress code defaults, family representation norms, architectural grammar, and approved color palettes for cultural moments. Stored as BrandDNA `market_variants` (Section 3) — this is data curation work, not a separate codebase.
3. **Dialect Layer** — VO direction metadata (Gulf / Egyptian / Levantine Arabic) attached to GenerationJob params when routing to VO providers (ElevenLabs or equivalent with Arabic dialect support).
4. **Cultural Compliance Guardrails** — the Cultural Visual Library and per-market rules feed the Content Safety enforcement layer (11.8) as *hard* pre- and post-generation checks for institutional/government work, not advisory hints.
5. **Arabic Visual Engine (the one sanctioned model-training exception, Principle 3)** — Arabic text rendering inside generated imagery is broken across all current providers. The fix is a fine-tune (LoRA) on an open-weight diffusion base model (e.g. Flux.1 or SDXL) trained specifically on correct Arabic typography in-scene. This is scoped explicitly:
   - Do not attempt to build a general-purpose competing image model.
   - Scope is narrow: render legible, correctly-shaped, non-mirrored Arabic text within generated scenes.
   - This is a Phase 3 research effort, gated on P1/P2 being live and validated first. Do not pull this forward — it is the highest-risk, highest-effort item in the entire blueprint and must not block anything else.
   - **Acceptance bar:** ≥95% character-accuracy on a held-out test set of brand-relevant Arabic phrases, human-graded, before any client-facing use. Below that bar it stays an internal experiment.

---

## 10. Module: IP Documentation (codename RYK CLEARANCE, integrated as a module)

**Closes:** Gap #5, contributes to Gap #10

### Data model

```
ProvenanceRecord
 ├─ id, tenant_id, asset_id, generation_job_id
 ├─ model_used, model_version, provider
 ├─ training_data_disclosure (text/link, as published by provider)
 ├─ usage_rights_summary (derived from provider's commercial terms)
 ├─ generated_at, generated_by
 └─ certificate_hash (sha256 of the record — tamper-evidence, shown on client-facing cert)

ModelReleaseFlow
 ├─ id, tenant_id, asset_id, requires_release (boolean — auto-flagged for generated human likeness)
 ├─ release_document_id (FK → Documenso envelope)
 └─ status (not_required|pending|signed)

RightsRecord
 ├─ id, tenant_id, asset_id, channel[] (broadcast|digital|print|social), markets[], valid_from, valid_until
 └─ jurisdiction_notes (free text, e.g. UAE Take It Down Act equivalent considerations)
```

### Required behaviors

- `ProvenanceRecord` is created automatically and atomically when a `GenerationJob` completes — this is not a manual data-entry step. Principle 2 enforcement happens at the data layer: a `GenerationJob.status = succeeded` transition with no corresponding `ProvenanceRecord` is a system invariant violation that alerts, never silently passes.
- `ModelReleaseFlow.requires_release` auto-flags based on a simple heuristic in Phase 1 (does this asset use a `character_library` entry with a real-person likeness reference?) and can be made smarter later, but must exist from Phase 1 — even a crude flag beats none.
- Client-facing "compliance certificate" is a generated PDF (server-rendered via Playwright headless) combining ProvenanceRecord + RightsRecord + signed releases for a given asset or campaign — the literal deliverable for enterprise/government clients who ask "how was this made?"
- CLEARANCE is designed to be exposable as a standalone API in Phase 4+ (the report calls it "the most modular" concept) — keep its service boundary clean so it can be sold separately.

---

## 11. Cross-Cutting Engineering Concerns (binding on every module)

Modules describe *what* the product does. This section describes the engineering properties *every* module must satisfy. A module is not "done" if it violates anything here. This section exists to close the loopholes that module specs alone leave open.

### 11.1 Identity, Tenancy & RBAC

- **Tenancy model:** shared schema, `tenant_id` on every row, enforced by Postgres **Row-Level Security** policies keyed off a session variable set per request. No application query may rely on app-code filtering alone.
- **Authentication:** **Authentik** (or Keycloak) as the IdP. Studio users and external-agency users authenticate via OIDC. Client reviewers use scoped, signed magic links (no account) — they are never `User` rows.
- **RBAC matrix (baseline roles):**

| Role | Briefs | BrandDNA | Generation | Budgets/Spend override | Client Portal admin | IP/Clearance | Tenant settings/billing |
|---|---|---|---|---|---|---|---|
| Owner/Admin | CRUD | CRUD | CRUD | Yes | Yes | CRUD | Yes |
| Creative Director | CRUD | CRUD | CRUD | Up to ceiling | Yes | Read | No |
| Producer | CRUD | Read | CRUD | No | Yes | Read | No |
| Operator/Artist | Read/Edit assigned | Read | Run jobs | No | No | Read | No |
| Finance | Read | Read | Read | Yes | No | Read | Yes (billing only) |
| Client Guest | — (scoped link) | — | — | — | comment/approve only | view cert only | — |

- All role checks are server-side (tRPC middleware), never UI-only. Privilege changes are audited.

### 11.2 Security & Secrets

- **Secrets management:** all provider API keys and signing keys live in a secrets manager (**HashiCorp Vault**, open source, self-hosted; or cloud KMS in managed deployments) — never in env files committed to the repo, never in the database in plaintext.
- **Encryption:** TLS 1.2+ in transit everywhere; encryption at rest for Postgres and MinIO buckets; per-tenant encryption keys for enterprise/government tenants requiring it.
- **Tenant-scoped provider keys (enterprise):** enterprise/government tenants may supply their own provider API keys so generation runs on their commercial accounts and their data-processing terms — stored per-tenant in Vault.
- **AppSec baseline:** dependency scanning (the repo already surfaces Dependabot alerts — these must be triaged, not ignored), SAST in CI, secret-scanning pre-commit + CI, and an annual third-party penetration test from Enterprise-readiness onward.
- **Threat model owned and reviewed each phase** (STRIDE-level): the highest-value targets are provider API keys (financial loss) and the audit/provenance ledger (legal integrity). Both get the strongest controls.

### 11.3 Provider Resilience (idempotency, webhooks, circuit breakers, fallback)

- **Idempotency** (Principle 8): every paid `submit()` carries an `idempotency_key`; retries never double-charge. Adapters dedupe by `provider_request_id`.
- **Async by webhook + reconciliation:** most generation is async. Each adapter exposes a webhook endpoint to receive provider completion callbacks, correlated by `provider_request_id`. A periodic reconciliation job polls for any job whose webhook never arrived — webhooks are an optimization, never the sole completion path.
- **Circuit breakers + rate limits:** per-provider circuit breaker opens on sustained failures and routes new jobs to a fallback model (per Budget Planner routing rules) or queues them with a visible "provider degraded" state. Per-provider concurrency/rate caps prevent one campaign from exhausting a shared quota.
- **Cost reconciliation:** actual provider charges (from billing webhooks or polled usage) reconcile against `cost_estimate_usd` and post to the Credit Ledger (11.5). Drift beyond a threshold alerts Finance.

### 11.4 Cost Governance & Spend Caps

- Hard ceilings at three levels: **per-Brief** (`spend_ceiling_usd`), **per-Tenant** (monthly), and **per-Provider** (global safety valve).
- Crossing any ceiling halts new job submission and requires an explicit, audited override by an Owner/Admin or Finance role (Principle 8).
- Real-time spend dashboard per tenant; alerts at 50/80/100% of each ceiling.

### 11.5 Billing & Credit Ledger

- **Credit Ledger** is a double-entry, append-only ledger: every provider charge is a debit; every client invoice/credit purchase is a credit. This is the financial system of record — `BudgetEstimate.actual_spend_usd` is derived from it, never the other way around.
- **External billing (Phase 4+):** **Stripe** for subscriptions + metered usage. Pricing model per the source report: base SaaS subscription + generation-credit markup (wholesale provider rates resold with margin). Government/enterprise may be invoiced manually outside Stripe.
- Ledger entries are immutable; corrections are compensating entries, never edits.

### 11.6 Data Lifecycle, Retention, Backup & DR

- **Retention policies** per `Asset.retention_class` (e.g. active-campaign, archived, legal-hold). Legal-hold assets (anything tied to a signed Approval or RightsRecord) cannot be deleted until the hold lifts — overrides "right to be forgotten" for the specific legal record while still honoring it for incidental personal data.
- **Backups:** Postgres PITR (point-in-time recovery) + nightly logical dumps; MinIO bucket versioning + cross-region replication for enterprise. **Backups are restore-tested on a schedule** — an untested backup is not a backup.
- **DR targets:** Production-readiness requires documented and *drilled* RPO ≤ 1h / RTO ≤ 4h. Enterprise/government may demand tighter, region-pinned targets.

### 11.7 Compliance & Privacy

- **Privacy:** GDPR (for any EU-touching data), **UAE PDPL** and **Saudi PDPL** for MENA — data-subject access/deletion workflows, DPA templates, records of processing. Data-region pinning (Principle 6) is the technical backbone.
- **Certifications roadmap:** **SOC 2 Type II** is the gating bar for "Enterprise-Ready" (Section 13); **ISO 27001** pursued in parallel for government engagements. Begin control collection (access reviews, change management, incident logs) from Phase 1 so the audit isn't a scramble later.
- **AI content regulation:** track US Take It Down Act, UAE/KSA AI-content rules; CLEARANCE provenance records are the compliance artifact.

### 11.8 Content Safety & Cultural Compliance Enforcement

- **Pre-generation guardrails:** prompts are checked against `BrandDNA.prohibited_elements` and (for MENA work) the Cultural Visual Library rules *before* a paid job is submitted — cheaper and safer to block early.
- **Post-generation review:** generated assets pass an automated safety screen (provider moderation signals + a lightweight classifier) and, for government/Ramadan/National-Day work, a mandatory human cultural-QA step recorded in the audit log. Per the source report, MENA content still requires human QA — the system makes that step explicit and tracked, not informal.

### 11.9 Observability & SLOs

- **Stack:** OpenTelemetry traces/metrics/logs into Grafana/Loki/Tempo/Prometheus (all open source).
- **SLOs (production):** API availability ≥ 99.9%; generation-job success rate (excluding provider-side failures) ≥ 99%; p95 portal page load < 2s. Error budgets tracked; burn alerts page on-call.
- **Golden signals + provider health board:** a live view of every provider's circuit state, latency, and error rate — the multi-provider failure surface is the #1 operational risk.

### 11.10 Testing & Quality Gates

- **Unit + integration** for all business logic; **contract tests** for every provider adapter (recorded fixtures + periodic live smoke tests against sandboxes).
- **E2E** (Playwright) for the brief→generation→review→approval critical path.
- **Load tests** against the Orchestrator and portal before each readiness milestone.
- **Coverage gate** and green CI required to merge; no merge to the release branch on red.

### 11.11 CI/CD & Release Management

- Trunk-based-ish with short-lived branches; CI runs lint + typecheck + tests + SAST + secret-scan + migration check.
- **Zero-downtime, reversible DB migrations** (expand/contract pattern); every migration has a tested rollback.
- Environments: **dev → staging → production**, staging mirrors prod topology. Blue/green or rolling deploys; feature flags for risky features.

### 11.12 Audit Log & Tamper-Evidence

- `AuditEvent` (Section 1.5) is append-only and **hash-chained** (`this_hash = sha256(prev_hash + payload)`) so any retroactive edit is detectable. This is the technical backbone of Principle 7 and the legal credibility of CLEARANCE.
- Every approval, sign-off, spend override, role change, and data deletion writes an AuditEvent.

---

## 12. Technology Stack (Definitive — Do Not Substitute Without Updating This Section)

This section is binding. If a future contributor wants to swap a tool, they edit this document and justify the change here first — they do not silently introduce a different tool in code.

| Layer | Choice | Why / Constraint |
|---|---|---|
| Frontend + internal app | **Next.js 15 (App Router), TypeScript, React Server Components** | Single codebase serves internal tool, client portal, and future external SaaS. RTL/Arabic UI support required (i18n from Phase 1 scaffolding). |
| API layer | **tRPC** | End-to-end type safety, fast iteration for small team |
| Database | **PostgreSQL** + Row-Level Security | System of record; FK integrity (Principle 1) + tenant isolation (Principle 9) |
| Vector/semantic search | **pgvector extension** | Brand DNA / prompt library similarity search — no separate vector DB at this scale |
| ORM | **Drizzle** (preferred) or Prisma | Type-safe schema, migration discipline (expand/contract) |
| Workflow orchestration | **Temporal (self-hosted, open source)** | Durable, multi-branch generation pipelines; versioning matrix (§5); human-in-the-loop (§7) |
| LLM gateway | **LiteLLM (open source)** | Unified interface for brief/script/emotion-translation LLM calls; swappable backends |
| Provider adapters | **Custom adapter modules per provider** | Intentionally proprietary glue — platform IP, not a generic wrapper lib |
| Object storage | **MinIO (self-hosted, S3-compatible)** | Data-sovereignty option (Principle 6); versioning + replication for DR |
| E-signature / audit | **Documenso (open source)** | Model releases, client approvals — Principle 7 |
| Auth / IdP / tenancy | **Authentik or Keycloak (open source)** | OIDC; studio users, agency users, scoped guest links |
| Secrets management | **HashiCorp Vault (open source)** | Provider API keys, signing keys, per-tenant keys (11.2) |
| Billing | **Stripe** (Phase 4+) | Subscriptions + metered credit usage; manual invoicing for gov |
| Real-time collab (optional, P2+) | **Yjs + Hocuspocus (open source)** | Only if live co-annotation validated; not before Portal v1 |
| Background jobs (non-workflow) | **BullMQ (Redis-backed)** | Lightweight queue (PDF render, reconciliation polls) |
| Search | **Meilisearch or Typesense (open source)** | Past campaigns, brand assets, prompt libraries |
| Observability | **OpenTelemetry + Grafana/Loki/Tempo/Prometheus** | Multi-provider failure surface visibility (11.9) |
| CI/CD | **GitHub Actions** (+ SAST, secret-scan, migration check) | Quality gates (11.10–11.11) |
| Deployment (P1) | **Docker Compose** | Single-studio internal use |
| Deployment (P4+) | **k3s or Coolify (open-source PaaS)** | Externalization; Coolify preferred unless team grows |
| Calendar/Hijri data | **Open Hijri calendar library/dataset** | Cultural Calendar Service (§9) — do not hand-roll |
| PDF generation | **Playwright (headless render)** | Compliance certificates (§10) |
| Arabic Visual Engine (P3 research) | **LoRA fine-tune on Flux.1 / SDXL (open weights)** | Sanctioned model exception (Principle 3, §9) |

### Proprietary (non-substitutable, by design — Principle 5)

| Capability | Provider(s) |
|---|---|
| Multi-model video generation | Higgsfield (aggregator), Runway, Kling, Veo |
| Image generation | Adobe Firefly (IP-indemnified work), Midjourney (manual, concept work only — no API) |
| Upscaling/enhancement | Magnific (specialist use only) |
| Voice generation | ElevenLabs |
| Music generation | Suno |
| LLM (brief/script/emotion translation) | Claude (Anthropic), routed via LiteLLM so alternates can be added without rework |

---

## 13. Readiness Definitions (the hard gates)

These three bars are referenced by the phase plan (Section 14). A phase that claims to deliver one of these must satisfy *every* checkbox in that bar — partial is not the bar.

### 13.1 Production-Ready (the studio can bet real client work on it)
- [ ] All critical-path flows (brief → generation → review → approval → delivery) work end-to-end with no manual DB surgery.
- [ ] Idempotency + spend caps enforced (Principles 8); no path can double-charge or run away on spend.
- [ ] Provenance auto-created on every successful job (Principle 2); zero orphan assets (Principle 1).
- [ ] Observability live: tracing, metrics, alerting, provider health board.
- [ ] Backups automated **and restore-tested**; DR runbook drilled (RPO ≤ 1h / RTO ≤ 4h).
- [ ] Secrets in Vault; TLS + encryption-at-rest everywhere; SAST + secret-scan green in CI.
- [ ] On-call rotation + incident runbooks exist.
- [ ] Load-tested at 3× expected peak with SLOs met.

### 13.2 Enterprise-Ready (a P&G / large agency can buy it)
- [ ] Everything in 13.1, plus:
- [ ] **SOC 2 Type II** achieved (or in active audit with controls operating).
- [ ] Multi-tenant isolation verified by third-party pen test; RLS proven.
- [ ] SSO/SAML/OIDC for enterprise IdPs; SCIM provisioning; full RBAC (11.1).
- [ ] Per-tenant data-region pinning + optional customer-managed provider keys.
- [ ] Contractual SLAs, status page, DPA, and signed sub-processor list.
- [ ] CLEARANCE compliance certificates accepted by at least one enterprise legal team.

### 13.3 GA (open, self-serve, generally available)
- [ ] Everything in 13.1 + 13.2 relevant items, plus:
- [ ] Self-serve onboarding + billing (Stripe) with credit ledger reconciliation.
- [ ] Public API + docs (incl. CLEARANCE-as-API) with versioning and rate limits.
- [ ] White-label theming; tenant lifecycle (trial → paid → suspend → offboard/export).
- [ ] Documented support process + SLAs by plan tier.
- [ ] Data-export + account-deletion (PDPL/GDPR) self-serve.
- [ ] ≥ 3 external paying tenants live through a full campaign cycle without high-sev incidents.

---

## 14. Phase-Wise Implementation Plan (to full GA / Enterprise / Production readiness)

Each phase lists **workstreams → deliverables → exit gate**. A phase is done only when its exit gate is fully true. Items marked *(early-start OK)* may begin in the prior phase; nothing else may.

### Phase 0 — Foundations (Weeks 0–4) · *no product features yet, by design*
**Goal:** lay the rails so later speed doesn't create debt that violates Principles 8 & 9.
- **Platform:** monorepo scaffold (Next.js + tRPC + Drizzle); Docker Compose for Postgres, Temporal, MinIO, Redis, Authentik, Vault, OTel/Grafana.
- **Data:** initial migration with `Tenant`, `User`, `Client`, `Asset`, `AuditEvent` and **RLS policies + `tenant_id` everywhere from commit one** (Principle 9).
- **Security/Ops:** Vault wired; CI with lint/typecheck/test/SAST/secret-scan; staging env stood up.
- **Exit gate:** a "hello-tenant" request flows through auth → RLS-scoped query → audit event, with a trace visible in Grafana. CI is green and blocks merges on red.

### Phase 1 — Internal Production Tool (Months 1–3) · *single tenant (RYK Studio), Production-Ready for internal use*
**Workstreams:**
- **Brief Engine + Brand DNA Store** (§2, §3): create brief, BrandDNA for ≥2 real clients, live spawn-tree UI.
- **Orchestrator + 2 adapters** (§4, 11.3): Higgsfield + ElevenLabs, with idempotency, webhooks + reconciliation, circuit breakers.
- **Provenance** (§10): auto-created on every success; invariant alert if missing (Principle 2).
- **Budget Planner + Credit Ledger** (§6, 11.5): ProviderCostTable seeded; spend ceilings enforced (Principle 8).
- **Ops:** backups + restore test; provider health board; on-call runbook v1.
- **Exit gate:** one real campaign ran fully through the system instead of Docs+WhatsApp; the team chooses to repeat voluntarily; **internal Production-Ready (13.1) checklist passes.**

### Phase 2 — Client Portal (Months 3–6) · *first external-facing surface*
- **Portal** (§8): scoped review links, structured feedback, versioned assets, Documenso e-sign approval, guest audit events.
- **Hardening:** abuse/rate-limit on public link endpoints; content-safety pre/post screens (11.8) v1.
- **Exit gate:** ≥1 real client approves a deliverable in-portal with a signed audit trail; portal critical path E2E-tested and load-tested.

### Phase 3 — MENA Intelligence Layer / RYK MARJAN (Months 6–12) · *the defensible moat*
- **Cultural Calendar Service + Cultural Visual Library** (§9) for UAE/KSA/Egypt; Dialect Layer in VO routing.
- **Cultural compliance guardrails** wired into 11.8 as hard checks for institutional work.
- **Arabic Visual Engine** — research spike only; gated on ≥95% char-accuracy bar before any client use.
- **Exit gate:** a real Ramadan/National-Day campaign used the cultural layer with measurably less manual correction than the prior year.

### Phase 4 — Multi-Tenant SaaS + Enterprise Readiness (Year 2, H1) · *toward Enterprise-Ready (13.2)*
- **Tenancy at scale:** verify RLS isolation under pen test; tenant lifecycle; per-tenant data-region pinning + customer-managed provider keys.
- **Enterprise auth:** SAML/OIDC SSO, SCIM, full RBAC.
- **Billing:** Stripe subscriptions + metered credits reconciled to the ledger; spend dashboards.
- **CLEARANCE-as-add-on** (§10) with clean service boundary; white-label theming v1.
- **Compliance:** SOC 2 Type II audit underway/achieved; status page + SLAs + DPA.
- **Deployment:** migrate to k3s/Coolify; blue/green deploys.
- **Exit gate:** ≥1 external boutique studio/agency paying and active; **Enterprise-Ready (13.2) checklist passes** for at least one enterprise design-partner.

### Phase 5 — Government / Institutional (Year 2, H2) · *data sovereignty + ministry workflows*
- **In-region/on-prem deployment** validated (Gulf cloud or air-gapped); per-tenant encryption keys.
- **Ministry-grade approval workflows** on Portal primitives; government compliance cert templates in CLEARANCE.
- **ISO 27001** track for government procurement.
- **Exit gate:** first signed UAE/KSA government or quasi-government engagement running on a sovereign deployment.

### Phase 6 — GA Hardening & Self-Serve (Year 2 H2 – Year 3) · *toward GA (13.3)*
- **Self-serve onboarding + billing**; trial→paid→suspend→export lifecycle.
- **Public API + docs** (incl. CLEARANCE-as-API) with versioning, rate limits, SDKs.
- **Scale + reliability:** chaos/failover drills; SLOs met at GA load; cost-optimization pass.
- **Support:** tiered support process, runbooks, SLA per plan.
- **Exit gate:** **GA (13.3) checklist passes**; ≥3 external paying tenants through full campaign cycles with no high-sev incidents.

### Phase 7 — Post-GA Continuous (ongoing)
- Smart (ML-assisted) routing — only now, with real campaign data (per §4 sequencing).
- Additional providers, additional markets/dialects, MARJAN/CLEARANCE potential spin-outs.
- Annual pen test, SOC 2 renewal, DR re-drills, threat-model refresh.

### Phase summary

| Phase | Window | Theme | Readiness gate reached |
|---|---|---|---|
| 0 | Wk 0–4 | Foundations & rails | — |
| 1 | Mo 1–3 | Internal production tool | Production-Ready (internal) |
| 2 | Mo 3–6 | Client Portal | Production-Ready (client-facing path) |
| 3 | Mo 6–12 | MENA intelligence (MARJAN) | Moat validated |
| 4 | Y2 H1 | Multi-tenant SaaS | **Enterprise-Ready (13.2)** |
| 5 | Y2 H2 | Government / sovereign | Sovereign deployment live |
| 6 | Y2 H2–Y3 | GA hardening & self-serve | **GA (13.3)** |
| 7 | ongoing | Continuous / scale | sustained |

---

## 15. Decision Log (append here, never delete prior entries)

Record every deviation from this document here, with date, reasoning, and who approved it. An undocumented deviation is a bug in the process, not a valid shortcut.

| Date | Decision | Reasoning | Approved by |
|---|---|---|---|
| 2026-06-25 | Added Principles 8 & 9, Section 1.5 (shared entities), Section 11 (cross-cutting), Section 13 (readiness defs); expanded Section 14 to Phases 0–7. | Original draft left Asset/Tenant/User/Client undefined and had no treatment of security, idempotency, spend caps, billing, DR, compliance, testing, or explicit GA/Enterprise gates. | RYK Studio (P. Rajiv) |

---

## 16. Glossary (to remove ambiguity)

- **Brief**: the single record that owns a campaign's intent and spawns everything downstream. Not a document — a database row with structured fields plus free text.
- **BrandDNA**: the structured, reusable memory of how a brand should look/feel/sound, scoped per client.
- **GenerationJob**: one Temporal workflow execution that calls exactly one external provider for one task (script, image, video, VO, music, SFX).
- **Asset**: a single produced output (image/video/audio/document), provenance-tracked and version-chained.
- **ProvenanceRecord**: the immutable record of how an asset was made, created automatically, never hand-edited after creation.
- **Tenant**: an isolated customer of the platform (internal studio, external agency, enterprise, or government). Every row carries its `tenant_id`.
- **Credit Ledger**: the double-entry, append-only financial system of record for provider charges and client credits.
- **Master campaign**: the Brief + BrandDNA + VersioningMatrix axes definition. The "16+ versions" are derived, not separately briefed.
- **Production-Ready / Enterprise-Ready / GA**: the three hard readiness bars defined in Section 13.
- **Studio (internal use)**: RYK Studio, Phase 1–3 primary tenant.

---

*End of blueprint. Any feature request, architectural change, or scope addition must be checked against Section 0 (Non-Negotiable Principles) and Section 11 (cross-cutting concerns) before being added here.*
