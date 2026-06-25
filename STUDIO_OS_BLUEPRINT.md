# STUDIO OS — The Build Bible

**Status:** Canonical specification. This document is the single source of truth for building STUDIO OS. Where this document and any other artifact (chat message, verbal direction, old draft) disagree, this document wins until it is explicitly amended. Amendments are made by editing this file, not by working around it.

**Origin:** Derived from "The Platform Gap Report" (Yohan Wadia Studio, June 2026). That report identified 10 production-layer gaps no AI generation platform has closed. This document is the buildable answer to Gap Opportunity #1: STUDIO OS, the Agency-Grade AI Production Operating System.

**What this is not:** This is not a new image/video/audio generation model. STUDIO OS never trains or hosts a foundation generation model except where Section 9 explicitly says otherwise (Arabic text rendering). It is the orchestration, memory, and accountability layer that sits above third-party generation APIs (Higgsfield, Runway, ElevenLabs, Suno, Adobe Firefly, etc.) and turns them into a system a creative director can run real client production through.

---

## 0. Non-Negotiable Principles

These principles override feature-level decisions anywhere in this document. If a future feature request conflicts with one of these, the principle wins.

1. **The Brief is the only source of truth.** Every artifact in the system — script, storyboard, generation job, asset, approval, invoice line — must trace back to a Brief record via foreign key. Nothing is allowed to exist as an orphan upload.
2. **Every generated asset is provenance-tracked.** No asset enters the system without a Provenance Record (model, prompt, params, cost, timestamp, operator). This is not optional and not deferred to "later phases" — it ships in Phase 1.
3. **The platform orchestrates models; it does not become one.** Don't build a competing image/video generator. The one sanctioned exception is the Arabic Visual Engine (Section 9), and only as a fine-tune of an open-weight base model, not a foundation model from scratch.
4. **Build for one real studio first.** Every feature in Phases 1–3 must be validated against actual Yohan Wadia Studio client campaigns before being considered "done." A feature nobody used internally does not graduate to external SaaS.
5. **Open source for infrastructure, proprietary for generation.** Every piece of platform infrastructure (orchestration, database, auth, storage, workflow engine) must be open-source and self-hostable. Every piece of generation capability (the actual pixels/audio/video) is bought from the best available provider, proprietary or not. Do not violate this split in either direction — don't build your own LLM inference stack, and don't outsource the brand-memory database to a SaaS vendor.
6. **Data sovereignty is a first-class deployment property, not a feature flag bolted on later.** The system must be deployable entirely within a chosen region (including on-prem / Gulf-region cloud) from Phase 1 onward, even if Phase 1 doesn't need it yet.
7. **No client-visible feature ships without an audit trail.** Approvals, revisions, sign-offs — anything a client touches must be logged with timestamp, actor, and immutable record. This is the legal spine of Gap #5 and #10 and is not negotiable for scope-cutting.

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
                    │   (CLEARANCE module)   │
                    └───────────────────────┘
```

Eight modules. Each is specified below with: purpose, data model, required behaviors, explicit non-goals, and the gap(s) it closes.

---

## 2. Module: Brief Engine

**Closes:** Gap #1 (Production Pipeline), Gap #7 (Campaign Versioning, partially)

**Purpose:** The brief is not a document attached to a project. The brief IS the project. Every other module reads from and writes back to the Brief record.

### Data model

```
Brief
 ├─ id, client_id, title, status (draft|active|in_review|approved|archived)
 ├─ objective (free text — the actual creative ask)
 ├─ emotional_direction_id (FK → EmotionDirection, nullable until Emotion Translator runs)
 ├─ brand_dna_id (FK → BrandDNA)
 ├─ market_targets[] (e.g. ["UAE","KSA","Egypt"])
 ├─ format_targets[] (e.g. ["16:9","9:16","1:1"])
 ├─ dialect_targets[] (e.g. ["Gulf Arabic","Egyptian Arabic","English"])
 ├─ calendar_context (nullable FK → CulturalCalendarEvent, e.g. Ramadan)
 ├─ budget_tier (FK → BudgetEstimate)
 ├─ created_by, created_at, updated_at
 └─ revision_history[] (append-only log of every field change, actor, timestamp)
```

### Required behaviors

- A Brief cannot be deleted, only archived. Revision history is append-only — never overwritten.
- Changing any field on an active Brief that has already spawned generation jobs creates a new **Brief Revision** and prompts the user: "this affects N downstream jobs — re-run them?" Never silently invalidates work in progress.
- The Brief view shows a live tree of everything it has spawned: scripts, storyboards, generation jobs, assets, approvals — this tree is the literal UI manifestation of Principle 1.

### Explicit non-goals

- The Brief Engine is not a generic project management tool (no Gantt charts, no time tracking). Resist scope creep toward becoming a Jira clone.

---

## 3. Module: Brand DNA Store

**Closes:** Gap #3 (Brand DNA)

**Purpose:** Store not just brand assets (logo, colors, fonts) but brand *behavior*: how a brand should feel across campaigns, encoded as reusable, structured presets — not prose nobody re-reads.

### Data model

```
BrandDNA
 ├─ id, client_id, brand_name
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
 ├─ brief_id, brand_dna_id
 ├─ task_type (script | storyboard | video | image | vo | music | sfx)
 ├─ assigned_model (e.g. "higgsfield:kling-v2", "elevenlabs:vo-arabic-gulf")
 ├─ routing_reason (why this model was chosen — quality/cost/capability — logged, not implicit)
 ├─ params (full request payload sent to provider, stored verbatim)
 ├─ status (queued|running|succeeded|failed|needs_review)
 ├─ cost_actual (credits/USD consumed — reconciled against Budget Planner estimate)
 ├─ output_asset_id (FK → Asset, once complete)
 └─ retry_count, last_error
```

### Required behaviors

- **Provider adapters are isolated.** Each provider (Higgsfield, Runway, ElevenLabs, Suno, Adobe Firefly, Midjourney-manual) gets its own adapter module implementing a shared `GenerationProvider` interface (`submit()`, `poll()`, `cancel()`, `estimateCost()`). New providers are added by writing one adapter, never by touching orchestration logic.
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
 ├─ brief_id
 ├─ axes: markets[], formats[], dialects[], calendar_variants[]
 ├─ derivation_rules[] (per-axis overrides — e.g. "KSA variant: swap VO model, apply stricter prohibited_elements")
 └─ generated_combinations[] (FK → GenerationJob[], one per resolved combination)
```

### Required behaviors

- Given a Brief with `market_targets=[UAE,KSA]`, `format_targets=[16:9,9:16]`, `dialect_targets=[Gulf,Egyptian]`, the system computes the full cartesian product (8 combinations here) and spawns one GenerationJob branch per combination automatically — the user defines axes once, not 8 times.
- `derivation_rules` allow per-axis overrides without forking the brief (e.g., "for KSA, always use the stricter prohibited_elements list from BrandDNA.market_variants").
- The matrix view shows all derivative versions against the master in a single grid — this is the literal UI fix for "no platform has versioning intelligence."

---

## 6. Module: Budget Planner

**Closes:** Gap #8

**Purpose:** Forecast generation cost before generation happens, and reconcile actual spend after.

### Data model

```
BudgetEstimate
 ├─ brief_id
 ├─ scope_inputs (number of scenes, formats, markets, dialects, quality tier)
 ├─ per_task_estimates[] (task_type, recommended_model, estimated_credits, estimated_usd)
 ├─ total_estimate_usd
 └─ actual_spend_usd (rolled up from GenerationJob.cost_actual as jobs complete)
```

### Required behaviors

- Estimate is generated BEFORE the first generation job is submitted, from a maintained internal cost table per provider/model (updated manually when providers reprice — given the doc notes Higgsfield has repriced 3+ times, this table needs a changelog and an owner, not a one-time hardcode).
- Variance between `total_estimate_usd` and `actual_spend_usd` is surfaced per campaign — this is the studio's real financial control mechanism, not a nice-to-have dashboard.

---

## 7. Module: Emotional Direction Translator

**Closes:** Gap #9

**Purpose:** Convert a human emotional brief into model-ready prompt architecture across image, video, and audio simultaneously.

### Data model

```
EmotionDirection
 ├─ id, brief_id
 ├─ raw_input (free text — "the feeling of calling your mother for the first time from a different country")
 ├─ resolved_parameters (structured output: lighting, pacing, color grade, music tempo/key, VO tone, camera movement)
 ├─ translator_model (which LLM performed the translation, e.g. Claude)
 └─ human_reviewed (boolean — Principle: emotional intelligence requires human oversight, never fully automated)
```

### Required behaviors

- This module calls an LLM (via LiteLLM gateway, Section 11) to translate `raw_input` into `resolved_parameters`, but `resolved_parameters` is **always presented to a human creative director for edit/approval before being passed to the Orchestrator.** `human_reviewed=false` blocks generation job creation. This is non-negotiable per the source report's own caveat that this "can't be purely automated."
- Approved `resolved_parameters` are saved as reusable Direction Templates, attached to BrandDNA for reuse on future campaigns.
- Phase placement: per the source report, this ships as a feature inside STUDIO OS, not a standalone product. Do not let it grow a separate UI shell.

---

## 8. Module: Client Portal

**Closes:** Gap #2

**Purpose:** Replace WhatsApp/Drive/WeTransfer with a single client-facing surface for review, structured feedback, and legally meaningful approval.

### Data model

```
ReviewLink
 ├─ id, brief_id, asset_ids[], expires_at, access_token
 ├─ allowed_actions (view|comment|approve)
 └─ created_by

Feedback
 ├─ review_link_id, asset_id, comment_text, timestamp_marker (for video — frame/timecode)
 ├─ author_name (client-side, no login required), created_at
 └─ resolved (boolean)

Approval
 ├─ review_link_id, asset_id, approver_name, approver_email
 ├─ signature_record_id (FK → Documenso envelope)
 ├─ approved_at, ip_address
 └─ status (pending|approved|rejected|revision_requested)
```

### Required behaviors

- Review links are shareable without requiring the client to create an account (frictionless access, token-based).
- Feedback is structured (attached to a specific asset, optionally a specific timecode/frame) — not freeform chat, directly fixing "can you make it more premium?" ambiguity by forcing comment-to-asset attachment as a UX pattern (the UX should still allow free text, but it must be anchored to a specific asset/version).
- Approval is a real e-signature event via **Documenso** (self-hosted, open source), producing a legally meaningful, timestamped, IP-logged record — not a "Looks good!" WhatsApp message. This satisfies Principle 7.
- All revisions are versioned; the client always sees a version history, never just "the latest file."

---

## 9. Module: MENA Cultural Intelligence Layer (codename MARJAN, integrated as a module)

**Closes:** Gap #4, contributes to Gap #10

**Purpose:** Per the source report, this is the most defensible, least-contested-by-incumbents capability. Build it as a module inside STUDIO OS first (per Build Phase P3), with the option to spin out as a standalone product later if validated.

### Sub-components

1. **Cultural Calendar Service** — a maintained dataset (Hijri calendar conversion, Ramadan dates, UAE/KSA National Days, regional observances) exposed as a service that BrandDNA and Brief records can subscribe to (`calendar_context` field, Section 2). Source this from an open Hijri calendar library (e.g. `hijri-converter` or equivalent open dataset) — do not hand-roll calendar math.
2. **Cultural Visual Library** — structured presets per market (UAE, KSA, Egypt, Levant) covering dress code defaults, family representation norms, architectural grammar, and approved color palettes for cultural moments. Stored as BrandDNA `market_variants` (Section 3) — this is data curation work, not a separate codebase.
3. **Dialect Layer** — VO direction metadata (Gulf / Egyptian / Levantine Arabic) attached to GenerationJob params when routing to VO providers (ElevenLabs or equivalent with Arabic dialect support).
4. **Arabic Visual Engine (the one sanctioned model-training exception, Principle 3)** — Arabic text rendering inside generated imagery is broken across all current providers. The fix is a fine-tune (LoRA) on an open-weight diffusion base model (e.g. Flux.1 or SDXL) trained specifically on correct Arabic typography in-scene. This is scoped explicitly:
   - Do not attempt to build a general-purpose competing image model.
   - Scope is narrow: render legible, correctly-shaped, non-mirrored Arabic text within generated scenes.
   - This is a Phase 3 research effort, gated on P1/P2 being live and validated first. Do not pull this forward — it is the highest-risk, highest-effort item in the entire blueprint and must not block anything else.

---

## 10. Module: IP Documentation (codename CLEARANCE, integrated as a module)

**Closes:** Gap #5, contributes to Gap #10

### Data model

```
ProvenanceRecord
 ├─ asset_id, generation_job_id
 ├─ model_used, model_version, provider
 ├─ training_data_disclosure (text/link, as published by provider)
 ├─ usage_rights_summary (derived from provider's commercial terms)
 ├─ generated_at, generated_by
 └─ certificate_hash (for tamper-evidence — sha256 of the record, displayed on client-facing cert)

ModelReleaseFlow
 ├─ asset_id, requires_release (boolean — auto-flagged when asset contains a generated human likeness)
 ├─ release_document_id (FK → Documenso envelope)
 └─ status (not_required|pending|signed)

RightsRecord
 ├─ asset_id, channel[] (broadcast|digital|print|social), markets[], valid_from, valid_until
 └─ jurisdiction_notes (free text, e.g. UAE Take It Down Act equivalent considerations)
```

### Required behaviors

- `ProvenanceRecord` is created automatically and atomically when a `GenerationJob` completes — this is not a manual data-entry step. Principle 2 enforcement happens here at the database trigger level: a `GenerationJob.status = succeeded` transition with no corresponding `ProvenanceRecord` is a system invariant violation and should alert, not silently pass.
- `ModelReleaseFlow.requires_release` auto-flags based on a simple heuristic in Phase 1 (does this asset use a `character_library` entry with a real-person likeness reference?) and can be made smarter later, but must exist from Phase 1 — even a crude flag beats none.
- Client-facing "compliance certificate" is a generated PDF (server-rendered, e.g. via open-source `Puppeteer`/`Playwright` PDF rendering) combining ProvenanceRecord + RightsRecord + signed releases for a given asset or campaign — this is the literal deliverable for enterprise/government clients who ask "how was this made?"

---

## 11. Technology Stack (Definitive — Do Not Substitute Without Updating This Section)

This section is binding. If a future contributor wants to swap a tool, they edit this document and justify the change here first — they do not silently introduce a different tool in code.

| Layer | Choice | Why / Constraint |
|---|---|---|
| Frontend + internal app | **Next.js 15 (App Router), TypeScript, React Server Components** | Single codebase serves internal tool, client portal, and future external SaaS |
| API layer | **tRPC** | End-to-end type safety, fast iteration for small team |
| Database | **PostgreSQL** | System of record for Brief, BrandDNA, jobs, approvals, provenance — all relational, all need FK integrity (Principle 1 enforcement) |
| Vector/semantic search | **pgvector extension** | Brand DNA / prompt library similarity search — no separate vector DB needed at this scale |
| ORM | **Drizzle** (preferred) or Prisma | Type-safe schema, migration discipline |
| Workflow orchestration | **Temporal (self-hosted, open source)** | Durable execution for multi-step, multi-branch generation pipelines; native support for the versioning matrix (Section 5) and human-in-the-loop steps (Section 7) |
| LLM gateway | **LiteLLM (open source)** | Unified interface for brief/script/emotion-translation LLM calls; swappable backend models |
| Provider adapters (image/video/audio gen) | **Custom adapter modules per provider** (Higgsfield, Runway, ElevenLabs, Suno, Adobe Firefly) | Intentionally proprietary glue — this is platform IP, not outsourced to a generic wrapper lib |
| Object storage | **MinIO (self-hosted, S3-compatible)** | Keeps data-sovereignty option open (Principle 6); swappable to Cloudflare R2 if self-hosting storage becomes a burden |
| E-signature / audit trail | **Documenso (open source)** | Model releases, client approvals — Principle 7 enforcement |
| Auth / multi-tenancy | **Authentik or Keycloak (open source)** | Studio users, guest client reviewers, future multi-tenant agencies |
| Real-time collaboration (optional, Phase 2+) | **Yjs + Hocuspocus (open source)** | Only if live co-annotation is validated as needed; do not build before Client Portal v1 ships |
| Background jobs (non-workflow) | **BullMQ (Redis-backed)** | Lightweight queue for tasks that don't need full Temporal durability (e.g. PDF rendering) |
| Search | **Meilisearch or Typesense (open source)** | Searching past campaigns, brand assets, prompt libraries |
| Observability | **OpenTelemetry + Grafana/Loki/Tempo (open source)** | Critical from day one given multi-provider API failure surface |
| Deployment (Phase 1) | **Docker Compose** | Single-studio internal use, minimal ops overhead |
| Deployment (Phase 4+) | **k3s or Coolify (open-source PaaS)** | When externalizing to other studios; Coolify preferred for lower ops burden unless team grows |
| Calendar/Hijri data | **Open Hijri calendar library/dataset** | Cultural Calendar Service (Section 9) — do not hand-roll |
| PDF generation | **Playwright (headless render)** | Compliance certificates (Section 10) |

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

## 12. Build Phases — Exact Scope Per Phase

This is the literal task list. A phase is not "done" until every item in its checklist is true. Do not start the next phase's checklist items early except where explicitly marked "can start early."

### Phase 1 (Months 1–3): Internal tool, single studio, no external users

- [ ] Postgres schema for Brief, BrandDNA, GenerationJob, ProvenanceRecord live
- [ ] Temporal cluster running (self-hosted, Docker Compose)
- [ ] At least 2 provider adapters built (start with Higgsfield + ElevenLabs — highest usage)
- [ ] Brief Engine UI: create brief, see live tree of spawned jobs
- [ ] BrandDNA Store populated for at least 2 real clients (e.g. Head & Shoulders, Always)
- [ ] ProvenanceRecord auto-created on every successful GenerationJob — zero exceptions
- [ ] Budget Planner cost table seeded for Higgsfield + ElevenLabs pricing, manually maintained
- [ ] Used on at least one real live client campaign end-to-end
- [ ] **Exit criterion:** the studio's own production for one real campaign ran through the Brief Engine instead of Google Docs + WhatsApp, and the team would choose to do it again voluntarily.

### Phase 2 (Months 3–6): Client Portal

- [ ] ReviewLink + Feedback + Approval schema live
- [ ] Documenso integrated for e-signature
- [ ] Tested with 2–3 current clients for real approval cycles
- [ ] **Exit criterion:** at least one real client used the portal to approve a deliverable instead of WhatsApp, with a signed audit trail to show for it.

### Phase 3 (Months 6–12): MENA Intelligence Layer

- [ ] Cultural Calendar Service live, integrated into Brief.calendar_context
- [ ] Cultural Visual Library populated for UAE, KSA, Egypt at minimum
- [ ] Dialect Layer wired into VO generation jobs
- [ ] Arabic Visual Engine LoRA fine-tune: research spike only in this phase — do not commit to production use until quality bar is met on a held-out test set of brand-relevant scenes
- [ ] Validated against Ramadan or National Day campaign work for a real client
- [ ] **Exit criterion:** a real Ramadan/National Day campaign used the cultural layer and required measurably less manual correction than the previous year's process.

### Phase 4 (Year 2): External SaaS / White-label

- [ ] Multi-tenancy via Authentik, tenant isolation verified
- [ ] Pricing model implemented: base subscription + generation credit markup
- [ ] White-label theming capability
- [ ] CLEARANCE (IP Documentation) offered as standalone add-on
- [ ] **Exit criterion:** at least one external boutique studio or agency is paying for and actively using the platform.

### Phase 5 (Year 2–3): Government / Enterprise

- [ ] Data residency deployment validated in-region (Gulf cloud or on-prem)
- [ ] Ministry-grade approval workflow built on top of existing Client Portal primitives
- [ ] Government-specific compliance documentation templates added to CLEARANCE
- [ ] **Exit criterion:** first signed engagement with a UAE/KSA government or quasi-government entity.

---

## 13. Decision Log (append here, never delete prior entries)

Record every deviation from this document here, with date, reasoning, and who approved it. An undocumented deviation is a bug in the process, not a valid shortcut.

| Date | Decision | Reasoning | Approved by |
|---|---|---|---|
| — | (template row — delete once first real entry is added) | — | — |

---

## 14. Glossary (to remove ambiguity)

- **Brief**: the single record that owns a campaign's intent and spawns everything downstream. Not a document — a database row with structured fields plus free text.
- **BrandDNA**: the structured, reusable memory of how a brand should look/feel/sound, scoped per client.
- **GenerationJob**: one Temporal workflow execution that calls exactly one external provider for one task (script, image, video, VO, music, SFX).
- **ProvenanceRecord**: the immutable record of how an asset was made, created automatically, never hand-edited after creation.
- **Master campaign**: the Brief + BrandDNA + VersioningMatrix axes definition. The "16+ versions" are derived, not separately briefed.
- **Studio (internal use)**: Yohan Wadia Studio, Phase 1–3 sole user.
- **Tenant (external use)**: any agency/studio using the platform from Phase 4 onward, isolated from other tenants' data.

---

*End of blueprint. Any feature request, architectural change, or scope addition must be checked against Section 0 (Non-Negotiable Principles) before being added here.*
