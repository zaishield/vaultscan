-- 0044 — Audit log archival + RFC 3161 timestamping infrastructure.
--
-- Closes two SEV-3 gaps from the forensic report:
--
--   §3.5: audit_retention_policies table exists + VerifyDeep exists,
--         but no background job actually archives expired rows. Tables
--         grow unbounded.
--
--   §3.6: audit chain is locally hash-chained. For GDPR Art 30 + PCI
--         10.5 admissibility most regulators require external
--         timestamping (RFC 3161 TSA — FreeTSA, DigiCert, Sectigo).
--
-- Tables:
--
--   audit_archive_runs       one row per archival sweep. Tracks
--                            inclusive id range, sha256 of the
--                            concatenated payload hashes, sha256 of
--                            the archive file (S3 ETag), and the
--                            RFC 3161 TimeStampToken bytes returned
--                            by the TSA. The token contains the TSA's
--                            counter-signature over our anchor hash,
--                            which a court can verify against the
--                            TSA's published cert.
--
--   audit_tsa_anchors        Optional per-day anchor records — even
--                            without a full archive, the cron pushes
--                            today's max-id + chain-hash to the TSA
--                            and stores the token. Used for compliance
--                            "we timestamp every day" claims.

BEGIN;

CREATE TABLE audit_archive_runs (
    id                  BIGSERIAL PRIMARY KEY,
    -- Inclusive id range of audit_logs rows in this archive.
    from_audit_id       BIGINT NOT NULL,
    to_audit_id         BIGINT NOT NULL,
    row_count           BIGINT NOT NULL,
    -- Hash of the entire archive payload (concat of audit_logs rows
    -- in id order). Recomputable from the archive file.
    payload_sha256      TEXT NOT NULL,
    -- Where the archive landed. vaultscan://archive/<date>/<id>.gz for
    -- the FilesystemStorage backend; s3://<bucket>/<key> for S3.
    storage_url         TEXT NOT NULL,
    -- size_bytes of the on-disk archive (gzip'd).
    size_bytes          BIGINT NOT NULL,
    -- RFC 3161 TimeStampToken bytes — opaque CMS SignedData blob
    -- (TimeStampToken ::= ContentInfo) that a verifier can validate
    -- against the TSA's published cert.
    tsa_token           BYTEA,
    -- TSA URL we asked for the token (so verifiers know which cert
    -- to fetch).
    tsa_url             TEXT,
    -- TSA serial number from the response — humans cite this when
    -- referencing the timestamp in legal proceedings.
    tsa_serial          TEXT,
    archived_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    -- Whether this archive has been deleted from the source table.
    purged_at           TIMESTAMPTZ,
    CHECK (to_audit_id >= from_audit_id)
);

CREATE INDEX audit_archive_runs_range_idx
    ON audit_archive_runs(from_audit_id, to_audit_id);
CREATE INDEX audit_archive_runs_unpurged_idx
    ON audit_archive_runs(archived_at)
    WHERE purged_at IS NULL;

-- ---- Daily TSA anchors --------------------------------------------------
--
-- Even without archival, the cron pushes today's audit-chain head
-- (max audit_logs.id + its chain_hash) to the TSA and stores the
-- returned token. This gives us a daily "we timestamped this state"
-- breadcrumb for compliance.

CREATE TABLE audit_tsa_anchors (
    id                  BIGSERIAL PRIMARY KEY,
    -- Audit log id at the moment we asked the TSA.
    anchored_audit_id   BIGINT NOT NULL,
    -- chain_hash from that row.
    chain_hash          BYTEA NOT NULL,
    tsa_url             TEXT NOT NULL,
    tsa_token           BYTEA,
    tsa_serial          TEXT,
    anchored_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_tsa_anchors_anchored_at_idx
    ON audit_tsa_anchors(anchored_at DESC);

COMMIT;
