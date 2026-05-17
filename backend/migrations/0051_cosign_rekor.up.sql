-- 0051_cosign_rekor.up.sql
--
-- Carries Rekor transparency-log metadata on every verification so
-- an auditor can re-verify the signature against the public log
-- (rekor-cli get --uuid <rekor_uuid>) even after the underlying
-- key is rotated. Empty when the signature didn't ship with a
-- Rekor entry — the verifier still accepts those, but the lack of
-- transparency-log evidence is now explicit in the row.

ALTER TABLE cosign_verifications
    ADD COLUMN IF NOT EXISTS rekor_log_id      TEXT,
    ADD COLUMN IF NOT EXISTS rekor_log_index   BIGINT,
    ADD COLUMN IF NOT EXISTS rekor_integrated_at TIMESTAMPTZ;

-- Convenience index for the audit query "show every signature this
-- key emitted, in Rekor-log order".
CREATE INDEX IF NOT EXISTS cosign_verifications_rekor_idx
    ON cosign_verifications(rekor_log_id, rekor_log_index)
    WHERE rekor_log_id IS NOT NULL;
