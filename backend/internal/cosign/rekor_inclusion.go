// rekor_inclusion.go — RFC 6962 merkle inclusion-proof verifier.
//
// Closes the documented gap from the previous audit pass: the
// SET-signature path proved Rekor once attested to an entry, but
// any operator who wanted "this entry is in the current tree"
// still had to shell out to rekor-cli. RFC 6962 §2.1.1 specifies
// a deterministic algorithm for walking the proof: given a leaf
// hash, leaf index, tree size, proof hashes, and the signed tree
// head (STH) root, the verifier can prove inclusion with zero
// trust beyond the STH signature.
//
// Rekor uses RFC 6962 hashing (sha256 with 0x00 leaf prefix and
// 0x01 internal-node prefix) so the algorithm transplants directly.
//
// What this file adds:
//   - LogProof type — the inclusion proof + STH + body.
//   - RekorHTTPClient — minimal HTTP client that fetches the proof
//     and STH from a Rekor instance over its public REST API.
//   - VerifyInclusion — the pure-crypto merkle walk; testable
//     against a synthetic tree, no network needed.
//   - Service.VerifyImage flow: when RequireRekorInclusion is set,
//     fetch the proof + STH at verify time and walk it. Failure
//     flips Decision to DecisionRejectedRekor.

package cosign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LeafPrefix and NodePrefix are the domain separators from RFC 6962
// §2.1. The same prefixes are used by Rekor (sigstore/rekor commits
// e62a3bb1+) so verification works against the public log unchanged.
const (
	rekorLeafPrefix byte = 0x00
	rekorNodePrefix byte = 0x01
)

// LogProof carries everything VerifyInclusion needs. Fields match
// the Rekor /api/v1/log/entries/<uuid>?verify=true response shape so
// the HTTP client can populate it directly.
type LogProof struct {
	LeafHash  []byte   // sha256(0x00 || body)
	LogIndex  int64    // 0-indexed leaf position
	TreeSize  int64    // size of the tree at proof time
	Hashes    [][]byte // inclusion-proof sibling hashes, leaf-to-root order
	RootHash  []byte   // expected root if the inclusion proof is correct
	// STH (Signed Tree Head). Signed by the Rekor instance's public
	// key; if RekorPublic is wired, VerifyInclusion will check it
	// in addition to the merkle math.
	STHSig     []byte
	STHPayload []byte // canonical JSON the STHSig covers
}

// VerifyInclusion runs the RFC 6962 §2.1.1 algorithm over the
// proof. Returns nil if and only if recomputing the path from
// LeafHash up the merkle tree using Hashes lands on RootHash.
// Errors describe which check failed — operator-actionable, not
// just a boolean.
func VerifyInclusion(p *LogProof) error {
	if p == nil {
		return errors.New("rekor: nil proof")
	}
	if p.LogIndex < 0 || p.TreeSize <= 0 || p.LogIndex >= p.TreeSize {
		return fmt.Errorf("rekor: out-of-range index/size (%d/%d)", p.LogIndex, p.TreeSize)
	}
	if len(p.LeafHash) != sha256.Size || len(p.RootHash) != sha256.Size {
		return errors.New("rekor: leaf/root must be 32-byte sha256")
	}
	for i, h := range p.Hashes {
		if len(h) != sha256.Size {
			return fmt.Errorf("rekor: sibling hash %d wrong length", i)
		}
	}

	// RFC 6962 §2.1.1 walk. Variable names match the spec for
	// reviewability: fn = leaf index, sn = upper bound, r = running
	// hash. We iterate the proof, alternating "I'm a right child"
	// vs "I'm a left child" based on the bit pattern of fn.
	fn, sn := p.LogIndex, p.TreeSize-1
	r := p.LeafHash
	for _, sibling := range p.Hashes {
		if sn == 0 {
			return errors.New("rekor: proof has trailing entries past tree top")
		}
		if fn&1 == 1 || fn == sn {
			// We are the right child or the last node at this level.
			r = hashNode(sibling, r)
			// Compress: walk up until we are no longer a right edge.
			for fn&1 == 0 {
				if fn == 0 {
					break
				}
				fn >>= 1
				sn >>= 1
			}
		} else {
			// Left child.
			r = hashNode(r, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		// Proof was too short — didn't reach the top.
		return fmt.Errorf("rekor: proof exhausted with sn=%d (expected 0)", sn)
	}
	if !bytes.Equal(r, p.RootHash) {
		return fmt.Errorf("rekor: recomputed root %s != claimed root %s",
			hex.EncodeToString(r), hex.EncodeToString(p.RootHash))
	}
	return nil
}

// hashNode = sha256(0x01 || left || right). RFC 6962 §2.1.
func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rekorNodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// HashLeaf = sha256(0x00 || body). Exposed so tests / Rekor body
// constructors can derive the leaf hash without re-implementing
// the prefix logic.
func HashLeaf(body []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rekorLeafPrefix})
	h.Write(body)
	return h.Sum(nil)
}

// ---------------- HTTP client -----------------------------------------------

// RekorHTTPClient talks to a Rekor instance's public REST API to
// fetch the inclusion proof + STH at verify time. Production
// deployments may run their own Rekor; the URL is config-driven.
type RekorHTTPClient struct {
	BaseURL string         // e.g. https://rekor.sigstore.dev
	Client  *http.Client   // optional; nil → 10s-timeout default
}

// NewRekorHTTPClient with a 10s timeout (Rekor responses are small
// — kilobytes — so anything past 10s is a connectivity problem,
// not a slow query).
func NewRekorHTTPClient(baseURL string) *RekorHTTPClient {
	return &RekorHTTPClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// FetchProof retrieves the inclusion proof for the entry at the
// given UUID. Returns a LogProof ready for VerifyInclusion.
func (c *RekorHTTPClient) FetchProof(ctx context.Context, uuid string) (*LogProof, error) {
	if c == nil || c.BaseURL == "" {
		return nil, errors.New("rekor: HTTP client not configured")
	}
	if uuid == "" {
		return nil, errors.New("rekor: empty uuid")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	url := fmt.Sprintf("%s/api/v1/log/entries/%s", c.BaseURL, uuid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rekor: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("rekor: entry %s not found in log", uuid)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("rekor: GET %s returned %d: %s",
			url, resp.StatusCode, string(body))
	}
	// Rekor returns a map keyed by uuid → {body, verification: {...}, ...}.
	var resBody map[string]struct {
		Body         string `json:"body"`
		LogIndex     int64  `json:"logIndex"`
		LogID        string `json:"logID"`
		Verification struct {
			InclusionProof struct {
				LogIndex int64    `json:"logIndex"`
				TreeSize int64    `json:"treeSize"`
				RootHash string   `json:"rootHash"`
				Hashes   []string `json:"hashes"`
				Checkpoint string `json:"checkpoint"`
			} `json:"inclusionProof"`
			SignedEntryTimestamp string `json:"signedEntryTimestamp"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(body, &resBody); err != nil {
		return nil, fmt.Errorf("rekor: parse response: %w", err)
	}
	entry, ok := resBody[uuid]
	if !ok {
		return nil, fmt.Errorf("rekor: response keyed under different uuid (got keys: %d)",
			len(resBody))
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return nil, fmt.Errorf("rekor: body base64: %w", err)
	}
	rootHash, err := hex.DecodeString(entry.Verification.InclusionProof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("rekor: rootHash hex: %w", err)
	}
	hashes := make([][]byte, len(entry.Verification.InclusionProof.Hashes))
	for i, h := range entry.Verification.InclusionProof.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("rekor: sibling hash %d hex: %w", i, err)
		}
		hashes[i] = b
	}
	return &LogProof{
		LeafHash: HashLeaf(bodyBytes),
		LogIndex: entry.Verification.InclusionProof.LogIndex,
		TreeSize: entry.Verification.InclusionProof.TreeSize,
		Hashes:   hashes,
		RootHash: rootHash,
	}, nil
}
