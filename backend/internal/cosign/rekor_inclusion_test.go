package cosign

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// buildTree builds an RFC 6962 merkle tree from N leaves and
// returns (allLeafHashes, rootHash, proofFor). proofFor returns
// the inclusion-proof sibling hashes for the leaf at the given
// index, ordered leaf-to-root the way RFC 6962 expects.
//
// This is the canonical reference implementation; the production
// verifier in VerifyInclusion must agree with what this generates
// for every position 0..N-1 across multiple tree sizes.
func buildTree(t *testing.T, leaves [][]byte) (leafHashes [][]byte, root []byte, proofFor func(idx int) [][]byte) {
	t.Helper()
	leafHashes = make([][]byte, len(leaves))
	for i, l := range leaves {
		leafHashes[i] = HashLeaf(l)
	}
	// Build all levels of the tree.
	levels := [][][]byte{leafHashes}
	for len(levels[len(levels)-1]) > 1 {
		cur := levels[len(levels)-1]
		next := make([][]byte, 0, (len(cur)+1)/2)
		for i := 0; i < len(cur); i += 2 {
			if i+1 < len(cur) {
				next = append(next, hashNode(cur[i], cur[i+1]))
			} else {
				next = append(next, cur[i]) // odd node carried up
			}
		}
		levels = append(levels, next)
	}
	root = levels[len(levels)-1][0]
	proofFor = func(idx int) [][]byte {
		proof := [][]byte{}
		pos := idx
		for level := 0; level < len(levels)-1; level++ {
			cur := levels[level]
			var sibling []byte
			if pos%2 == 1 {
				sibling = cur[pos-1]
			} else if pos+1 < len(cur) {
				sibling = cur[pos+1]
			}
			if sibling != nil {
				proof = append(proof, sibling)
			}
			pos /= 2
		}
		return proof
	}
	return
}

func TestVerifyInclusion_VariousTreeSizes(t *testing.T) {
	t.Parallel()
	// Trees of 1, 2, 3, 5, 8, 11 leaves — covers powers of two and
	// odd-numbered ragged-right trees where the recursion edges
	// differ.
	for _, n := range []int{1, 2, 3, 5, 8, 11} {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			t.Parallel()
			leaves := make([][]byte, n)
			for i := range leaves {
				leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
			}
			leafHashes, root, proofFor := buildTree(t, leaves)
			for idx := 0; idx < n; idx++ {
				p := &LogProof{
					LeafHash: leafHashes[idx],
					LogIndex: int64(idx),
					TreeSize: int64(n),
					Hashes:   proofFor(idx),
					RootHash: root,
				}
				if err := VerifyInclusion(p); err != nil {
					t.Errorf("n=%d idx=%d: %v", n, idx, err)
				}
			}
		})
	}
}

func TestVerifyInclusion_RejectsTamper(t *testing.T) {
	t.Parallel()
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	leafHashes, root, proofFor := buildTree(t, leaves)
	good := &LogProof{
		LeafHash: leafHashes[2],
		LogIndex: 2,
		TreeSize: 4,
		Hashes:   proofFor(2),
		RootHash: root,
	}
	// Sanity: the unmodified proof verifies.
	if err := VerifyInclusion(good); err != nil {
		t.Fatalf("baseline verify: %v", err)
	}
	// Tampering with the leaf hash flips one bit → wrong root.
	bad := *good
	bad.LeafHash = append([]byte(nil), good.LeafHash...)
	bad.LeafHash[0] ^= 1
	if err := VerifyInclusion(&bad); err == nil {
		t.Error("expected verification to fail when leaf hash is tampered")
	}
	// Tampering with a sibling hash → wrong root.
	if len(good.Hashes) == 0 {
		t.Skip("tree too small for sibling tamper")
	}
	bad2 := *good
	bad2.Hashes = append([][]byte(nil), good.Hashes...)
	bad2.Hashes[0] = append([]byte(nil), good.Hashes[0]...)
	bad2.Hashes[0][0] ^= 1
	if err := VerifyInclusion(&bad2); err == nil {
		t.Error("expected verification to fail when a sibling hash is tampered")
	}
	// Tampering with the claimed root → wrong root.
	bad3 := *good
	bad3.RootHash = append([]byte(nil), good.RootHash...)
	bad3.RootHash[0] ^= 1
	if err := VerifyInclusion(&bad3); err == nil {
		t.Error("expected verification to fail when root is tampered")
	}
}

func TestVerifyInclusion_RejectsBadInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		p    *LogProof
	}{
		{"nil", nil},
		{"negative index", &LogProof{LogIndex: -1, TreeSize: 4}},
		{"oob index", &LogProof{LogIndex: 5, TreeSize: 4}},
		{"zero tree", &LogProof{LogIndex: 0, TreeSize: 0}},
		{"wrong-len leaf hash", &LogProof{
			LogIndex: 0, TreeSize: 4,
			LeafHash: []byte{1, 2, 3}, // not 32 bytes
			RootHash: make([]byte, 32),
		}},
		{"wrong-len root", &LogProof{
			LogIndex: 0, TreeSize: 4,
			LeafHash: make([]byte, 32),
			RootHash: []byte{1, 2, 3},
		}},
		{"wrong-len sibling", &LogProof{
			LogIndex: 0, TreeSize: 4,
			LeafHash: make([]byte, 32),
			RootHash: make([]byte, 32),
			Hashes:   [][]byte{{1, 2, 3}},
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if err := VerifyInclusion(c.p); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestRekorHTTPClient_FetchProof_HappyPath(t *testing.T) {
	t.Parallel()
	leaves := [][]byte{[]byte("e0"), []byte("e1"), []byte("e2"), []byte("e3")}
	_, root, proofFor := buildTree(t, leaves)
	const uuid = "abcd"
	wantBody := leaves[2]
	siblingHex := make([]string, 0, 2)
	for _, h := range proofFor(2) {
		siblingHex = append(siblingHex, hex.EncodeToString(h))
	}
	resp := map[string]any{
		uuid: map[string]any{
			"body":     base64.StdEncoding.EncodeToString(wantBody),
			"logIndex": 2,
			"verification": map[string]any{
				"inclusionProof": map[string]any{
					"logIndex": 2,
					"treeSize": 4,
					"rootHash": hex.EncodeToString(root),
					"hashes":   siblingHex,
				},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	c := NewRekorHTTPClient(srv.URL)
	p, err := c.FetchProof(context.Background(), uuid)
	if err != nil {
		t.Fatal(err)
	}
	// The fetched proof must verify end-to-end.
	if err := VerifyInclusion(p); err != nil {
		t.Errorf("fetched proof failed verification: %v", err)
	}
	// And the leaf hash must match the canonical RFC-6962 prefix.
	want := sha256.Sum256(append([]byte{0x00}, wantBody...))
	if !equalBytes(p.LeafHash, want[:]) {
		t.Errorf("leaf hash mismatch")
	}
}

func TestRekorHTTPClient_FetchProof_404(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	c := NewRekorHTTPClient(srv.URL)
	if _, err := c.FetchProof(context.Background(), "missing"); err == nil {
		t.Error("expected 404 error")
	}
}

func TestRekorHTTPClient_FetchProof_5xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	c := NewRekorHTTPClient(srv.URL)
	if _, err := c.FetchProof(context.Background(), "x"); err == nil {
		t.Error("expected 503 error")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
