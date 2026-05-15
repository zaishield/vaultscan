// Package searchindex is a thin OpenSearch / Elasticsearch REST client.
// Stdlib HTTP only — no opensearch-go dependency.
//
// Production deployments wire two index aliases:
//
//   vaultscan-findings   — receives every finding upserted by
//                          findings.Service. Tenant-scoped via routing
//                          on tenant_id. Searched from the findings
//                          panel for full-text + boolean queries.
//
//   vaultscan-audit      — receives every audit_logs row appended.
//                          Searched from audit forensics view.
//
// Index template: 1 primary shard per index for now (small dataset);
// `tenant_id` keyword for term filtering; `body` text for full-text.
//
// At-rest encryption + RBAC happen at the OpenSearch cluster level —
// the client doesn't deal in either, only HTTP basic / API-key auth.
package searchindex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	addr       string
	user       string
	pass       string
	httpClient *http.Client
}

type Config struct {
	URL        string  // https://opensearch.internal:9200 or comma-separated cluster
	Username   string
	Password   string
	HTTPClient *http.Client
}

func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("searchindex: URL required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	addr := strings.TrimRight(strings.SplitN(cfg.URL, ",", 2)[0], "/")
	return &Client{
		addr: addr, user: cfg.Username, pass: cfg.Password, httpClient: hc,
	}, nil
}

// Health is the equivalent of `GET /_cluster/health`. Returns
// ("green"|"yellow"|"red", err).
func (c *Client) Health(ctx context.Context) (string, error) {
	body, err := c.do(ctx, http.MethodGet, "/_cluster/health", nil)
	if err != nil {
		return "", err
	}
	var r struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", err
	}
	return r.Status, nil
}

// EnsureIndex creates the index with the given mapping if it doesn't
// already exist. Idempotent.
func (c *Client) EnsureIndex(ctx context.Context, name string, mapping map[string]any) error {
	// HEAD to check existence.
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, c.url(name), nil)
	c.auth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return nil
	}
	body, _ := json.Marshal(mapping)
	_, err = c.do(ctx, http.MethodPut, "/"+name, body)
	return err
}

// IndexDoc upserts a document at /<index>/_doc/<id>.
// `routing` (optional) hashes the doc to a shard — typically tenant_id
// so all of one tenant's docs co-locate for queries with
// `?routing=<tenant>` (cuts search fanout).
func (c *Client) IndexDoc(ctx context.Context, index, id string, doc any, routing string) error {
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/%s/_doc/%s", index, id)
	if routing != "" {
		path += "?routing=" + routing
	}
	_, err = c.do(ctx, http.MethodPut, path, body)
	return err
}

// SearchHit is one item in a search response.
type SearchHit struct {
	ID     string         `json:"_id"`
	Score  float64        `json:"_score"`
	Source map[string]any `json:"_source"`
}

// SearchResponse is the slice of OpenSearch's response we care about.
type SearchResponse struct {
	Total int         `json:"total"`
	Hits  []SearchHit `json:"hits"`
}

// Search runs a query against the index.
//
// Example query body:
//   {"query":{"bool":{"must":[
//       {"term":{"tenant_id":"<uuid>"}},
//       {"match":{"title":"sql injection"}}
//   ]}},"size":50,"sort":[{"updated_at":"desc"}]}
func (c *Client) Search(ctx context.Context, index string, query map[string]any) (*SearchResponse, error) {
	body, _ := json.Marshal(query)
	raw, err := c.do(ctx, http.MethodPost, "/"+index+"/_search", body)
	if err != nil {
		return nil, err
	}
	var r struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []SearchHit `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &SearchResponse{Total: r.Hits.Total.Value, Hits: r.Hits.Hits}, nil
}

// Bulk indexes many docs in one request. `ops` is the NDJSON-style
// list — one action header + one doc per pair, alternating. Caller
// builds the slice; we marshal each to NDJSON and POST.
type BulkOp struct {
	Action string  // "index" | "delete"
	Index  string
	ID     string
	Doc    any     // nil for deletes
	Routing string
}

func (c *Client) Bulk(ctx context.Context, ops []BulkOp) error {
	if len(ops) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, op := range ops {
		header := map[string]any{
			op.Action: map[string]any{"_index": op.Index, "_id": op.ID},
		}
		if op.Routing != "" {
			header[op.Action].(map[string]any)["routing"] = op.Routing
		}
		hb, _ := json.Marshal(header)
		buf.Write(hb)
		buf.WriteByte('\n')
		if op.Action != "delete" && op.Doc != nil {
			db, _ := json.Marshal(op.Doc)
			buf.Write(db)
			buf.WriteByte('\n')
		}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+"/_bulk", &buf)
	c.auth(req)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("bulk %d: %s", resp.StatusCode, string(body))
	}
	// Even on 200, individual ops may have failed (HTTP envelopes
	// per-op statuses). Detect via "errors":true.
	var r struct {
		Errors bool `json:"errors"`
	}
	_ = json.Unmarshal(body, &r)
	if r.Errors {
		return fmt.Errorf("bulk: partial failure: %s", string(body))
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, rdr)
	if err != nil {
		return nil, err
	}
	c.auth(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("opensearch %s %s: %d %s", method, path, resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func (c *Client) auth(req *http.Request) {
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
}

func (c *Client) url(index string) string {
	return c.addr + "/" + index
}
