// Package analytics is the OpenSearch-backed read-side of the platform.
//
// Blueprint §26.4 specifies a 3-node OpenSearch cluster as the analytics
// store. The dashboards (§7.4) and the technical-trend widgets need
// aggregations that don't belong in Postgres at scale. The analytics
// service:
//
//   - Maintains index templates for findings, scan_jobs, agents, assets,
//     audit_logs.
//   - Subscribes to every event from eventbus and mirrors authoritative
//     records into OpenSearch (eventual consistency, < 5 s typically).
//   - Exposes typed aggregation queries that power the executive,
//     technical, and partner dashboards.
//
// Wire it via analytics.New(...).Wire(bus). When OpenSearch is unreachable,
// the indexer logs and silently skips - the Postgres-backed dashboards
// continue to work.
package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a thin HTTP wrapper over the OpenSearch REST API. Production
// deployments may swap in the official go-elasticsearch client; we stick to
// net/http to keep the dependency surface small and the failure mode obvious.
type Client struct {
	baseURL  *url.URL
	http     *http.Client
	username string
	password string
}

func NewClient(rawBase, username, password string) (*Client, error) {
	if rawBase == "" {
		return nil, fmt.Errorf("analytics: base url required")
	}
	u, err := url.Parse(rawBase)
	if err != nil {
		return nil, fmt.Errorf("analytics: parse base url: %w", err)
	}
	return &Client{
		baseURL:  u,
		username: username,
		password: password,
		http:     &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Ping returns nil when the cluster responds 2xx to GET /.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// EnsureTemplate creates or updates an index template.
func (c *Client) EnsureTemplate(ctx context.Context, name string, body any) error {
	path := "/_index_template/" + url.PathEscape(name)
	resp, err := c.do(ctx, http.MethodPut, path, body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Index writes (or replaces) a single document by id.
func (c *Client) Index(ctx context.Context, index, id string, doc any) error {
	path := fmt.Sprintf("/%s/_doc/%s?refresh=false",
		url.PathEscape(index), url.PathEscape(id))
	resp, err := c.do(ctx, http.MethodPut, path, doc)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// BulkOp is one action in a _bulk request.
type BulkOp struct {
	Action string // "index" | "delete" | "create" | "update"
	Index  string
	ID     string
	Doc    any
}

// Bulk performs a single _bulk request from a list of (action, doc) pairs.
func (c *Client) Bulk(ctx context.Context, actions []BulkOp) error {
	if len(actions) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, op := range actions {
		hdr, _ := json.Marshal(map[string]any{op.Action: map[string]any{
			"_index": op.Index, "_id": op.ID,
		}})
		buf.Write(hdr)
		buf.WriteByte('\n')
		if op.Doc != nil {
			body, _ := json.Marshal(op.Doc)
			buf.Write(body)
			buf.WriteByte('\n')
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.url("/_bulk"), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	c.maybeAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("analytics: bulk %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// Search runs a query and returns the parsed JSON response.
func (c *Client) Search(ctx context.Context, index string, query any) (map[string]any, error) {
	path := fmt.Sprintf("/%s/_search", url.PathEscape(index))
	resp, err := c.do(ctx, http.MethodPost, path, query)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(c.baseURL.String(), "/") + path
}

func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.maybeAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("analytics: %s %s: %d %s",
			method, path, resp.StatusCode, string(raw))
	}
	return resp, nil
}

func (c *Client) maybeAuth(req *http.Request) {
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}
}
