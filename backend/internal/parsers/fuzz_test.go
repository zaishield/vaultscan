package parsers

import (
	"testing"

	"github.com/google/uuid"
)

// Parsers consume bytes produced by external scanner tools that an
// attacker can influence (custom payloads, hostile target responses,
// fabricated scanner output). A panic, infinite loop, or unbounded
// allocation in any parser becomes a DoS / availability bug — and
// because parsers run on the result-ingestion path, a crash kills the
// scan job and loses real findings.
//
// We fuzz every parser through a single dispatch so adding a new tool
// to Registry automatically inherits coverage.

func fuzzCtx() Context {
	return Context{
		PlatformID:   uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
		PartnerID:    uuid.MustParse("00000000-0000-0000-0000-0000000000b1"),
		TenantID:     uuid.MustParse("00000000-0000-0000-0000-0000000000c1"),
		EngagementID: uuid.MustParse("00000000-0000-0000-0000-0000000000d1"),
	}
}

// FuzzAllParsers drives random bytes through every parser in Registry.
// The contract: a parser may return an error, but must never panic, and
// the (input → findings) transform must not produce a finding with a
// missing tenant/partner/platform ID (since those would later violate
// the RLS WHERE-clause invariants).
func FuzzAllParsers(f *testing.F) {
	seeds := [][]byte{
		[]byte(``),
		[]byte(`{}`),
		[]byte(`[]`),
		[]byte(`null`),
		[]byte(`{"info":{"name":"x","severity":"high"}}`),
		[]byte(`<?xml version="1.0"?><nmaprun></nmaprun>`),
		[]byte(`<?xml version="1.0"?><nmaprun><host><address addr="1.1.1.1" addrtype="ipv4"/></host></nmaprun>`),
		[]byte(`{"results":[{"name":"x"}]}`),
		[]byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","Severity":"HIGH"}]}]}`),
		[]byte(`{"site":[{"alerts":[{"name":"x","riskcode":"3"}]}]}`),
		[]byte("\x00\x01\x02"),
		[]byte(strings_repeat("a", 4096)),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	ctx := fuzzCtx()
	f.Fuzz(func(t *testing.T, raw []byte) {
		for tool, parse := range Registry {
			out, err := parse(ctx, raw)
			if err != nil {
				continue
			}
			for i, ing := range out {
				if ing.PlatformID == uuid.Nil || ing.PartnerID == uuid.Nil ||
					ing.TenantID == uuid.Nil || ing.EngagementID == uuid.Nil {
					t.Fatalf("parser %q produced finding %d with nil tenancy ID — RLS will reject", tool, i)
				}
			}
		}
	})
}

// strings_repeat — local helper so we can keep the fuzz file imports
// minimal. fmt.Sprintf("%s%s%s...") would also work but explodes the
// generated assembly.
func strings_repeat(s string, n int) string {
	out := make([]byte, n*len(s))
	for i := 0; i < n; i++ {
		copy(out[i*len(s):], s)
	}
	return string(out)
}

// FuzzParseNmap targets the XML decoder specifically — XML has been a
// historic source of memory-amplification bugs (billion-laughs, XXE).
// Go's encoding/xml is hardened, but we still want a baseline that
// proves our type bindings can handle malicious shapes.
func FuzzParseNmap(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><nmaprun></nmaprun>`))
	f.Add([]byte(`<?xml version="1.0"?><nmaprun><host><address addr="x" addrtype="ipv4"/><ports><port portid="22" protocol="tcp"><state state="open"/></port></ports></host></nmaprun>`))
	f.Add([]byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun><host><address addr="&xxe;"/></host></nmaprun>`))
	ctx := fuzzCtx()
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseNmap(ctx, raw)
	})
}

// FuzzParseNuclei targets JSONL where each line is independent. Tests
// that an attacker-supplied line doesn't blow up the line-splitter.
func FuzzParseNuclei(f *testing.F) {
	f.Add([]byte(`{"template-id":"x","info":{"name":"x","severity":"high"},"host":"h","matched-at":"h"}`))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte(`{"template-id":"x"`)) // truncated
	ctx := fuzzCtx()
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseNuclei(ctx, raw)
	})
}

// FuzzParseTrivy targets the deeply-nested {Results:[{Vulnerabilities:[...]}]}
// shape — a common source of nil-deref bugs.
func FuzzParseTrivy(f *testing.F) {
	f.Add([]byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","Severity":"HIGH"}]}]}`))
	f.Add([]byte(`{"Results":null}`))
	f.Add([]byte(`{"Results":[{}]}`))
	ctx := fuzzCtx()
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseTrivy(ctx, raw)
	})
}

// Benchmarks for the high-volume parsers — Gap 4 perf coverage.
// Production ingest can run 100k findings/hr per region; we want a
// known-good baseline so a regression shows up in CI.
func BenchmarkParseNmap(b *testing.B) {
	raw := []byte(`<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="5.7"/></port>
<port protocol="tcp" portid="5432"><state state="open"/><service name="postgres" product="PostgreSQL" version="14"/></port>
</ports></host></nmaprun>`)
	ctx := fuzzCtx()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseNmap(ctx, raw)
	}
}

func BenchmarkParseNuclei(b *testing.B) {
	line := `{"template-id":"http-missing-security-headers","info":{"name":"Missing security headers","severity":"low","description":"x","tags":["misconfig"]},"host":"https://example.com","matched-at":"https://example.com/"}`
	// 50 lines
	var buf []byte
	for i := 0; i < 50; i++ {
		buf = append(buf, []byte(line)...)
		buf = append(buf, '\n')
	}
	ctx := fuzzCtx()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseNuclei(ctx, buf)
	}
}

func BenchmarkParseTrivy(b *testing.B) {
	raw := []byte(`{"Results":[{"Target":"image","Vulnerabilities":[
{"VulnerabilityID":"CVE-2024-0001","PkgName":"openssl","InstalledVersion":"1.1.1","FixedVersion":"1.1.1w","Severity":"HIGH","Title":"x","Description":"y"},
{"VulnerabilityID":"CVE-2024-0002","PkgName":"libxml2","InstalledVersion":"2.9","FixedVersion":"2.10","Severity":"MEDIUM","Title":"x","Description":"y"}
]}]}`)
	ctx := fuzzCtx()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseTrivy(ctx, raw)
	}
}
