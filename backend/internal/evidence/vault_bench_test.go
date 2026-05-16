package evidence

import (
	"bytes"
	"testing"
)

// Evidence encryption runs on every uploaded artefact (PCAP, scanner
// output, signed authorisation doc, screenshot). Small artefacts
// dominate; throughput floor matters more than tail latency. These
// benchmarks pin the cost of the AES-GCM round-trip at the sizes we
// see in production: 4 KiB (single screenshot tile), 64 KiB (small
// scanner output), 1 MiB (PCAP segment).

var benchKey = bytes.Repeat([]byte{0xA5}, 32)

func benchVault(b *testing.B) *Vault {
	b.Helper()
	return &Vault{masterKey: benchKey}
}

func BenchmarkEncrypt_4KB(b *testing.B) {
	v := benchVault(b)
	payload := bytes.Repeat([]byte{'x'}, 4<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = v.encrypt(payload)
	}
}

func BenchmarkEncrypt_64KB(b *testing.B) {
	v := benchVault(b)
	payload := bytes.Repeat([]byte{'x'}, 64<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = v.encrypt(payload)
	}
}

func BenchmarkEncrypt_1MB(b *testing.B) {
	v := benchVault(b)
	payload := bytes.Repeat([]byte{'x'}, 1<<20)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = v.encrypt(payload)
	}
}

func BenchmarkDecrypt_64KB(b *testing.B) {
	v := benchVault(b)
	payload := bytes.Repeat([]byte{'x'}, 64<<10)
	ct, nonce, _ := v.encrypt(payload)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = v.decrypt(ct, nonce)
	}
}
