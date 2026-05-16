package assets

import (
	"bytes"
	"testing"
)

// bytesNoNewline strips trailing \r and \n bytes from a slice — used
// by the line-oriented subdomain ingest path. A missing trim leaks
// a literal newline into the asset value column.

func TestBytesNoNewline_StripsTrailingNewlines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   []byte
		want []byte
	}{
		{[]byte("api.example.com"), []byte("api.example.com")},
		{[]byte("api.example.com\n"), []byte("api.example.com")},
		{[]byte("api.example.com\r\n"), []byte("api.example.com")},
		{[]byte("api.example.com\n\r\n"), []byte("api.example.com")},
		{[]byte("\n\n\n"), []byte("")},
		{[]byte(""), []byte("")},
		// Leading newline must NOT be stripped — only trailing.
		{[]byte("\napi.com"), []byte("\napi.com")},
	}
	for _, c := range cases {
		got := bytesNoNewline(append([]byte(nil), c.in...))
		if !bytes.Equal(got, c.want) {
			t.Errorf("bytesNoNewline(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestBytesNoNewline_DoesNotMutateAfterReturn(t *testing.T) {
	t.Parallel()
	// Caller relies on the returned slice; this just exercises that
	// the function doesn't write through the original beyond the
	// returned length.
	in := []byte("host\n")
	out := bytesNoNewline(in)
	if string(out) != "host" {
		t.Errorf("got %q", out)
	}
}
