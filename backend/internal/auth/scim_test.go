package auth

import "testing"

func TestParseSCIMFilter(t *testing.T) {
	cases := []struct {
		filter, field, value string
		wantErr              bool
	}{
		{`userName eq "alice@example.com"`, "username", "alice@example.com", false},
		{`id eq "00000000-0000-0000-0000-000000000001"`, "id",
			"00000000-0000-0000-0000-000000000001", false},
		{"userName co alice", "", "", true},     // co not supported
		{"", "", "", true},                       // empty errors
	}
	for _, c := range cases {
		f, v, err := parseSCIMFilter(c.filter)
		if (err != nil) != c.wantErr {
			t.Errorf("filter=%q err=%v wantErr=%v", c.filter, err, c.wantErr)
			continue
		}
		if !c.wantErr {
			if f != c.field || v != c.value {
				t.Errorf("filter=%q got (%q,%q) want (%q,%q)",
					c.filter, f, v, c.field, c.value)
			}
		}
	}
}

func TestStatusActiveRoundTrip(t *testing.T) {
	for _, b := range []bool{true, false} {
		if activeFromStatus(statusFromActive(b)) != b {
			t.Errorf("roundtrip %v failed", b)
		}
	}
}
