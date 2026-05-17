package auth

import "testing"

func TestParseSCIMFilter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		filter, field, op, value string
		wantErr                  bool
	}{
		{`userName eq "alice@example.com"`, "username", "eq", "alice@example.com", false},
		{`id eq "00000000-0000-0000-0000-000000000001"`, "id", "eq",
			"00000000-0000-0000-0000-000000000001", false},
		{`userName sw "alice"`, "username", "sw", "alice", false},
		{`userName ew "@example.com"`, "username", "ew", "@example.com", false},
		{`userName co "alice"`, "username", "co", "alice", false},
		{`userName pr`, "username", "pr", "", false},
		{"badop xx alice", "", "", "", true}, // unknown operator
		{"", "", "", "", true},               // empty errors
	}
	for _, c := range cases {
		f, op, v, err := parseSCIMFilter(c.filter)
		if (err != nil) != c.wantErr {
			t.Errorf("filter=%q err=%v wantErr=%v", c.filter, err, c.wantErr)
			continue
		}
		if !c.wantErr {
			if f != c.field || op != c.op || v != c.value {
				t.Errorf("filter=%q got (%q,%q,%q) want (%q,%q,%q)",
					c.filter, f, op, v, c.field, c.op, c.value)
			}
		}
	}
}

func TestStatusActiveRoundTrip(t *testing.T) {
	t.Parallel()
	for _, b := range []bool{true, false} {
		if activeFromStatus(statusFromActive(b)) != b {
			t.Errorf("roundtrip %v failed", b)
		}
	}
}
