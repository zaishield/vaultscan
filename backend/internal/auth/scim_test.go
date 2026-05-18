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

func TestSCIMCompositeFilter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		filter string
		wantOK bool
	}{
		{"single-clause-eq", `userName eq "a@b.com"`, true},
		{"and-two-clauses", `userName sw "alice" and userName ew "@example.com"`, true},
		{"or-two-clauses", `userName eq "a@b.com" or userName eq "c@d.com"`, true},
		{"mixed-and-or", `userName sw "a" and userName co "b" or userName pr`, true},
		{"trailing-connective", `userName eq "x" and`, false},
		{"value-contains-keyword", `userName eq "needs and want"`, true},
	}
	for _, c := range cases {
		_, _, err := scimFilterToSQL(c.filter, 1)
		if c.wantOK && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.wantOK && err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestSCIMTokeniseRespectsQuotes(t *testing.T) {
	// "and" inside a quoted value must NOT be treated as a connective.
	tokens := tokeniseSCIMComposite(`userName eq "alice and bob"`)
	if len(tokens) != 1 {
		t.Fatalf("got %d tokens (%v), want 1", len(tokens), tokens)
	}
}

func TestSCIMLikeEscape(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"plain":   "plain",
		"100%":    "100\\%",
		"a_b":     "a\\_b",
		"back\\":  "back\\\\",
		"x%_\\y":  "x\\%\\_\\\\y",
	}
	for in, want := range cases {
		if got := scimLikeEscape(in); got != want {
			t.Errorf("escape(%q) = %q, want %q", in, got, want)
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
