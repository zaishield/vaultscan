package scanorch

import (
	"reflect"
	"testing"
)

func TestNewFailoverRegionsFromEnv_ParsesPairs(t *testing.T) {
	t.Parallel()
	f := NewFailoverRegionsFromEnv(
		"us-east-1=us-west-2,us-east-2;eu-west-1=eu-central-1,eu-west-2")
	if got := f.Fallbacks("us-east-1"); !reflect.DeepEqual(got, []string{"us-west-2", "us-east-2"}) {
		t.Errorf("us-east-1 fallbacks: %v", got)
	}
	if got := f.Fallbacks("eu-west-1"); !reflect.DeepEqual(got, []string{"eu-central-1", "eu-west-2"}) {
		t.Errorf("eu-west-1 fallbacks: %v", got)
	}
}

func TestFailoverRegions_CaseInsensitiveLookup(t *testing.T) {
	t.Parallel()
	f := NewFailoverRegionsFromEnv("US-EAST-1=us-west-2")
	if got := f.Fallbacks("us-east-1"); len(got) != 1 || got[0] != "us-west-2" {
		t.Errorf("case-insensitive lookup failed: %v", got)
	}
}

func TestFailoverRegions_UnknownPrimary_ReturnsNil(t *testing.T) {
	t.Parallel()
	f := NewFailoverRegionsFromEnv("us-east-1=us-west-2")
	if got := f.Fallbacks("ap-southeast-1"); got != nil {
		t.Errorf("unknown primary should return nil, got %v", got)
	}
}

func TestFailoverRegions_NilSafe(t *testing.T) {
	t.Parallel()
	var f *FailoverRegions
	if got := f.Fallbacks("us-east-1"); got != nil {
		t.Errorf("nil receiver should return nil, got %v", got)
	}
}

func TestFailoverRegions_MalformedEntriesIgnored(t *testing.T) {
	t.Parallel()
	f := NewFailoverRegionsFromEnv("malformed;;us-east-1=us-west-2;empty=")
	if got := f.Fallbacks("us-east-1"); !reflect.DeepEqual(got, []string{"us-west-2"}) {
		t.Errorf("good entry should survive: %v", got)
	}
	if got := f.Fallbacks("empty"); got != nil {
		t.Errorf("empty fallback list should NOT register: %v", got)
	}
}

func TestFailoverRegions_TrimsWhitespace(t *testing.T) {
	t.Parallel()
	f := NewFailoverRegionsFromEnv(" us-east-1 = us-west-2 , us-east-2 ")
	got := f.Fallbacks("us-east-1")
	want := []string{"us-west-2", "us-east-2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestIsNoNodeErr(t *testing.T) {
	t.Parallel()
	if !isNoNodeErr(errFmt("scanorch: no scanner node available for region \"x\"")) {
		t.Error("should detect")
	}
	if isNoNodeErr(nil) {
		t.Error("nil should be false")
	}
	if isNoNodeErr(errFmt("db connection refused")) {
		t.Error("unrelated error should be false")
	}
}

// errFmt is a tiny helper; tests don't import errors directly.
func errFmt(s string) error { return &stringErr{s: s} }

type stringErr struct{ s string }

func (e *stringErr) Error() string { return e.s }
