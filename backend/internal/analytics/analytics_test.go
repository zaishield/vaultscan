package analytics

import "testing"

func TestBucketCounts(t *testing.T) {
	t.Parallel()
	res := map[string]any{
		"aggregations": map[string]any{
			"by_severity": map[string]any{
				"buckets": []any{
					map[string]any{"key": "critical", "doc_count": 4.0},
					map[string]any{"key": "high", "doc_count": 12.0},
				},
			},
		},
	}
	got := bucketCounts(res, "by_severity")
	if got["critical"] != 4 || got["high"] != 12 {
		t.Fatalf("unexpected counts: %+v", got)
	}
}

func TestBucketKV(t *testing.T) {
	t.Parallel()
	res := map[string]any{
		"aggregations": map[string]any{
			"by_asset": map[string]any{
				"buckets": []any{
					map[string]any{"key": "10.0.0.1", "doc_count": 7.0},
				},
			},
		},
	}
	got := bucketKV(res, "by_asset")
	if len(got) != 1 || got[0].Key != "10.0.0.1" || got[0].Count != 7 {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestHistogramBuckets(t *testing.T) {
	t.Parallel()
	res := map[string]any{
		"aggregations": map[string]any{
			"by_day": map[string]any{
				"buckets": []any{
					map[string]any{"key_as_string": "2026-05-15", "doc_count": 3.0},
					map[string]any{"key_as_string": "2026-05-16", "doc_count": 7.0},
				},
			},
		},
	}
	got := histogramBuckets(res, "by_day")
	if len(got) != 2 || got[0].Scans != 3 || got[1].Date != "2026-05-16" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestStringFromPayload(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in     map[string]any
		key    string
		want   string
		wantOk bool
	}{
		{nil, "x", "", false},
		{map[string]any{"x": "abc"}, "x", "abc", true},
		{map[string]any{"x": 5}, "x", "", false},
	}
	for _, tc := range cases {
		got, ok := stringFromPayload(tc.in, tc.key)
		if got != tc.want || ok != tc.wantOk {
			t.Fatalf("stringFromPayload(%v, %q) = %q,%v; want %q,%v",
				tc.in, tc.key, got, ok, tc.want, tc.wantOk)
		}
	}
}
