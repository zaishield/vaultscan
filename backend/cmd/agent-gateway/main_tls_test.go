package main

import "testing"

func TestIsProductionEnv(t *testing.T) {
	cases := map[string]bool{
		"production":   true,
		"PRODUCTION":   true,
		"Production":   true,
		"prod":         true,
		"PROD":         true,
		"  prod  ":     true,
		"development":  false,
		"staging":      false,
		"":             false,
		"prod-staging": false,
	}
	for in, want := range cases {
		if got := isProductionEnv(in); got != want {
			t.Errorf("isProductionEnv(%q) = %v, want %v", in, got, want)
		}
	}
}
