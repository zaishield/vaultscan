package policy

import "testing"

func TestPolicy_ProfileGate(t *testing.T) {
	p := NewLocal()
	// Empty allow list = allow everything.
	if !p.AllowsProfile("ext_recon_quick") {
		t.Error("empty allow list should permit any profile")
	}
	p.Update(nil, nil, []string{"ext_recon_quick", "internal_creds"}, nil, 1, 70, 75)
	if !p.AllowsProfile("ext_recon_quick") {
		t.Error("should allow listed profile")
	}
	if p.AllowsProfile("dangerous_full_audit") {
		t.Error("should reject unlisted profile")
	}
}

func TestPolicy_ToolGate(t *testing.T) {
	p := NewLocal()
	if !p.AllowsTool("nmap") {
		t.Error("empty allow list should permit any tool")
	}
	p.Update(nil, nil, nil, []string{"nmap", "nuclei"}, 1, 70, 75)
	if !p.AllowsTool("nmap") {
		t.Error("nmap should be allowed")
	}
	if p.AllowsTool("hydra") {
		t.Error("hydra should be blocked")
	}
}

func TestPolicy_TargetCIDR(t *testing.T) {
	p := NewLocal()
	p.Update([]string{"10.0.0.0/8"}, nil, nil, nil, 1, 70, 75)
	if !p.AllowsTarget("10.5.5.5") {
		t.Error("10.5.5.5 should be inside 10.0.0.0/8")
	}
	if p.AllowsTarget("8.8.8.8") {
		t.Error("8.8.8.8 should be outside 10.0.0.0/8")
	}
}

func TestPolicy_TargetDomainSuffix(t *testing.T) {
	p := NewLocal()
	p.Update([]string{"example.com"}, nil, nil, nil, 1, 70, 75)
	if !p.AllowsTarget("api.example.com") {
		t.Error("api.example.com should match suffix example.com")
	}
	// Exact match also works.
	if !p.AllowsTarget("example.com") {
		t.Error("exact match should pass")
	}
	if p.AllowsTarget("evilexample.com") {
		t.Error("evilexample.com is not a subdomain of example.com — should reject")
	}
}

func TestPolicy_BlockListWinsOverAllowList(t *testing.T) {
	p := NewLocal()
	// Allow everything in 10/8 but block 10.0.0.0/24.
	p.Update([]string{"10.0.0.0/8"}, []string{"10.0.0.0/24"}, nil, nil, 1, 70, 75)
	if p.AllowsTarget("10.0.0.5") {
		t.Error("10.0.0.5 in blocked 10.0.0.0/24 — should reject")
	}
	if !p.AllowsTarget("10.5.5.5") {
		t.Error("10.5.5.5 outside block, inside allow — should pass")
	}
}

func TestPolicy_MaxConcurrentDefaultsToOne(t *testing.T) {
	p := NewLocal()
	if p.MaxConcurrent() != 1 {
		t.Errorf("default should be 1, got %d", p.MaxConcurrent())
	}
	p.Update(nil, nil, nil, nil, 4, 70, 75)
	if p.MaxConcurrent() != 4 {
		t.Errorf("got %d, want 4", p.MaxConcurrent())
	}
	// Floor at 1 even if config says 0.
	p.Update(nil, nil, nil, nil, 0, 70, 75)
	if p.MaxConcurrent() != 1 {
		t.Errorf("zero-or-negative should floor to 1, got %d", p.MaxConcurrent())
	}
}

func TestPolicy_ResourceCaps(t *testing.T) {
	p := NewLocal()
	p.Update(nil, nil, nil, nil, 2, 50, 60)
	if p.MaxCPUPercent() != 50 {
		t.Errorf("MaxCPUPercent: got %d, want 50", p.MaxCPUPercent())
	}
	if p.MaxMemoryPercent() != 60 {
		t.Errorf("MaxMemoryPercent: got %d, want 60", p.MaxMemoryPercent())
	}
}
