// Package policy is the local policy enforcer (Blueprint §28.2). The cloud
// pushes the canonical policy; the agent caches it and enforces it before
// running any tool.
package policy

import (
	"net"
	"strings"
	"sync"
)

type Local struct {
	mu                sync.RWMutex
	allowedScopes     []string
	blockedScopes     []string
	allowedProfiles   map[string]bool
	allowedTools      map[string]bool
	maxConcurrentJobs int
	maxCPU            int
	maxMemory         int
}

func NewLocal() *Local {
	return &Local{
		allowedProfiles:   map[string]bool{},
		allowedTools:      map[string]bool{},
		maxConcurrentJobs: 1,
		maxCPU:            70,
		maxMemory:         75,
	}
}

func (p *Local) Update(allowedScopes, blockedScopes, profiles, tools []string,
	maxJobs, maxCPU, maxMem int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedScopes = allowedScopes
	p.blockedScopes = blockedScopes
	p.allowedProfiles = mapOf(profiles)
	p.allowedTools = mapOf(tools)
	p.maxConcurrentJobs = maxJobs
	p.maxCPU = maxCPU
	p.maxMemory = maxMem
}

func (p *Local) AllowsProfile(code string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.allowedProfiles) == 0 {
		return true
	}
	return p.allowedProfiles[code]
}

func (p *Local) AllowsTarget(target string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, b := range p.blockedScopes {
		if matches(b, target) {
			return false
		}
	}
	if len(p.allowedScopes) == 0 {
		return true
	}
	for _, a := range p.allowedScopes {
		if matches(a, target) {
			return true
		}
	}
	return false
}

func (p *Local) AllowsTool(tool string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.allowedTools) == 0 {
		return true
	}
	return p.allowedTools[tool]
}

func (p *Local) MaxConcurrent() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.maxConcurrentJobs < 1 {
		return 1
	}
	return p.maxConcurrentJobs
}

func (p *Local) MaxCPUPercent() int    { p.mu.RLock(); defer p.mu.RUnlock(); return p.maxCPU }
func (p *Local) MaxMemoryPercent() int { p.mu.RLock(); defer p.mu.RUnlock(); return p.maxMemory }

func matches(scope, target string) bool {
	scope = strings.ToLower(strings.TrimSpace(scope))
	target = strings.ToLower(strings.TrimSpace(target))
	if scope == target {
		return true
	}
	if _, network, err := net.ParseCIDR(scope); err == nil {
		if ip := net.ParseIP(target); ip != nil {
			return network.Contains(ip)
		}
	}
	if strings.Contains(scope, ".") && strings.HasSuffix(target, "."+scope) {
		return true
	}
	return false
}

func mapOf(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}
