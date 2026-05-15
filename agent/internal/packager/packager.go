// Package packager bundles raw tool output for upload (Blueprint §13.3
// evidence-packager). For the dev build we keep the payload as-is; production
// can swap in tar.gz with manifest signing.
package packager

import "github.com/zaishield/vaultscan/agent/internal/runner"

type Packager struct{}

func New() *Packager { return &Packager{} }

func (Packager) Package(out *runner.Output) ([]byte, error) {
	if len(out.Stdout) > 0 {
		return out.Stdout, nil
	}
	return out.Stderr, nil
}
