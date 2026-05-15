// Package emergency listens for the cloud-side emergency-stop signal
// (Blueprint §28.2). When triggered, the agent halts all running tools
// within the SLA (default 30s) and refuses to start new ones.
package emergency

import (
	"sync/atomic"
	"time"
)

type Listener struct {
	stopped int32
	since   atomic.Value // time.Time
}

func New() *Listener { return &Listener{} }

func (l *Listener) Trigger() {
	atomic.StoreInt32(&l.stopped, 1)
	l.since.Store(time.Now())
}
func (l *Listener) Reset() { atomic.StoreInt32(&l.stopped, 0) }

func (l *Listener) Stopped() bool { return atomic.LoadInt32(&l.stopped) == 1 }

func (l *Listener) Since() time.Time {
	v := l.since.Load()
	if t, ok := v.(time.Time); ok {
		return t
	}
	return time.Time{}
}
